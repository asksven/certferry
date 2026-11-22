from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from certferry.certs import (
    DEFAULT_FORMATS,
    FORMATS,
    CertMaterial,
    OutputFile,
    Pkcs12Options,
    load_certs,
    render,
    render_format,
    same_content,
)
from certferry.errors import CertificateError

from .conftest import Pki, make_pki


def material_for(p: Pki, *, ca: bool = True) -> CertMaterial:
    return CertMaterial.from_pem(p.tls_crt, p.tls_key, p.ca_crt if ca else None)


class TestParsing:
    def test_leaf_chain_and_ca(self, pki: Pki) -> None:
        m = material_for(pki)
        assert m.leaf == pki.leaf_cert
        assert m.chain == [pki.inter_cert]
        assert m.ca == [pki.root_cert]
        assert m.fingerprint == __import__("hashlib").sha256(pki.leaf_der).hexdigest()

    def test_info(self, pki: Pki) -> None:
        info = material_for(pki).info()
        assert info["common_name"] == "www.example.test"
        assert info["dns_names"] == ["www.example.test", "example.test"]
        assert info["key_type"] == "ec-secp256r1"
        assert info["chain_length"] == 1
        assert info["has_ca"] is True
        assert "CN=Test Intermediate" in info["issuer"]

    @pytest.mark.parametrize(
        ("fixture", "expected"), [("rsa_pki", "rsa2048"), ("ed_pki", "ed25519")]
    )
    def test_key_types(self, request: pytest.FixtureRequest, fixture: str, expected: str) -> None:
        p = request.getfixturevalue(fixture)
        assert material_for(p).info()["key_type"] == expected

    def test_empty_ca_is_ignored(self, pki: Pki) -> None:
        m = CertMaterial.from_pem(pki.tls_crt, pki.tls_key, b"  \n")
        assert m.ca == []

    def test_no_san(self) -> None:
        p = make_pki(sans=False)
        m = material_for(p)
        assert m.dns_names() == []
        data = render_format("pkcs12", m, Pkcs12Options())
        bundle = pkcs12.load_pkcs12(data, None)
        assert bundle.cert is not None and bundle.cert.friendly_name == b"certificate"

    def test_key_mismatch(self, pki: Pki, other_pki: Pki) -> None:
        with pytest.raises(CertificateError, match="does not match"):
            CertMaterial.from_pem(pki.tls_crt, other_pki.tls_key)

    def test_bad_key(self, pki: Pki) -> None:
        with pytest.raises(CertificateError, match="cannot parse private key"):
            CertMaterial.from_pem(pki.tls_crt, b"-----BEGIN PRIVATE KEY-----\nAAAA\n")

    def test_no_certificate(self, pki: Pki) -> None:
        with pytest.raises(CertificateError, match="no PEM certificate"):
            CertMaterial.from_pem(b"garbage", pki.tls_key)

    def test_corrupt_certificate(self) -> None:
        with pytest.raises(CertificateError, match="cannot parse certificate"):
            load_certs(b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----", "x")

    def test_days_remaining(self, pki: Pki) -> None:
        m = material_for(pki)
        assert 89 < m.days_remaining() <= 90
        assert m.days_remaining(m.not_after - timedelta(days=3)) == pytest.approx(3)


class TestFormats:
    def test_all_formats_registered(self) -> None:
        assert set(DEFAULT_FORMATS) <= set(FORMATS)
        assert {f for f, s in FORMATS.items() if s.secret} == {
            "key",
            "key-pkcs8",
            "key-traditional",
            "combined",
            "pkcs12",
        }

    def test_cert(self, pki: Pki) -> None:
        assert render_format("cert", material_for(pki), Pkcs12Options()) == pki.leaf_pem

    def test_chain(self, pki: Pki) -> None:
        data = render_format("chain", material_for(pki), Pkcs12Options())
        assert load_certs(data, "chain") == [pki.inter_cert]

    def test_fullchain(self, pki: Pki) -> None:
        data = render_format("fullchain", material_for(pki), Pkcs12Options())
        assert load_certs(data, "fc") == [pki.leaf_cert, pki.inter_cert]

    def test_ca(self, pki: Pki) -> None:
        assert render_format("ca", material_for(pki), Pkcs12Options()) == pki.ca_crt

    def test_key_as_stored(self, rsa_pki: Pki) -> None:
        data = render_format("key", material_for(rsa_pki), Pkcs12Options())
        assert data.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
        assert data.endswith(b"\n")

    def test_key_pkcs8(self, rsa_pki: Pki) -> None:
        data = render_format("key-pkcs8", material_for(rsa_pki), Pkcs12Options())
        assert data.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_key_traditional(self, pki: Pki) -> None:
        data = render_format("key-traditional", material_for(pki), Pkcs12Options())
        assert data.startswith(b"-----BEGIN EC PRIVATE KEY-----")

    def test_key_traditional_unavailable_for_ed25519(self, ed_pki: Pki) -> None:
        with pytest.raises(CertificateError, match="not available for ed25519"):
            render_format("key-traditional", material_for(ed_pki), Pkcs12Options())

    def test_combined(self, pki: Pki) -> None:
        data = render_format("combined", material_for(pki), Pkcs12Options())
        assert load_certs(data, "c") == [pki.leaf_cert, pki.inter_cert]
        key = serialization.load_pem_private_key(data, None)
        assert key.public_key() == pki.leaf_key.public_key()

    def test_der(self, pki: Pki) -> None:
        data = render_format("der", material_for(pki), Pkcs12Options())
        assert x509.load_der_x509_certificate(data) == pki.leaf_cert

    @pytest.mark.parametrize("legacy", [False, True])
    def test_pkcs12_encrypted(self, pki: Pki, legacy: bool) -> None:
        opts = Pkcs12Options(password=b"s3cret", legacy=legacy, friendly_name="alias")
        data = render_format("pkcs12", material_for(pki), opts)
        bundle = pkcs12.load_pkcs12(data, b"s3cret")
        assert bundle.cert is not None and bundle.cert.certificate == pki.leaf_cert
        assert bundle.cert.friendly_name == b"alias"
        assert [c.certificate for c in bundle.additional_certs] == [pki.inter_cert, pki.root_cert]
        with pytest.raises(ValueError):
            pkcs12.load_pkcs12(data, b"wrong")

    def test_pkcs12_unencrypted_without_ca(self, pki: Pki) -> None:
        data = render_format("pkcs12", material_for(pki, ca=False), Pkcs12Options())
        bundle = pkcs12.load_pkcs12(data, None)
        assert bundle.cert is not None
        assert bundle.cert.friendly_name == b"www.example.test"
        assert [c.certificate for c in bundle.additional_certs] == [pki.inter_cert]

    def test_chain_missing(self, pki: Pki) -> None:
        m = CertMaterial.from_pem(pki.leaf_pem, pki.tls_key)
        with pytest.raises(CertificateError, match="no intermediate"):
            render_format("chain", m, Pkcs12Options())

    def test_ca_missing(self, pki: Pki) -> None:
        with pytest.raises(CertificateError, match="no ca.crt"):
            render_format("ca", material_for(pki, ca=False), Pkcs12Options())

    def test_unknown(self, pki: Pki) -> None:
        with pytest.raises(CertificateError, match="unknown format"):
            render_format("nope", material_for(pki), Pkcs12Options())

    def test_render_names_and_secret_flag(self, pki: Pki) -> None:
        files = render(material_for(pki), ["fullchain", "key", "der"], {"key": "site.key"})
        assert [(f.format, f.name, f.secret) for f in files] == [
            ("fullchain", "fullchain.pem", False),
            ("key", "site.key", True),
            ("der", "cert.der", False),
        ]

    def test_every_format_renders(self, pki: Pki) -> None:
        files = render(material_for(pki), list(FORMATS), pkcs12_opts=Pkcs12Options(b"pw"))
        assert len({f.name for f in files}) == len(FORMATS)
        assert all(f.data for f in files)


class TestSameContent:
    def test_plain(self, pki: Pki) -> None:
        f = OutputFile("cert", "cert.pem", pki.leaf_pem, False)
        assert same_content(f, pki.leaf_pem, None)
        assert not same_content(f, b"other", None)
        assert not same_content(f, None, None)

    def test_pkcs12_salted_output_is_equal(self, pki: Pki) -> None:
        m = material_for(pki)
        opts = Pkcs12Options(b"pw")
        a = render(m, ["pkcs12"], pkcs12_opts=opts)[0]
        b = render(m, ["pkcs12"], pkcs12_opts=opts)[0]
        assert a.data != b.data
        assert same_content(a, b.data, b"pw")

    def test_pkcs12_different_cert(self, pki: Pki, other_pki: Pki) -> None:
        a = render(material_for(pki), ["pkcs12"], pkcs12_opts=Pkcs12Options(b"pw"))[0]
        b = render(material_for(other_pki), ["pkcs12"], pkcs12_opts=Pkcs12Options(b"pw"))[0]
        assert not same_content(a, b.data, b"pw")

    def test_pkcs12_garbage_or_wrong_password(self, pki: Pki) -> None:
        a = render(material_for(pki), ["pkcs12"], pkcs12_opts=Pkcs12Options(b"pw"))[0]
        assert not same_content(a, b"garbage", b"pw")
        other = render(material_for(pki), ["pkcs12"], pkcs12_opts=Pkcs12Options(b"x"))[0]
        assert not same_content(a, other.data, b"pw")
