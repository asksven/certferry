"""Exception hierarchy. Every error carries the process exit code it maps to."""

from __future__ import annotations

EXIT_OK = 0
EXIT_GENERAL = 1
EXIT_CONFIG = 2
EXIT_EXTRACT = 3
EXIT_DEPLOY = 4
EXIT_COMMAND = 5
EXIT_VERIFY = 6
EXIT_EXPIRY = 7


class CertferryError(Exception):
    """Base class for all expected, reportable failures."""

    exit_code = EXIT_GENERAL


class ConfigError(CertferryError):
    """Invalid command line or configuration file."""

    exit_code = EXIT_CONFIG


class ExtractError(CertferryError):
    """The secret could not be read from Kubernetes."""

    exit_code = EXIT_EXTRACT


class CertificateError(CertferryError):
    """The secret content is not a usable certificate / key pair."""

    exit_code = EXIT_EXTRACT


class DeployError(CertferryError):
    """Files could not be written to a target."""

    exit_code = EXIT_DEPLOY


class CommandFailed(CertferryError):
    """A post-deploy command returned a non-zero exit status."""

    exit_code = EXIT_COMMAND


class VerifyError(CertferryError):
    """Post-deploy verification failed."""

    exit_code = EXIT_VERIFY


class ExpiryError(CertferryError):
    """The certificate expires sooner than the configured threshold."""

    exit_code = EXIT_EXPIRY
