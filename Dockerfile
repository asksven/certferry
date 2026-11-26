# syntax=docker/dockerfile:1
#
# certferry container image on Chainguard Python.
#
#   docker build -t certferry .                         # hardened distroless runtime (default)
#   docker build -t certferry:dev --target runtime-dev .  # simpler, larger, has apk + shells
#
# Layout (both targets):
#   /app/venv                 application virtualenv, owned by root, read-only at runtime
#   /usr/bin/kubectl          static kubectl copied from cgr.dev/chainguard/kubectl
#   /usr/bin/ssh, scp         OpenSSH client from Wolfi
#   /etc/certferry/           mount point for certferry.yaml (read-only)
#   /home/nonroot/.ssh/       mount point for id_*, known_hosts, config (read-only)
#   /home/nonroot/.kube/      mount point for kubeconfig (read-only; not needed in-cluster)
#   /tmp                      the ONLY path that must be writable (tmpfs / emptyDir):
#                             scp staging files and the kubectl discovery cache
#
# Pin the bases by digest in production, and keep python and python-dev on the same
# release (the build fails if their Python minor versions differ).

ARG PYTHON_IMAGE=cgr.dev/chainguard/python:latest@sha256:4ba1897d53045d3661b549ca66aa1888816d67c27632aca7913cd521d10589cc
ARG PYTHON_DEV_IMAGE=cgr.dev/chainguard/python:latest-dev@sha256:fbcaaaf39fa2d0c8cb15e836bc57a6966103e0aaacc76b643e0d596729f1e9fb
ARG KUBECTL_IMAGE=cgr.dev/chainguard/kubectl:latest@sha256:c72018fb3a29ea34b1d6190ee2e0d7276bef976c1feb628adb5b1c81256169a8
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11

FROM ${UV_IMAGE} AS uv
FROM ${KUBECTL_IMAGE} AS kubectl
FROM ${PYTHON_IMAGE} AS base

# ---------------------------------------------------------------------------------------------
# 1. Build the virtualenv in the -dev image (has uv/pip, a shell and apk).
# ---------------------------------------------------------------------------------------------
FROM ${PYTHON_DEV_IMAGE} AS build
USER root
COPY --from=uv /uv /usr/local/bin/uv

# Use the image's interpreter (never download one), copy instead of hardlink from the
# cache, precompile bytecode now because /app is read-only at runtime.
ENV UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/bin/python \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/app/venv

WORKDIR /src
# Dependencies first, so source edits do not invalidate this layer.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable \
 && /app/venv/bin/certferry --version

# ---------------------------------------------------------------------------------------------
# 2. Assemble the distroless root: a copy of the minimal python image plus the OpenSSH client,
#    a busybox /bin/sh (for string commands), kubectl and the venv. Everything is smoke
#    tested with chroot before it is copied into the final image.
# ---------------------------------------------------------------------------------------------
FROM ${PYTHON_DEV_IMAGE} AS assemble
USER root
COPY --from=base / /rootfs

RUN set -eux; \
    want="$(python -c 'import sys; print("%d.%d" % sys.version_info[:2])')"; \
    test -d "/rootfs/usr/lib/python${want}" \
      || { echo "python and python-dev images differ (need python${want})" >&2; exit 1; }; \
    mkdir -p /rootfs/etc/apk; \
    cp -a /etc/apk/keys /etc/apk/repositories /rootfs/etc/apk/; \
    apk add --no-cache --no-scripts --root /rootfs openssh-client busybox; \
    if [ ! -e /rootfs/bin/sh ]; then \
      bb="$(cd /rootfs && ls usr/bin/busybox bin/busybox 2>/dev/null | head -n1)"; \
      ln -s "/${bb}" /rootfs/bin/sh; \
    fi; \
    ldconfig -r /rootfs || true; \
    rm -rf /rootfs/etc/apk/keys /rootfs/var/cache/apk/*; \
    install -d -m 0755 /rootfs/etc/certferry; \
    install -d -o 65532 -g 65532 -m 0700 /rootfs/home/nonroot/.ssh /rootfs/home/nonroot/.kube

COPY --from=kubectl /usr/bin/kubectl /rootfs/usr/bin/kubectl
COPY --from=build /app/venv /rootfs/app/venv

RUN set -eux; \
    chroot /rootfs /bin/sh -c 'echo shell-ok'; \
    chroot /rootfs /usr/bin/ssh -V; \
    chroot /rootfs /usr/bin/scp 2>&1 | grep -qi usage; \
    chroot /rootfs /usr/bin/kubectl version --client; \
    for args in "--version" "--list-formats"; do \
      chroot /rootfs /usr/bin/python -c "import os, sys; os.setgid(65532); os.setuid(65532); \
os.execv('/app/venv/bin/certferry', ['certferry', sys.argv[1]])" "$args" >/dev/null; \
    done; \
    chroot /rootfs /usr/bin/python -c "import os; os.setgid(65532); os.setuid(65532); \
assert not os.access('/app/venv', os.W_OK), 'venv must not be writable by nonroot'"

# ---------------------------------------------------------------------------------------------
# 3. Default target: distroless runtime (no apk, no pip, no uv).
# ---------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
COPY --from=assemble /rootfs /

ENV PATH=/app/venv/bin:/usr/local/bin:/usr/bin:/bin \
    HOME=/home/nonroot \
    TMPDIR=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CERTFERRY_KUBECTL_CACHE_DIR=/tmp/kube-cache

USER 65532:65532
WORKDIR /home/nonroot
LABEL org.opencontainers.image.title="certferry" \
      org.opencontainers.image.description="Ship cert-manager TLS secrets to files, hosts and services" \
      org.opencontainers.image.source="https://github.com/OWNER/certferry"

# The Chainguard python image's entrypoint is /usr/bin/python; replace it.
ENTRYPOINT ["/app/venv/bin/certferry"]
CMD ["--help"]

# ---------------------------------------------------------------------------------------------
# Alternative target: run on python:latest-dev directly. Simpler and easier to debug (it has
# a shell and apk), but carries more packages; Chainguard recommends -dev for builds only.
# ---------------------------------------------------------------------------------------------
FROM ${PYTHON_DEV_IMAGE} AS runtime-dev
USER root
RUN apk add --no-cache openssh-client \
 && install -d -m 0755 /etc/certferry \
 && install -d -o 65532 -g 65532 -m 0700 /home/nonroot/.ssh /home/nonroot/.kube
COPY --from=kubectl /usr/bin/kubectl /usr/bin/kubectl
COPY --from=build /app/venv /app/venv

ENV PATH=/app/venv/bin:/usr/local/bin:/usr/bin:/bin \
    HOME=/home/nonroot \
    TMPDIR=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CERTFERRY_KUBECTL_CACHE_DIR=/tmp/kube-cache

USER 65532:65532
WORKDIR /home/nonroot
ENTRYPOINT ["/app/venv/bin/certferry"]
CMD ["--help"]

# Keep the hardened image as the default when no --target is given.
FROM runtime
