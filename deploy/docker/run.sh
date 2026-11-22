#!/bin/sh
# Run certferry from a host (e.g. a systemd timer) with the same hardening as in Kubernetes:
# read-only root filesystem, tmpfs /tmp, no capabilities, nonroot UID 65532.
#
# The mounted files must be readable by UID 65532 (or group 65532), e.g.:
#   install -d -m 0750 -g 65532 /etc/certferry /etc/certferry/ssh
#   install -m 0640 -g 65532 kubeconfig certferry.yaml /etc/certferry/
#   install -m 0640 -g 65532 id_ed25519 known_hosts /etc/certferry/ssh/
#
# Local directory targets must be bind mounted and writable by 65532, e.g.
#   -v /etc/nginx/ssl:/out/nginx    (and use "/out/nginx" as the target in certferry.yaml)
set -eu

IMAGE="${CERTFERRY_IMAGE:-certferry:latest}"
CONF_DIR="${CERTFERRY_CONF_DIR:-/etc/certferry}"

exec docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777 \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network host \
  -e KUBECONFIG=/etc/certferry/kubeconfig \
  -v "${CONF_DIR}/certferry.yaml:/etc/certferry/certferry.yaml:ro" \
  -v "${CONF_DIR}/kubeconfig:/etc/certferry/kubeconfig:ro" \
  -v "${CONF_DIR}/ssh:/home/nonroot/.ssh:ro" \
  "${IMAGE}" --config /etc/certferry/certferry.yaml "$@"
