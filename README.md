# certferry

Ferry TLS certificates that cert-manager maintains in Kubernetes to the services that live
outside the cluster.

`certferry` reads a `kubernetes.io/tls` secret with `kubectl`, renders it into the file formats
the consuming service expects, deploys the files to local directories and/or remote hosts
(scp), runs reload/restart commands locally or over ssh, and optionally verifies that the
files are in place and that the endpoint actually serves the new certificate.

Output is designed for scripts, cron and log shippers: plain `key=value` lines (or JSON), no
colors, no emoji, and distinct exit codes per failure class.

## Install

```sh
uv tool install .            # installs the `certferry` command
# or run from the checkout
uv run certferry --help
```

Runtime requirements: Python 3.10+, `kubectl` with access to the cluster, and the OpenSSH
`ssh`/`scp` clients for remote targets. The remote side only needs a POSIX shell, `mkdir`,
`mv`, `cat` and `rm`.

## Quick start

Use case 1 - write into a directory and reload nginx:

```sh
certferry --certificate example-com -n web \
  --target /etc/nginx/ssl/example.com \
  --exec 'nginx -t && systemctl reload nginx' \
  --verify-files --verify-endpoint 127.0.0.1:443 --verify-servername example.com
```

Use case 2 - copy to a remote machine and let a Caddy container reload:

```sh
certferry --secret example-com-tls -n web \
  --target scp://deploy@proxy.example.com/srv/caddy/certs \
  --remote-exec deploy@proxy.example.com \
      'docker exec caddy caddy reload --config /etc/caddy/Caddyfile --force' \
  --verify-endpoint proxy.example.com:443
```

Use case 3 - any combination, several jobs, from a file (see `examples/`):

```sh
certferry -c examples/combined.yaml --only-if-changed -o jsonl
```

Use case 4 - extract from kubernetes, copy to remote server and restart nginx

```sh
uv run certferry --secret $SECRET_NAME$ -n $NAMEPACE$ \
  --target certferry@$SERVER$:/etc/nginx/ssl \
  --filename fullchain=$CERT_NAME.crt --filename key=CERT_NAME.key \
  --remote-exec certferry@$SERVER$ 'sudo -n nginx -t && sudo -n systemctl reload nginx.service' \
  --verify-files \
  --verify-endpoint $DOMAIN$:443 \
  --min-days 14 \
  --only-if-changed
```  


Run `certferry --check-config -c FILE` to validate a file and see the resolved jobs without
touching the cluster, and `--dry-run` to extract and compare without writing anything.

## Remote permissions

For the case certferry needs to update remote servers and restart services it requires a user and permissions. This example configures a user `certcaddy`, gives it permissions to write to `/etc`:

```sh
# 1. Create the user 
sudo adduser --disabled-password --gecos "" certferry

# 2. Setup public key
sudo install -d -o certferry -g certferry -m 0700 /home/certferry/.ssh
sudo tee -a /home/certferry/.ssh/authorized_keys < your_key.pub
sudo chown certferry:certferry /home/certferry/.ssh/authorized_keys
sudo chmod 0600 /home/certferry/.ssh/authorized_keys

# 3. Give it permissions to the cert folder
sudo install -d -o certferry -g certferry -m 0750 /etc/nginx/ssl
sudo usermod -aG certferry ubuntu     # log out and back in afterwards

# 4. Allow reloading the service
echo 'certferry ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /usr/bin/systemctl reload nginx.service' \
  | sudo tee /etc/sudoers.d/certferry
sudo chmod 0440 /etc/sudoers.d/certferry
sudo visudo -cf /etc/sudoers.d/certferry     # must print "parsed OK"
```

## What happens in a run

For every job, in order:

| step              | what it does                                                            |
|-------------------|-------------------------------------------------------------------------|
| `extract`         | `kubectl get secret` (or resolves a cert-manager `Certificate` first, and requires it to be `Ready`); checks the key matches the leaf |
| `render`          | builds the requested formats in memory                                  |
| `compare`         | with `--only-if-changed`: reads what is deployed and decides per target |
| `deploy`          | writes files atomically (temp file + rename), local or via scp + `mv`   |
| `command`         | runs post-deploy commands in the given order; skipped if nothing changed |
| `verify-files`    | re-reads every deployed file and compares it with what was rendered      |
| `verify-endpoint` | TLS handshake against host:port (with SNI); compares the served leaf to the extracted one, with retries |
| `expiry`          | with `--min-days N`: fails if the certificate expires within N days       |

A failure stops that job; other jobs still run unless `--fail-fast` is given. The expiry
check runs last, so an expiring certificate is still deployed but the run reports failure
(useful as an alert that cert-manager stopped renewing).

## Formats

Which format a service needs (`certferry --list-formats` prints the list):

| format            | default file          | contents                              | typical consumer |
|-------------------|-----------------------|---------------------------------------|------------------|
| `fullchain`       | `fullchain.pem`       | leaf + intermediates                  | nginx, Caddy, Apache >= 2.4.8, Traefik, Envoy, Postfix, Dovecot, Grafana |
| `key`             | `key.pem`             | private key as stored by cert-manager  | everything PEM based |
| `cert`            | `cert.pem`            | leaf only                             | Apache < 2.4.8 (`SSLCertificateFile`), appliances |
| `chain`           | `chain.pem`           | intermediates only                    | Apache < 2.4.8 (`SSLCertificateChainFile`), OCSP stapling |
| `ca`              | `ca.pem`              | `ca.crt` from the secret              | clients/mTLS trust; only present for CA/Vault/self-signed issuers |
| `combined`        | `combined.pem`        | fullchain + key in one file           | HAProxy, some Lighttpd/Webmin setups |
| `key-pkcs8`       | `key.pkcs8.pem`       | `BEGIN PRIVATE KEY`                   | Java/Netty, Node tools that insist on PKCS#8 |
| `key-traditional` | `key.traditional.pem` | `BEGIN RSA/EC PRIVATE KEY`            | older software expecting PKCS#1 / SEC1 |
| `der`             | `cert.der`            | leaf in binary DER                    | appliances, Windows `.cer` import |
| `pkcs12`          | `cert.p12`            | key + leaf + chain (+ ca), encrypted  | Java keystores (Tomcat, Keycloak, Jenkins, Kafka), Windows/IIS, Exchange |

Notes:

* cert-manager stores the key in PKCS#1 or PKCS#8 depending on the Certificate's
  `spec.privateKey.encoding`. Use `key-pkcs8` / `key-traditional` when the consumer is picky.
* Files containing key material (`key*`, `combined`, `pkcs12`) get `--key-mode` (default
  `0600`); the others get `--cert-mode` (default `0644`).
* PKCS#12 uses AES-256 by default. `--pkcs12-legacy` switches to 3DES/SHA1, which Java 8
  before 8u301, Windows Server 2016 and older, and OpenSSL 1.0 need. Java 9+ reads PKCS#12
  directly as a keystore, so no JKS conversion is needed; if you really need JKS, run
  `keytool -importkeystore` as a post command.
* A password is never accepted on the command line; use `--pkcs12-password-env` or
  `--pkcs12-password-file` (YAML also allows `password:` inline, not recommended).
* PKCS#12 output is randomly salted, so `--only-if-changed` and `--verify-files` compare it
  by decoding it with the password instead of byte for byte.

### Reload hints

* **nginx**: `nginx -t && systemctl reload nginx` (or `nginx -s reload`).
* **Caddy**: `caddy reload` skips a reload when the config file is unchanged; certificate
  files changing on disk do not count, so use `--force`:
  `docker exec caddy caddy reload --config /etc/caddy/Caddyfile --force`.
  If Caddy runs without the admin API, restart the container instead.
* **HAProxy**: `haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy`.
* **Apache**: `apachectl configtest && systemctl reload apache2`.
* **Java services**: usually need a restart unless they watch the keystore.

## Configuration file

A file contains either a single job at the top level, or `defaults` plus a list of `jobs`.
Every value under `defaults` is applied to each job; nested sections (`ssh`, `verify`,
`pkcs12`, `filenames`) are merged one level deep. Command line options override both and
apply to every job, so combine them with `--job NAME` when the file has several jobs. List
options given on the command line (`--target`, `--exec`, `--verify-endpoint`, ...) replace
the lists from the file rather than extending them.

```yaml
defaults:
  context: prod                  # kubectl --context
  kubeconfig: ~/.kube/config     # optional
  kubectl: kubectl               # executable
  namespace: web
  kubectl_timeout: 60
  kubectl_cache_dir: /tmp/kube-cache   # default: $CERTFERRY_KUBECTL_CACHE_DIR
  ssh:
    ssh_bin: ssh
    scp_bin: scp
    identity: ~/.ssh/id_ed25519
    options: [StrictHostKeyChecking=yes]   # each becomes -o OPTION
    batch_mode: true                       # -o BatchMode=yes, never prompt
    connect_timeout: 10

jobs:
  - name: website                 # defaults to the secret/certificate name
    certificate: example-com      # or: secret: example-com-tls
    require_ready: true           # only with certificate
    formats: [fullchain, key]
    filenames: {fullchain: example.com.crt, key: example.com.key}
    cert_mode: "0644"             # quote modes so YAML does not read them as decimal
    key_mode: "0600"
    targets:
      - /etc/nginx/ssl                         # string forms: /dir, dir:/dir,
      - deploy@proxy:/srv/certs                #   [user@]host:path,
      - scp://deploy@proxy:2222/srv/certs      #   scp://[user@]host[:port]/path
      - type: dir                              # mapping form
        path: /etc/haproxy/certs
        owner: haproxy                         # local targets only
        group: haproxy
        create: true                           # mkdir -p (default true)
      - type: scp
        host: proxy.example.com
        user: deploy
        port: 22
        path: /srv/caddy/certs
        timeout: 120
    commands:
      - nginx -t && systemctl reload nginx     # string: run through the local shell
      - [systemctl, reload, nginx]             # list: run without a shell
      - host: deploy@proxy.example.com:22      # remote via ssh (user/port may be separate)
        run: docker exec caddy caddy reload --config /etc/caddy/Caddyfile --force
        timeout: 120
    verify:
      files: true
      endpoints:
        - example.com:443
        - {host: 10.0.0.5, port: 443, servername: example.com}
      retries: 5
      delay: 2
      timeout: 5
    pkcs12: {password_env: KEYSTORE_PASSWORD, legacy: false, friendly_name: server}
    min_days: 14
    only_if_changed: true
```

Local commands receive `CERTFERRY_JOB`, `CERTFERRY_FINGERPRINT` (SHA-256 of the leaf, hex),
`CERTFERRY_NOT_AFTER` and `CERTFERRY_COMMON_NAME` in their environment.

## Output

`-o text` (default) prints one logfmt line per step, values with spaces are JSON-quoted:

```
job=website step=extract status=ok secret=web/example-com-tls common_name=example.com dns_names=example.com,www.example.com not_after=2027-01-15T08:00:00+00:00 fingerprint=3f9a...
job=website step=render status=ok formats=fullchain,key files=fullchain.pem,key.pem
job=website step=deploy status=ok target=dir:/etc/nginx/ssl files=fullchain.pem,key.pem
job=website step=command status=ok index=0 location=local command="nginx -t && systemctl reload nginx"
job=website step=verify-endpoint status=ok endpoint=127.0.0.1:443#example.com attempts=1 fingerprint=3f9a...
job=website step=expiry status=ok days_remaining=89.6 not_after=2027-01-15T08:00:00+00:00
step=summary status=ok exit_code=0 jobs=1 failed="" changed=website
```

`-o jsonl` prints the same events as JSON objects, one per line. `-o json` prints a single
document at the end with every job, its certificate details and its events. Diagnostics go
to stderr (`-v`, `-vv` shows every executed command); secret material is never logged.

Statuses: `ok`, `failed`, `skipped`, `dry-run`, and for `compare`: `changed` / `unchanged`.

### Exit codes

| code | meaning                                             |
|------|-----------------------------------------------------|
| 0    | success                                             |
| 1    | unexpected error                                    |
| 2    | invalid command line or configuration               |
| 3    | secret could not be read or is not a valid cert/key |
| 4    | deploying to a target failed                        |
| 5    | a post-deploy command failed                        |
| 6    | verification failed                                 |
| 7    | certificate expires within `--min-days`             |

With several jobs the exit code is the one of the first failing job.

## Running it periodically

cert-manager renews ahead of expiry, so polling is enough:

```ini
# /etc/systemd/system/certferry.service
[Service]
Type=oneshot
Environment=KUBECONFIG=/etc/certferry/kubeconfig
ExecStart=/usr/local/bin/certferry -c /etc/certferry/certferry.yaml --only-if-changed -o jsonl

# /etc/systemd/system/certferry.timer
[Timer]
OnCalendar=hourly
RandomizedDelaySec=10m
[Install]
WantedBy=timers.target
```

Give the kubeconfig a ServiceAccount that may only `get` the secrets (and `certificates`)
it needs:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: certferry, namespace: web}
rules:
  - apiGroups: [""]
    resources: [secrets]
    resourceNames: [example-com-tls]
    verbs: [get]
  - apiGroups: [cert-manager.io]
    resources: [certificates]
    verbs: [get]
```

## Container image

The `Dockerfile` builds on [Chainguard](https://images.chainguard.dev/directory/image/python/overview)
Python images and bundles `kubectl` and the OpenSSH client.

```sh
docker build -t certferry .                          # hardened distroless image (default)
docker build -t certferry:dev --target runtime-dev .  # python:latest-dev based, has a shell + apk
```

### How the image is put together

Chainguard ships two free variants: `python:latest` is distroless (no shell, no apk, no pip)
and `python:latest-dev` adds pip, uv, apk and shells. Chainguard recommends building in
`-dev` and running on the minimal image. certferry, however, needs three things at runtime
that the minimal image does not have: `ssh`/`scp`, `kubectl`, and `/bin/sh` for string
commands. The build therefore has three stages:

1. **build** (`python:latest-dev`): `uv sync --locked --no-dev --no-editable` into
   `/app/venv`, using the image's own interpreter (`UV_PYTHON_DOWNLOADS=never`) and
   precompiling bytecode (`UV_COMPILE_BYTECODE=1`), because nothing may write `.pyc` files
   at runtime.
2. **assemble** (`python:latest-dev`, as root): copies the whole distroless `python:latest`
   filesystem to `/rootfs`, installs `openssh-client` and `busybox` into it with
   `apk add --root /rootfs --no-scripts`, adds the static `kubectl` from
   `cgr.dev/chainguard/kubectl` and the venv, then smoke tests everything with `chroot`
   (including running certferry as UID 65532 and checking it cannot write to `/app`). It
   also fails the build if `python` and `python-dev` were pulled at different Python minor
   versions, since the venv's interpreter symlink would break.
3. **runtime** (`python:latest`): receives the assembled root. No apk, pip or uv; entrypoint
   is `/app/venv/bin/certferry` (the Chainguard python image's own entrypoint is
   `/usr/bin/python`, so it is replaced explicitly).

The `runtime-dev` target is the simple alternative: `apk add openssh-client` on
`python:latest-dev` and drop back to UID 65532. Easier to debug, but it ships apk, pip and
shells, which Chainguard advises against for production.

Free Chainguard images only offer `latest` / `latest-dev`. Pin all four `ARG` images
(`PYTHON_IMAGE`, `PYTHON_DEV_IMAGE`, `KUBECTL_IMAGE`, `UV_IMAGE`) by digest and rebuild
regularly; keep kubectl within one minor version of your cluster.

### Read-only filesystem layout

The image is meant to run with a read-only root filesystem as UID 65532 (`nonroot`, which
exists in the image's `/etc/passwd`; ssh refuses to run for a UID without a passwd entry,
so do not let a platform assign a random UID).

| path                    | mode      | what goes there                                         |
|-------------------------|-----------|---------------------------------------------------------|
| `/app/venv`             | read-only, root owned | the application                             |
| `/etc/certferry/`       | read-only mount | `certferry.yaml` (`CERTFERRY_CONFIG` can point to it) |
| `/home/nonroot/.ssh/`   | read-only mount | `id_ed25519`, `known_hosts`, optional `config`    |
| `/home/nonroot/.kube/` or `KUBECONFIG` | read-only mount | kubeconfig; not needed in-cluster |
| `/tmp`                  | **writable** (tmpfs / emptyDir) | scp staging files, kubectl cache  |
| any local target dir    | writable mount  | e.g. a host directory nginx reads from            |

What this means in practice:

* `/tmp` is the only writable path. `TMPDIR=/tmp`, and `CERTFERRY_KUBECTL_CACHE_DIR=/tmp/kube-cache`
  makes certferry pass `--cache-dir` to kubectl (kubectl itself has no environment variable
  for it and would otherwise try `$HOME/.kube/cache`).
* `known_hosts` is read-only, so ssh can never add a host. Pre-populate it
  (`ssh-keyscan host >> known_hosts`, verify the fingerprints) and use
  `StrictHostKeyChecking=yes`; `accept-new` fails on a read-only mount.
* Kubernetes secret volumes are owned by root with group `fsGroup`. OpenSSH only rejects a
  group-readable private key when the key belongs to the running user, so `defaultMode: 0440`
  with `fsGroup: 65532` works; with plain Docker, make the key group-readable for GID 65532.
* `PYTHONDONTWRITEBYTECODE=1` avoids write attempts next to the source.

### Running it

In the cluster (recommended): `deploy/kubernetes/certferry.yaml` contains a ServiceAccount,
a Role limited to `get` on the specific secrets, a ConfigMap with the configuration and a
CronJob with `readOnlyRootFilesystem: true`, dropped capabilities, a memory-backed `/tmp`
and the ssh key from a Secret. kubectl uses the pod's ServiceAccount automatically, so no
kubeconfig is involved. This fits the scp + remote command use cases.

From a host: `deploy/docker/run.sh` runs the image with `--read-only`, a tmpfs `/tmp`,
`--cap-drop ALL`, `no-new-privileges` and the configuration, kubeconfig and ssh directory
mounted read-only. Local directory targets must be bind mounted into the container and
writable by UID 65532; reloading a service on the same host from inside a container is
best done with `--remote-exec` to that host.

CI builds both targets and checks, with `--read-only` and a tmpfs `/tmp`: the entrypoint,
kubectl/ssh/scp/sh presence, that it runs as 65532 with an immutable `/app` and only `/tmp`
writable, that the hardened image has no apk/pip/uv, that the example configs validate
inside the container, and runs a Trivy scan.

#### Running as a Kubernetes CronJob

##### 1. Create an ssh key for certferry

Generate a dedicated key without a passphrase (the CronJob can't type one):

```sh
ssh-keygen -t ed25519 -N "" -C "certferry@cronjob" -f ./certferry_ed25519
```

This creates `certferry_ed25519` (private key, goes into the Secret) and
`certferry_ed25519.pub` (public key, goes onto the server).

Install the public key for the `certferry` user on the target server:

```sh
scp certferry_ed25519.pub server-flori:/tmp/
ssh server-flori 'sudo tee -a /home/certferry/.ssh/authorized_keys < /tmp/certferry_ed25519.pub \
  && sudo chown certferry:certferry /home/certferry/.ssh/authorized_keys \
  && sudo chmod 0600 /home/certferry/.ssh/authorized_keys && rm /tmp/certferry_ed25519.pub'
```

Test that the new key works and sudo needs no password:

```sh
ssh -i ./certferry_ed25519 -o IdentitiesOnly=yes certferry@server-flori 'sudo -n nginx -t'
```

### 2. Record the server's host key

The container's `.ssh` folder is read-only, so ssh can't add unknown hosts.
Collect the host key in advance:

```sh
ssh-keyscan -t ed25519 server-flori > ./known_hosts
ssh-keygen -lf ./known_hosts                                     # fingerprint you collected
ssh server-flori 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'  # must match
```

The host name in `known_hosts` must be exactly the name used in the
certferry config (`server-flori`), and the pod must be able to resolve it.
If cluster DNS doesn't know `server-flori`, use its FQDN or IP address in both
places.

##### 3. Create the Secret

```sh
kubectl create namespace certferry
kubectl -n certferry create secret generic certferry-ssh \
  --from-file=id_ed25519=./certferry_ed25519 \
  --from-file=known_hosts=./known_hosts
```

The key names matter: ssh picks up `~/.ssh/id_ed25519` automatically, and the
config sets `UserKnownHostsFile=/home/nonroot/.ssh/known_hosts`. The CronJob
mounts the Secret with `defaultMode: 0440` and `fsGroup: 65532`, which ssh
accepts.

Check it, then delete the local private key copy:

```sh
kubectl -n certferry get secret certferry-ssh -o jsonpath='{.data}' | jq 'keys'
# ["id_ed25519","known_hosts"]
shred -u ./certferry_ed25519
```

To rotate the key later, generate a new one, add its public key to
`authorized_keys`, replace the Secret with
`kubectl -n certferry create secret generic certferry-ssh ... --dry-run=client -o yaml | kubectl apply -f -`,
and then remove the old public key from the server.

## Development

```sh
uv sync                    # create .venv with runtime + dev dependencies
uv run pytest              # tests with coverage (fails under 90%)
uv run ruff check .        # lint
uv run ruff format .       # format
uv run mypy                # strict type check
```

The tests need no cluster and no remote host: they generate a throw-away PKI, put fake
`kubectl`, `ssh` and `scp` executables on disk (the fake ssh/scp act on the local file
system), and start a local TLS server for endpoint verification. `tests/test_cli.py`
exercises the documented use cases plus the full matrix of target types x command types x
verification modes, and every format against every target type.

CI (`.github/workflows/ci.yml`) runs lint, format check and mypy, the test suite on Python
3.10 to 3.13, and builds and smoke-tests the wheel.
