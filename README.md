# ntfy-idp-push

A drop-in replacement for the Duo Auth API, so Authelia's `duo_api` integration (and authentik's Duo
stage) delivers mobile push over [ntfy](https://ntfy.sh). ntfy is transport only: approving a sign-in
requires a signature from a device-bound passkey on the enrolled phone. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the design.

It also works as a generic **ntfy provisioning tool**, with no Duo integration at all: behind your IdP,
`/provision` creates the signed-in user's ntfy account, applies `enroll-access` grants, and signs their
phone or browser into ntfy with a one-tap link or QR (`user provision <u>` does the same from the CLI).

## Run

With Docker Compose ([`deploy/compose.yaml`](deploy/compose.yaml)):

```sh
ntfy-idp-push keygen                 # integration + secret key for the IdP
mkdir -p deploy/config deploy/secrets
cp deploy/server.yml deploy/config/server.yml     # fill in; leave the secrets out
cp tls.crt tls.key deploy/config/
printf '%s' '<secret key>' > deploy/secrets/duo_secret_key
printf '%s' 'tk_…' > deploy/secrets/ntfy_admin_token
docker compose -f deploy/compose.yaml up -d
```

```yaml
services:
  ntfy-idp-push:
    image: ghcr.io/babraham123/ntfy-idp-push:latest
    restart: unless-stopped
    ports: ["443:8443"]
    volumes:
      - ./config:/etc/ntfy-idp-push:ro     # a directory, so replaced files are seen
      - state:/var/lib/ntfy-idp-push
    environment:
      NTFY_IDP_PUSH_TLS_CERT_FILE: /etc/ntfy-idp-push/tls.crt
      NTFY_IDP_PUSH_TLS_KEY_FILE: /etc/ntfy-idp-push/tls.key
      NTFY_IDP_PUSH_DUO_SECRET_KEY_FILE: /run/secrets/duo_secret_key
      NTFY_IDP_PUSH_NTFY_ADMIN_TOKEN_FILE: /run/secrets/ntfy_admin_token
    secrets: [duo_secret_key, ntfy_admin_token]
secrets:
  duo_secret_key: {file: ./secrets/duo_secret_key}
  ntfy_admin_token: {file: ./secrets/ntfy_admin_token}
volumes:
  state:
```

`make image` builds the image locally. Run CLI commands in the container with
`docker compose -f deploy/compose.yaml exec ntfy-idp-push ntfy-idp-push <command>`.

Configuration: every key in [`deploy/server.yml`](deploy/server.yml) can also be set as
`NTFY_IDP_PUSH_<KEY>`. Secrets (`duo-secret-key`, `duo-secret-key-previous`, `ntfy-admin-token`,
`oidc-client-secret`) can instead be read from a file, named by `<key>-file` in the config or by
`NTFY_IDP_PUSH_<KEY>_FILE`, which suits Docker secrets and systemd credentials. `SIGHUP`
(`docker compose kill -s HUP`) reloads per-request settings (`push-disabled`, keys and secret files,
`enroll-access`, `push-timeout`).

ntfy prerequisites (`server.yml`):

```yaml
auth-default-access: deny-all
auth-users: ["idp-push:<bcrypt>:admin"]
auth-tokens: ["idp-push:tk_…:ntfy-idp-push"]
```

Authelia:

```yaml
duo_api:
  hostname: push.example.com
  integration_key: DI…
  secret_key: …
  enable_self_enrollment: true
```

Startup fails closed if the ntfy token is not admin, anonymous reads of push topics are allowed, or the
ntfy user list exceeds the client's 1 MiB response cap.

## TLS

Set `tls-cert-file` and `tls-key-file`; the pair is reloaded when the certificate file changes. Or set
`listen-http` and terminate TLS in a proxy that preserves `Host`. Duo clients pin Duo's CA bundle, so the
IdP must trust the shim's certificate chain or have that pinning disabled.

## CLI

```
serve | keygen [--rotate] | enroll-link <user> | audit [user] | healthcheck [url] | version
user list | provision <u> | disable <u> | enable <u> | delete <u> [--keep-ntfy-user] | approve <challenge>
user reset-ntfy <u> [--force]
device list <u> | revoke <id> [--reset-ntfy-user] [--force]
```

## Routes

| Path | Who | Purpose |
|---|---|---|
| `/auth/v2/{ping,check,preauth,auth,enroll,enroll_status}` | IdP (signed) | Duo Auth API |
| `/enroll` | forward-auth/OIDC user, or `?code=` | register passkey, get ntfy link |
| `/enroll/resend`, `/enroll/password` | the enrollment result page | resend the setup push; set an ntfy password for apps without one-tap sign-in |
| `/enroll/verify/<device>` | the phone (from the test push) | activate device |
| `/challenge/<id>` | the phone (from the push) | approve with passkey, or report fraud |
| `/challenge/<id>/deny` | ntfy app `http` action | deny with token |
| `/provision`, `/provision/password`, `/devices` | forward-auth/OIDC user | ntfy account setup and manual sign-in, device list/revoke |
| `/enroll/qr` | IdP | QR for an issued enrollment URL |
| `/oidc/login`, `/oidc/callback` | browser (`auth-mode: oidc`) | sign in to the pages above |

## Develop

```sh
make test   # go test -race ./...
```

Tests drive the real `duo_api_golang` client (v2 form and v5 JSON signing) against the server, with a
fake ntfy, a fake OIDC provider and a software WebAuthn authenticator, through enrollment, push, passkey
approval, deny, fraud, timeout, revocation and provisioning.
