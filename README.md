# ntfy-idp-push

A drop-in replacement for the Duo Auth API, so Authelia's `duo_api` integration (and authentik's Duo
stage) delivers mobile push over [ntfy](https://ntfy.sh). ntfy is transport only: approving a sign-in
requires a signature from a device-bound passkey on the enrolled phone. See [PLAN.md](PLAN.md) for the
design.

## Run

```sh
ntfy-idp-push keygen                       # integration + secret key for the IdP
cp deploy/server.yml /etc/ntfy-idp-push/server.yml   # fill in
make image                                 # or: podman build -f Containerfile .
podman run -d -p 443:8443 \
  -v ntfy-idp-push:/var/lib/ntfy-idp-push \
  -v /etc/ntfy-idp-push/server.yml:/etc/ntfy-idp-push/server.yml:ro \
  ghcr.io/babraham123/ntfy-idp-push
```

A Podman quadlet is in [`deploy/`](deploy/). Every config key can also be set as `NTFY_IDP_PUSH_<KEY>`.
`SIGHUP` reloads per-request settings (`push-disabled`, keys, `enroll-access`, `push-timeout`).

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

Startup fails closed if the ntfy token is not admin, or anonymous reads of push topics are allowed.

## TLS

Authelia and authentik pin Duo's CA bundle, so the certificate must chain to one of those roots.
`tls-mode: acme` issues from Google Trust Services with EAB (TLS-ALPN-01 on the HTTPS port, ECDSA P-256);
`tls-mode: file` takes any certificate (DigiCert, GlobalSign…).

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
| `/c/<id>` | the phone (from the push) | approve with passkey, or report fraud |
| `/c/<id>/deny` | ntfy app `http` action | deny with token |
| `/provision`, `/provision/password`, `/devices` | forward-auth/OIDC user | ntfy account setup and manual sign-in, device list/revoke |
| `/frame/qr` | IdP | QR for an issued enrollment URL |

## Develop

```sh
make test   # go test -race ./...
```

Tests drive the real `duo_api_golang` client (v2 form and v5 JSON signing) against the server, with a
fake ntfy and a software WebAuthn authenticator, through enrollment, push, passkey approval, deny, fraud,
timeout, revocation and provisioning.
