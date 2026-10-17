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
printf '%s' '<client secret>' > deploy/secrets/oidc_client_secret
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
    environment:                           # where the app reads each mounted secret
      NTFY_IDP_PUSH_DUO_SECRET_KEY_FILE: /run/secrets/duo_secret_key
      NTFY_IDP_PUSH_NTFY_ADMIN_TOKEN_FILE: /run/secrets/ntfy_admin_token
      NTFY_IDP_PUSH_OIDC_CLIENT_SECRET_FILE: /run/secrets/oidc_client_secret
    secrets: [duo_secret_key, ntfy_admin_token, oidc_client_secret]   # mounts them at /run/secrets/<name>
secrets:                                   # where Compose reads each secret on the host
  duo_secret_key: {file: ./secrets/duo_secret_key}
  ntfy_admin_token: {file: ./secrets/ntfy_admin_token}
  oidc_client_secret: {file: ./secrets/oidc_client_secret}
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

identity_providers:
  oidc:
    clients:
      - client_id: ntfy-idp-push
        client_secret: $pbkdf2-sha512$…         # authelia crypto hash generate; plaintext in oidc-client-secret
        authorization_policy: two_factor        # a stolen password alone must not enroll a phone
        redirect_uris: [https://push.example.com/oidc/callback]   # <public-url>/oidc/callback
        scopes: [openid, profile]               # profile carries preferred_username
        require_pkce: true
        pkce_challenge_method: S256
```

First enrollment: the user registers another second factor in Authelia (TOTP or a browser passkey), uses
it to pass the `two_factor` policy on the shim's client, and enrolls the phone at `/enroll`; push works
from then on. Without one, an admin issues a single-use link with `enroll-link <user>`. authentik enrolls
through its own Duo stage (`/auth/v2/enroll`).

Startup fails closed if the ntfy token is not admin, anonymous reads of push topics are allowed, or the
ntfy user list exceeds the client's 1 MiB response cap.

## TLS

Set `tls-cert-file` and `tls-key-file`; the pair is reloaded when the certificate file changes. Or set
`listen-http` and terminate TLS in a proxy that preserves `Host`. Duo clients pin Duo's CA bundle, so the
IdP must trust the shim's certificate chain or have that pinning disabled.

## Backup

The database holds every passkey; losing it means re-enrolling every phone. `backup` writes a
consistent copy while the server runs, `-` to stdout:

```sh
docker compose -f deploy/compose.yaml exec -T ntfy-idp-push ntfy-idp-push backup - > backup.sqlite
```

To restore, stop the server and replace `db.sqlite` with the copy, deleting any `db.sqlite-wal` and
`db.sqlite-shm` beside it.

## CLI

```
ntfy-idp-push [-c config.yml] <command>

Server
  serve                                      run the server
  healthcheck [url]                          exit 0 if /healthz answers (default https://127.0.0.1:8443/healthz)
  backup <path>|-                            consistent database copy, safe while serving
  keygen [--rotate]                          new integration/secret keys, or rotate the secret in the config
  version

Users
  user list
  user provision <user>                      create the ntfy account and apply enroll-access
  user disable|enable <user>
  user delete <user> [--keep-ntfy-user]
  user reset-ntfy <user> [--force]           recreate the ntfy user, invalidating its tokens
  user approve <challenge-id>                approve a pending login without a passkey (break-glass)
  enroll-link <user>                         single-use enrollment link, valid 5 minutes
  audit [user]                               last 100 audit entries

Devices
  device list <user>
  device revoke <device-id> [--reset-ntfy-user] [--force]
```

## Routes

Access: **IdP** needs a session from the shim's own OIDC sign-in; pages redirect to `/oidc/login`.
**Public** must be reachable from the user's phone and browser; each route checks its own code, token or
passkey. **Internal** is called only by the IdP server or the container healthcheck. Nothing needs
protecting or bypassing at a proxy.

| Path | Access | Purpose |
|---|---|---|
| `/provision`<br>`/provision/password`<br>`/devices`<br>`/devices/<id>/revoke` | IdP | ntfy account setup and manual sign-in; device list and revoke |
| `/enroll`<br>`/enroll/begin`<br>`/enroll/finish` | Public with `?code=`, else IdP | register a passkey, get the ntfy link |
| `/enroll/resend`<br>`/enroll/password` | Public (result-page token) | resend the setup push; set an ntfy password for apps without one-tap sign-in |
| `/enroll/verify/<device>` | Public (token in the setup push) | activate the device |
| `/enroll/qr` | Public (shim-issued codes only) | QR for an enrollment URL, shown by the IdP |
| `/challenge/<id>`<br>`/challenge/<id>/options`<br>`/challenge/<id>/assert`<br>`/challenge/<id>/fraud` | Public (passkey) | approve a sign-in, or report fraud |
| `/challenge/<id>/deny` | Public (deny token) | the ntfy app's Deny action |
| `/oidc/login`<br>`/oidc/callback` | Public | sign in to the IdP pages |
| `/static/` | Public | page assets |
| `/auth/v2/ping`<br>`/auth/v2/check`<br>`/auth/v2/preauth`<br>`/auth/v2/auth`<br>`/auth/v2/enroll`<br>`/auth/v2/enroll_status` | Internal (IdP server; HMAC-signed except `ping`) | Duo Auth API; see [TLS](#tls) for certificate pinning |
| `/healthz` | Internal | health check |

## Releases

Pushing a `vX.Y.Z` tag runs CI, then publishes Linux and macOS binaries (amd64, arm64) with
checksums to the GitHub release, and pushes `ghcr.io/babraham123/ntfy-idp-push:X.Y.Z`, `:X.Y` and
`:latest` for amd64 and arm64 with an SBOM and build provenance. Or install from source:
`go install github.com/babraham123/ntfy-idp-push/cmd/ntfy-idp-push@latest`.

## Develop

```sh
make test   # go test -race ./...
make lint   # gofmt, go vet, staticcheck, govulncheck; CI runs both on every PR
```

Tests drive the real `duo_api_golang` client (v2 form and v5 JSON signing) against the server, with a
fake ntfy, a fake OIDC provider and a software WebAuthn authenticator, through enrollment, push, passkey
approval, deny, fraud, timeout, revocation and provisioning.
