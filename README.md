# ntfy-idp-push

ntfy-idp-push replaces the Duo Auth API to deliver secure mobile push notifications over [ntfy](https://ntfy.sh) for Authelia and authentik. ntfy acts only as transport; approvals require a device-bound passkey signature from the enrolled phone. See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

Accounts follow your user directory (LDAP, or Authelia's `users_database.yml`). The shim polls the directory, creates an ntfy account for each new person, emails them a welcome with their ntfy password, and deletes accounts the directory drops. Users enroll their phone's passkey at `/enroll`.

## Run

The shim runs behind the reverse proxy that already fronts your IdP. The proxy terminates TLS for `duo-hostname`, forwards requests over plain HTTP, and signs users into the self-service pages with the IdP's forward-auth (Authelia `access_control`, authentik proxy provider). Deploy with Docker Compose using [`deploy/compose.yaml`](deploy/compose.yaml):

```sh
ntfy-idp-push keygen                 # integration + secret key for the IdP
mkdir -p deploy/config deploy/secrets
cp deploy/server.yml deploy/config/server.yml     # fill in; leave the secrets out
printf '%s' '<secret key>' > deploy/secrets/duo_secret_key
printf '%s' 'tk_…' > deploy/secrets/ntfy_admin_token
printf '%s' '<ldap bind password>' > deploy/secrets/ldap_password
printf '%s' '<smtp password>' > deploy/secrets/smtp_password
docker compose -f deploy/compose.yaml up -d
```

```yaml
services:
  ntfy-idp-push:
    image: ghcr.io/babraham123/ntfy-idp-push:latest
    restart: unless-stopped
    networks: [proxy]                      # the proxy's network; never publish port 8080 on the host
    volumes:
      - ./config:/etc/ntfy-idp-push:ro     # a directory, so replaced files are seen
      - state:/var/lib/ntfy-idp-push
    environment:                           # where the app reads each mounted secret
      NTFY_IDP_PUSH_DUO_SECRET_KEY_FILE: /run/secrets/duo_secret_key
      NTFY_IDP_PUSH_NTFY_ADMIN_TOKEN_FILE: /run/secrets/ntfy_admin_token
      NTFY_IDP_PUSH_DIRECTORY_LDAP_PASSWORD_FILE: /run/secrets/ldap_password
      NTFY_IDP_PUSH_SMTP_PASSWORD_FILE: /run/secrets/smtp_password
    secrets: [duo_secret_key, ntfy_admin_token, ldap_password, smtp_password]   # mounted at /run/secrets/<name>
secrets:                                   # where Compose reads each secret on the host
  duo_secret_key: {file: ./secrets/duo_secret_key}
  ntfy_admin_token: {file: ./secrets/ntfy_admin_token}
  ldap_password: {file: ./secrets/ldap_password}
  smtp_password: {file: ./secrets/smtp_password}
networks:
  proxy: {external: true}
volumes:
  state:
```

Build the local image with `make image`. Execute CLI commands inside the container using `docker compose -f deploy/compose.yaml exec ntfy-idp-push ntfy-idp-push <command>`.

**Configuration:** Set keys from [`deploy/server.yml`](deploy/server.yml) via environment variables as `NTFY_IDP_PUSH_<KEY>`. Load secrets (`duo-secret-key`, `duo-secret-key-previous`, `ntfy-admin-token`, `directory-ldap-password`, `smtp-password`) from files using `<key>-file` or `NTFY_IDP_PUSH_<KEY>_FILE` (ideal for Docker secrets or systemd credentials). Reload per-request settings (`push-disabled`, keys, secret files including a rotated `ntfy-admin-token`, `enroll-access`, `push-timeout`, `trusted-proxies`, `identity-header`) with `SIGHUP` (`docker compose kill -s HUP`). A reload that changes `listen-http`, `database`, `public-url`, `webauthn-*`, `ntfy-topic-prefix`, or any `directory-*`, `smtp-*` or `mail-*` key (their secret files included) is refused and logged; restart instead.

## Directory and email

The directory decides who gets an ntfy account. Once at startup and then every `directory-sync-interval` (default `15m`), the shim lists it and:

- creates an account for each new person, applies `enroll-access`, and sends one welcome email: ntfy server URL, username, a random password shown only there, app links, the "Manage users" steps that sign the app in, and an `ntfy://` link per `default-topics` entry;
- keeps email and display name current;
- deletes users absent from the directory or marked disabled, with their devices and ntfy account; a person who returns starts over with a new account and welcome;
- never changes a `user disable` made by an admin.

A directory that errors or lists nobody skips the round and changes nothing (audit `sync_skipped`), since deletes cannot be undone. The next round retries unsent welcome emails. Resetting a user's ntfy account (`user reset-ntfy`, `device revoke --reset-ntfy-user`) sends a new welcome, since the recreated account's password is unknown.

`directory-type: ldap` takes Authelia's LDAP settings: `directory-ldap-address` (`ldaps://` or `ldap://` with `directory-ldap-start-tls`), `directory-ldap-base-dn`, the bind `directory-ldap-user` and `directory-ldap-password` (or `-file`), `directory-ldap-users-filter` (default `(objectClass=person)`; it lists users, so no `{input}` placeholder), and the `directory-ldap-attribute-*` names (defaults `uid`, `mail`, `displayName`, `memberOf`). `directory-ldap-group-dn` limits the sync to one group's members, filtered by the server. An LDAP server with a certificate from a private CA needs `directory-ldap-ca-file`, a PEM bundle trusted besides the system roots; put it in `./config` and set `directory-ldap-ca-file: /etc/ntfy-idp-push/ldap-ca.pem`.

`directory-type: file` reads Authelia's file user database (`directory-file`, re-read every round), honoring each user's `disabled` flag; `directory-group` limits the sync to one group. Mount the directory that holds the file read-only (see `deploy/compose.yaml`).

Mail goes through `smtp-host`:`smtp-port` (default 587) with `smtp-user` and `smtp-password` (or `-file`). `smtp-starttls` (default true) refuses a relay that does not upgrade the connection; port 465 is implicit TLS. `mail-from` is required; `mail-reply-to` is optional, for instance the admins who can resend a welcome. The relay is not contacted at startup, so check delivery with `user welcome <user>`.

ntfy prerequisites (`server.yml`):

```yaml
auth-default-access: deny-all
auth-users: ["idp-push:<bcrypt>:admin"]
auth-tokens: ["idp-push:tk_…:ntfy-idp-push"]
```

## Reverse proxy and sign-in

> **Warning: the identity header is the whole login.** The shim takes the signed-in username from `identity-header` (default `Remote-User`) on any request that arrives from `trusted-proxies`. It has no other way to tell who is asking. Any gap lets anyone sign in as anyone, so:
>
> - The proxy must **overwrite or strip** a client-sent `Remote-User` on **every** route, bypassed ones included. Forward-auth middlewares that copy the IdP's response headers onto the upstream request do this for protected routes; check what your proxy does on bypassed ones.
> - Port 8080 must be reachable **only through the proxy**: no host port, no other containers on that network.
> - `trusted-proxies` must be **the proxy's address alone** (a `/32` or `/128`), never the network it sits on.

Supported proxies, each with the directive that sets the header:

| Proxy | Directive |
|---|---|
| Traefik | `forwardAuth` middleware with `authResponseHeaders: [Remote-User]`; Traefik replaces the client's header with the IdP's |
| Caddy | `forward_auth` with `copy_headers Remote-User` |
| nginx | `auth_request` plus `auth_request_set $user $upstream_http_remote_user;` and `proxy_set_header Remote-User $user;` |
| HAProxy | Authelia's documented Lua integration (`auth-request.lua`), which sets `Remote-User` from the IdP's response |

Authelia's [proxy integration docs](https://www.authelia.com/integration/proxies/introduction/) have complete examples for each. authentik's proxy provider sends `X-authentik-username`; oauth2-proxy sends `X-Auth-Request-User`. Set `identity-header` to match.

The proxy holds the TLS certificate for `duo-hostname`; any publicly trusted issuer (Let's Encrypt included) works. One prerequisite: the IdP's Duo client must not pin Duo's CA bundle, or its calls fail with an x509 error. Authelia's does until it carries the change that skips pinning for non-Duo hostnames.

Authelia:

```yaml
duo_api:
  hostname: push.example.com
  integration_key: DI…
  secret_key: …
  enable_self_enrollment: true

# Rules match in order: the bypass rule must come first. Each bypassed route checks its own code,
# token, passkey or signature; the two_factor rule protects the pages that trust Remote-User.
access_control:
  rules:
    - domain: push.example.com
      resources: ['^/token/', '^/challenge/', '^/auth/v2/', '^/static/']
      policy: bypass
    - domain: push.example.com
      policy: two_factor                    # a stolen password alone must not enroll a phone
```

**First enrollment:** Users must register another second factor in Authelia (TOTP or browser passkey) to pass the `two_factor` policy before enrolling their phone at `/enroll`. Admins can bypass this with a single-use link via `enroll-link <user>`. authentik uses its own Duo stage (`/auth/v2/enroll`).

Startup fails closed if the ntfy token lacks admin rights, anonymous reads of push topics are allowed, or the ntfy user list exceeds the client's 1 MiB response limit.

## Backup

The database stores all passkeys. Losing it requires re-enrolling all phones. The `backup` command streams a consistent copy safely while the server runs (`-` outputs to stdout):

```sh
docker compose -f deploy/compose.yaml exec -T ntfy-idp-push ntfy-idp-push backup - > backup.sqlite
```

To restore: stop the server, replace `db.sqlite` with the backup, and delete any `db.sqlite-wal` and `db.sqlite-shm` files.

## CLI

```
ntfy-idp-push [-c config.yml] <command>

Server
  serve                                      run the server
  healthcheck [url]                          exit 0 if /healthz answers (default http://127.0.0.1:8080/healthz)
  backup <path>|-                            consistent database copy, safe while serving
  keygen [--rotate]                          new integration/secret keys, or rotate the secret in the config
  version

Users
  user list                                  users with email, devices, status, last welcome and last sync
  user provision <user>                      create a directory user's account now; welcome if never sent
  user welcome <user>                        set a new ntfy password and email it in a new welcome
  user disable|enable <user>                 block or allow sign-in; the directory sync never changes it
  user delete <user> [--keep-ntfy-user]      the sync recreates a user the directory still lists
  user reset-ntfy <user> [--force]           recreate the ntfy user, invalidating its tokens; sends a new welcome
  user approve <challenge-id>                approve a pending login without a passkey (break-glass)
  enroll-link <user>                         single-use enrollment link, valid 5 minutes
  audit [user]                               last 100 audit entries
                                             (write "--" before a username that starts with "-")

Devices
  device list <user>
  device revoke <device-id> [--reset-ntfy-user] [--force]
```

## Routes

**Access Levels:**
*   **IdP:** Behind the proxy's forward-auth; the shim reads the user from `identity-header` and answers 401 without it.
*   **Public:** Bypassed at the proxy and reachable by user devices. Each route independently validates its code, token, or passkey and never reads the identity header.
*   **Internal:** Called only by the IdP server or container healthcheck.

| Path | Access | Purpose |
|---|---|---|
| `/enroll`<br>`/enroll/begin`<br>`/enroll/finish` | IdP | register a passkey, get the ntfy link |
| `/devices`<br>`/devices/<id>/revoke` | IdP | device list and revoke |
| `/token/#<code>`<br>`/token/begin`<br>`/token/finish` | Public (enrollment code, from the fragment, in the `begin` body) | enroll from an `enroll-link` or authentik activation link |
| `/token/resend` | Public (result-page token) | resend the setup push |
| `/token/verify/<device>#t=<token>` | Public (token from the setup push's fragment, in the form body) | activate the device |
| `/token/qr` | Public (shim-issued codes only) | QR for an enrollment URL, shown by the IdP |
| `/challenge/<id>`<br>`/challenge/<id>/options`<br>`/challenge/<id>/assert`<br>`/challenge/<id>/fraud` | Public (passkey) | approve a sign-in, or report fraud |
| `/challenge/<id>/deny` | Public (deny token) | the ntfy app's Deny action |
| `/static/` | Public | page assets |
| `/auth/v2/ping`<br>`/auth/v2/check`<br>`/auth/v2/preauth`<br>`/auth/v2/auth`<br>`/auth/v2/enroll`<br>`/auth/v2/enroll_status` | Internal (IdP server; HMAC-signed except `ping`) | Duo Auth API |
| `/healthz` | Internal | health check |

## Releases

Pushing a `vX.Y.Z` tag triggers CI to publish Linux/macOS binaries (amd64, arm64) with checksums to GitHub Releases. It also pushes Docker images to `ghcr.io/babraham123/ntfy-idp-push` (tags `:X.Y.Z`, `:X.Y`, `:latest`) with an SBOM and build provenance.

Install from source: `go install github.com/babraham123/ntfy-idp-push/cmd/ntfy-idp-push@latest`

## Develop

```sh
make test   # go test -race ./...
make lint   # gofmt, go vet, staticcheck, govulncheck; CI runs both on every PR
```

Tests execute the real `duo_api_golang` client (v2 form, v5 JSON signing) against the handler `serve` runs, using a fake ntfy, a fake directory, a recording mail sender and a software WebAuthn authenticator, with the test client standing in for the proxy's forward-auth. They cover directory sync and welcome emails, enrollment, push, passkey approval, deny, fraud, timeout, revocation, provisioning, and proxy identity.
