# Architecture

ntfy-idp-push implements the Duo **Auth API**, allowing identity providers (Authelia `duo_api`, authentik's Duo stage) to deliver mobile push via ntfy. ntfy acts only as the transport layer; sign-in approval requires a signature from a device-bound passkey.

```
browser ──1FA──▶ IdP ──signed Duo API──▶ ntfy-idp-push ──publish──▶ ntfy ──▶ phone (ntfy app)
                  ▲                            ▲                                  │
                  │        allow/deny          │  WebAuthn assertion (browser)    │ tap Approve
                  └────────────────────────────┴──────────────────────────────────┘
```

The server also provisions ntfy accounts (`/provision`, `user provision`) without a push device, serving as a self-service ntfy onboarding tool behind an IdP.

## Principles

- IdP config requires only `hostname`, `integration_key`, `secret_key`. The shim holds one ntfy admin token; no per-user IdP secrets.
- Push approval strictly requires a challenge-bound passkey assertion. Reading the push or holding ntfy tokens/server grants no access.
- ntfy username == IdP username.
- Misconfiguration fails closed (startup checks, config validation).
- Non-approvals return `result: deny`, feeding the IdP's lockout and rate limits.
- Only push is supported. `sms`, `phone`, and `passcode` return `deny`.

## Packages

```
cmd/ntfy-idp-push/   CLI: serve, keygen, user, device, enroll-link, audit, healthcheck
internal/config/     YAML + NTFY_IDP_PUSH_* env + <key>-file secrets; validation; enroll-access rules
internal/duoapi/     Duo Auth API: signature verification (v2/v5), replay guard, preauth/auth/enroll
internal/core/       provisioning, enrollment, login (eligibility, challenges), revocation, purge, startup checks
internal/webauthn/   passkey registration/assertion over stored passkeys (wraps go-webauthn); synced-passkey (BE flag) policy
internal/web/        enrollment, approval, provisioning and device pages; identity (OIDC session)
internal/oidc/       OIDC client (code + PKCE), session cookie
internal/ntfy/       ntfy admin, publish and token client
internal/store/      SQLite (modernc.org/sqlite, pure Go), migrations
internal/tlsconfig/  certificate/key from files, reloaded on change
internal/token/      random secrets and the hashes stored in their place
internal/testutil/   integration harness: fake ntfy, fake OIDC provider, software authenticator
```

## Data model

```
users         (id uuid, username UNIQUE, ntfy_grants_json, disabled_at, created_at)
devices       (id uuid, user_id, name, ntfy_topic UNIQUE, verify_token_hash, verified_at, created_at,
               last_used_at, revoked_at, result_token_hash UNIQUE)
passkeys      (cred_id, device_id, credential_json, aaguid, sign_count, created_at)
challenges    (id, username, device_id, nonce, ipaddr, target_url, display_username,
               state pending|allow|deny|fraud|timeout, deny_token_hash, created_at, expires_at, decided_at)
enroll_codes  (code_hash, username, device_id, expires_at, used_at)
oidc_sessions (id, username, expires_at)
audit         (ts, username, event, detail_json)
```

Users can have multiple devices. Each device uses one passkey and one ntfy topic (`<ntfy-topic-prefix><uuid>`). The IdP's `device` maps to `devices.id`; `user_id` maps to `users.id`.

## Duo API facade

Request validation order:

1. `Host` (lower-cased) must match `duo-hostname`. Proxies must not rewrite this as clients sign it.
2. `Date` (or `X-Duo-Date`) must fall within `duo-max-skew` (default 300 s).
3. `Authorization: Basic ikey:sig` validated with constant-time `ikey` comparison.
4. HMAC verified against the current key (and previous key during `duo-key-grace`):

   | Client | Body | Canonical string |
   |---|---|---|
   | duo_api_golang `SignedCall` (Authelia) | form | v2: `date\nMETHOD\nhost\npath\nparams` |
   | duo_api_golang `JSONSignedCall`, duo_client_python ≥ 5 (authentik) | JSON, or query for GET/DELETE | v5: v2 + `\nsha512(body)\nsha512(x-duo-* headers)` |
   | duo_client_python `sig_version=2` | form | v2, SHA-1 or SHA-512 |

   JSON bodies are verified as v5, forms as v2, and bodyless requests as both. SHA-1 is accepted for v2 only.
5. Replay guard: Each `(date, signature)` pair is accepted only once per skew window.

| Route | Behaviour |
|---|---|
| `GET /auth/v2/ping` | unsigned; `{"time":…}` |
| `GET /auth/v2/check` | signed; `{"time":…}` |
| `POST /auth/v2/preauth` | unknown user or no verified device → `enroll` with `enroll_portal_url` (or `deny` if unset); otherwise `auth` with one `phone` device per enrolled phone, capability `push` |
| `POST /auth/v2/auth` | user by `username` or `user_id`; `factor` must be `push` or `auto`; `device=auto` picks the most recently used device; publishes the push and blocks until decided or `push-timeout` |
| `POST /auth/v2/enroll` | IdP-driven enrollment: returns `user_id`, `activation_code`, `activation_url`, `activation_barcode` (`/enroll/qr`), `expiration` |
| `POST /auth/v2/enroll_status` | `waiting` → `success` once the device is verified; `invalid` for an unknown, expired or revoked enrollment |

`/auth/v2/auth` blocks up to `push-timeout`, extending its write deadline. Reloading `push-timeout` applies to subsequent requests.

Disabling a user or enabling the `push-disabled: true` kill switch causes preauth/auth to return `deny`. This affects in-flight logins: pending challenges are denied, and eligibility is re-verified upon approval and immediately before `auth` returns `allow`.

## Login

1. `auth` creates a challenge (32-byte nonce, `expires_at = now + push-timeout`) and a deny token (stored hashed), publishing to the device's topic:

   ```json
   {
     "topic": "push-<uuid>", "sequence_id": "<challenge>", "title": "Sign-in request",
     "message": "<user> from <ip> to <target host>", "priority": 4, "tags": ["lock"],
     "click": "https://<shim>/challenge/<id>",
     "actions": [
       {"action": "view", "label": "Approve", "url": "https://<shim>/challenge/<id>", "clear": true},
       {"action": "http", "label": "Deny", "url": "https://<shim>/challenge/<id>/deny",
        "method": "POST", "body": "<deny token>", "clear": true}
     ]
   }
   ```
2. `/challenge/<id>` displays the request. It calls `navigator.credentials.get()` using the nonce as the challenge, the device's passkeys as `allowCredentials`, and requires user verification.
3. `POST /challenge/<id>/assert` verifies origin, RP ID, nonce, UP+UV, device credential ownership, and the BE flag (unless `webauthn-allow-synced`). State becomes `allow`.
4. `POST /challenge/<id>/deny` with the deny token yields `deny`; "This wasn't me" yields `fraud`.
5. The blocked `auth` wakes and responds to the IdP. The push is then deleted from the device (ntfy `DELETE /<topic>/<sequence_id>`).

Challenges are single-use; decisions or expiries return 410 for `/challenge/<id>`. State-changing browser POSTs require an `Origin` matching the shim. The ntfy app's `http` action omits `Origin`, so `/challenge/<id>/deny` relies on the deny token for authorization. Pages enforce `Referrer-Policy: same-origin`, not `no-referrer`: with `no-referrer`, browsers send `Origin: null` on form posts and the Activate and Revoke forms would be refused. HTML pages use `Cache-Control: no-store` to protect ntfy sign-in codes and passwords.

## Enrollment

Entry points: `enroll-portal-url` (via preauth) to `/enroll` behind the IdP; or `enroll-link <user>`, generating a single-use `/enroll?code=…` (valid 5 minutes) to bootstrap users lacking a second factor.

1. **Passkey**: `navigator.credentials.create()` requires a platform authenticator, user verification, and direct attestation. Synced passkeys (BE flag) are rejected unless `webauthn-allow-synced`.
2. **ntfy account**: Provisioned as described below.
3. **Topic grant**: `PUT /v1/users/access` grants read-only access to the device's topic.
4. **Link**: Generates an ntfy enrollment code (ntfy#597, `POST /v1/users/token/enroll`) formatted as `ntfy://<host>/<topic>?user=<u>&code=<c>` (tap link and QR). The UI also offers "Set an ntfy password" and "Resend setup push".
5. **Test push**: Sends a "Finish setup" action to `/enroll/verify/<device>` to activate the device. Unverified devices are hidden from preauth and purged after 24 hours.

Execution order: verify attestation (read-only), claim the code and insert the unverified device/passkey in one transaction, then execute remote steps. Failed remote steps rollback the device and release the code for retry. Crashes leave unverified devices for the 24-hour purge.

### Provisioning

`Provision(username)` handles `user provision`, `/provision`, and enrollment: it creates the ntfy user (random password, role `user`), applies `enroll-access`, and records grants. It is idempotent, creates no push-related data, and lets preauth return `enroll`.

`/provision` mints an ntfy enrollment code and renders based on User-Agent: phones get app install links and one deep link per `default-topics` entry; desktops get a QR and web-app links to `<ntfy-base-url>/account/token/redeem#code=…&subscribe=…`. Reloading supersedes the previous code.

Identity for `/enroll`, `/provision`, `/devices`: The shim authenticates users via the IdP's OIDC provider (code + PKCE, `preferred_username`) and issues a 12-hour session cookie. Proxy headers are ignored. Duo API routes, `/challenge/*`, and token-authenticated enrollment routes require no identity. 
IdPs must require a second factor for the shim's OIDC client to prevent attackers from enrolling devices with just a stolen password. Users lacking a second factor enroll via: an existing IdP second-factor (e.g., TOTP), an admin `enroll-link`, or authentik's IdP-driven enrollment (bypassing the portal session).

### IdP-driven enrollment

authentik calls `enroll`, displays `activation_barcode` (`/enroll/qr?value=<activation url>`, generated only for shim-issued codes), and polls `enroll_status`. Phones scan the code and enroll via `/enroll?code=…` without an IdP session; the code serves as proof. Used codes persist for the unverified device's lifetime to accommodate IdP polling.

## Revocation

| Action | CLI | Effect |
|---|---|---|
| Revoke a phone | `device revoke <id>`, or `/devices` | locally first: `revoked_at`, passkeys deleted, pending challenges denied; then the topic grant is removed and the row deleted |
| …and cut its ntfy token | `device revoke <id> --reset-ntfy-user` | ntfy cannot revoke another user's tokens, so the user is deleted and recreated with its grants; every phone must reopen its ntfy link. Refused if the ntfy user has grants the shim did not make, unless `--force` |
| Reset the ntfy user | `user reset-ntfy <u> [--force]` | the same reset with no device revoked |
| Disable / enable | `user disable|enable <u>` | preauth/auth deny; nothing deleted |
| Delete | `user delete <u> [--keep-ntfy-user]` | all devices revoked, ntfy user deleted unless kept |
| Kill switch | `push-disabled: true` + `SIGHUP` | every preauth/auth denies |
| Rotate the IdP secret | `keygen --rotate` | new key written; the old one accepted for `duo-key-grace` |

Revocation is resumable. Failed remote steps retain `revoked_at`, allowing manual retries or the 10-minute purge job to complete them. ntfy user resets are recorded prior to execution and cleared upon completion, ensuring the purge job finishes them even if the device row is deleted. Missing ntfy users/grants count as removed, allowing interrupted resets to resume at recreation.

Revoked phones cannot approve requests, but their user-wide ntfy tokens retain `enroll-access` grants and can read push topics of the user's other devices (allowing them to deny logins). Only `--reset-ntfy-user` revokes this token. 

All actions are audited (`audit`).

## Configuration

See [`deploy/server.yml`](deploy/server.yml). Configuration mirrors ntfy's `server.yml`. Set keys via `NTFY_IDP_PUSH_<KEY>`. Secrets (`duo-secret-key`, `duo-secret-key-previous`, `ntfy-admin-token`, `oidc-client-secret`) support `<key>-file` or `NTFY_IDP_PUSH_<KEY>_FILE`. `SIGHUP` reloads request-scoped config (keys, kill switch, `enroll-access`, `push-timeout`, secret files). Listeners, TLS files, database, and WebAuthn settings require a restart.

`enroll-access` rules use `<topic-pattern>:<access>` matching ntfy's syntax, `*` wildcards, and `${user}` expansion. Validation rejects patterns matching the push topic prefix, `everyone`/`*`, duplicate pattern rules, and `default-topics` unreadable under ntfy's applied rules.

Startup checks (fail closed): Valid ntfy admin token; `GET /v1/users` succeeds under the 1 MiB response cap; anonymous push topic reads are refused; the shim can publish to push topics.

## TLS

Serve certificates via `tls-cert-file`/`tls-key-file` (auto-reloaded on change), or use plain HTTP behind a `Host`-preserving TLS proxy (`listen-http`). Since Duo clients pin Duo's CA bundle, the IdP must trust the shim's certificate chain or disable pinning.

## ntfy prerequisites

```yaml
auth-default-access: deny-all
auth-users: ["idp-push:<bcrypt>:admin"]
auth-tokens: ["idp-push:tk_…:ntfy-idp-push"]
```

Optional upstream ntfy features utilized (degrades gracefully without):

- ntfy#597: `POST /v1/users/token/enroll`, `POST /v1/account/token/redeem`, and `/account/token/redeem`. Without these, phones sign in using a password set from the result page.
- ntfy-android / ntfy-ios deep link handling for `user=` and `code=`: redeems if signed out, subscribes if signed in as that user, and refuses if signed in as someone else.

## Testing

Integration tests execute `duo_api_golang` (v2 form and v5 JSON signing) against the server using a fake ntfy (v2.30 error contract), fake OIDC provider, and software WebAuthn authenticator. They cover enrollment, push, passkey approval, deny, fraud, timeout, revocation recovery, provisioning, OIDC sign-in, and config loading. Forms simulate browser submissions, matching referrer policy Origins.
Live tests for `internal/ntfy` require a real ntfy server via `NTFY_IDP_PUSH_TEST_NTFY_URL`/`_TOKEN`.

## Other IdPs

| IdP | Integration | Status |
|---|---|---|
| Authelia | `duo_api` (duo_api_golang, v2 form signing) | supported; portal enrollment |
| authentik | Duo stage (duo_client 5, v5 JSON signing) | supported; IdP-driven enrollment, `auth(factor=auto, device=auto, user_id)`; Admin API import is not |
| Keycloak | community plugins use Duo's Universal Prompt (Web SDK v4) | not supported; would need an OIDC-style facade |
| Zitadel, Kanidm | no Duo integration | not supported |
