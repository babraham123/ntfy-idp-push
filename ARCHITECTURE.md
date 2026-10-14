# Architecture

ntfy-idp-push implements the Duo **Auth API**, so an identity provider's existing Duo integration
(Authelia `duo_api`, authentik's Duo stage) delivers mobile push over ntfy. ntfy is transport only:
approving a sign-in needs a signature from a device-bound passkey on the enrolled phone.

```
browser ──1FA──▶ IdP ──signed Duo API──▶ ntfy-idp-push ──publish──▶ ntfy ──▶ phone (ntfy app)
                  ▲                            ▲                                  │
                  │        allow/deny          │  WebAuthn assertion (browser)    │ tap Approve
                  └────────────────────────────┴──────────────────────────────────┘
```

The same server also provisions ntfy accounts (`/provision`, `user provision`) without any push device,
so it doubles as a self-service ntfy onboarding tool behind an IdP.

## Principles

- The IdP config is only `hostname`, `integration_key`, `secret_key`. No per-user secrets in the IdP; the
  shim holds one ntfy admin token.
- Reading the push, holding the ntfy token, or owning the ntfy server approves nothing. Only a passkey
  assertion bound to the challenge does.
- ntfy username == IdP username.
- Misconfiguration fails closed (startup checks, config validation).
- Every failure that is not an approval answers `result: deny`, which feeds the IdP's lockout and rate limits.
- Only push is supported; `sms`, `phone` and `passcode` answer `deny`.

## Packages

```
cmd/ntfy-idp-push/   CLI: serve, keygen, user, device, enroll-link, audit, healthcheck
internal/config/     YAML + NTFY_IDP_PUSH_* env + <key>-file secrets; validation; enroll-access rules
internal/duoapi/     Duo Auth API: signature verification (v2/v5), replay guard, preauth/auth/enroll
internal/core/       provisioning, enrollment, login, revocation, purge, startup checks
internal/challenge/  pending logins: create, wait, decide
internal/webauthn/   registration/assertion (go-webauthn) and the synced-passkey (BE flag) policy
internal/web/        enrollment, approval, provisioning and device pages; identity (forward auth / OIDC)
internal/oidc/       OIDC client (code + PKCE), session cookie
internal/ntfy/       ntfy admin, publish and token client
internal/store/      SQLite (modernc.org/sqlite, pure Go), migrations
internal/tlsconfig/  certificate/key from files, reloaded on change
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

One ntfy topic per device (`<ntfy-topic-prefix><uuid>`), normally one passkey per device, any number of
devices per user. The IdP's saved `device` is `devices.id`; `user_id` is `users.id`.

## Duo API facade

Request handling, in order:

1. `Host` (lower-cased) must equal `duo-hostname`: the client signs it, so a proxy must not rewrite it.
2. `Date` (or `X-Duo-Date`) within `duo-max-skew` (default 300 s).
3. `Authorization: Basic ikey:sig`; ikey compared in constant time.
4. HMAC verified against the current key, and the previous one during `duo-key-grace`:

   | Client | Body | Canonical string |
   |---|---|---|
   | duo_api_golang `SignedCall` (Authelia) | form | v2: `date\nMETHOD\nhost\npath\nparams` |
   | duo_api_golang `JSONSignedCall`, duo_client_python ≥ 5 (authentik) | JSON, or query for GET/DELETE | v5: v2 + `\nsha512(body)\nsha512(x-duo-* headers)` |
   | duo_client_python `sig_version=2` | form | v2, SHA-1 or SHA-512 |

   A JSON body is verified as v5 only, a form body as v2 only; a bodyless request against both. SHA-1 is
   accepted only for v2.
5. Replay guard: a `(date, signature)` pair is accepted once within the skew window.

| Route | Behaviour |
|---|---|
| `GET /auth/v2/ping` | unsigned; `{"time":…}` |
| `GET /auth/v2/check` | signed; `{"time":…}` |
| `POST /auth/v2/preauth` | unknown user or no verified device → `enroll` with `enroll_portal_url` (or `deny` if unset); otherwise `auth` with one `phone` device per enrolled phone, capability `push` |
| `POST /auth/v2/auth` | user by `username` or `user_id`; `factor` must be `push` or `auto`; `device=auto` picks the most recently used device; publishes the push and blocks until decided or `push-timeout` |
| `POST /auth/v2/enroll` | IdP-driven enrollment: returns `user_id`, `activation_code`, `activation_url`, `activation_barcode` (`/enroll/qr`), `expiration` |
| `POST /auth/v2/enroll_status` | `waiting` → `success` once the device is verified; `invalid` for an unknown, expired or revoked enrollment |

`/auth/v2/auth` holds the response open for up to `push-timeout`, so it extends its own write deadline
past the server's default; a reloaded `push-timeout` applies to the next request.

Disabling a user, or the global kill switch `push-disabled: true`, makes preauth and auth answer `deny`.
Both also apply to logins already in flight: pending challenges are denied, and eligibility (user
disabled, device revoked, kill switch) is re-checked at the moment of approval and again before `auth`
answers `allow`.

## Login

1. `auth` creates a challenge (32-byte nonce, `expires_at = now + push-timeout`) and a deny token (stored
   hashed), and publishes to the device's topic:

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
2. `/challenge/<id>` shows the request; `navigator.credentials.get()` with the nonce as challenge, the
   device's passkeys as `allowCredentials`, user verification required.
3. `POST /challenge/<id>/assert` verifies origin, RP ID, nonce, UP+UV, that the credential belongs to the
   challenge's device, and the BE flag unless `webauthn-allow-synced` (go-webauthn filters only at
   registration, so the shim checks it on every assertion). State → `allow`.
4. `POST /challenge/<id>/deny` with the deny token → `deny`; "This wasn't me" → `fraud`.
5. The blocked `auth` wakes and answers the IdP. When a challenge is decided its push is deleted from the
   phone (ntfy `DELETE /<topic>/<sequence_id>`).

Challenges are single-use; any decision or expiry makes `/challenge/<id>` answer 410.

Every state-changing browser POST must carry `Origin` equal to the shim's origin. The ntfy app's `http`
action sends no Origin, so `/challenge/<id>/deny` is exempt and the deny token authorizes it. Pages use
`Referrer-Policy: same-origin`: with `no-referrer`, browsers send `Origin: null` on form posts and the
Activate and Revoke forms would be refused. HTML pages are `Cache-Control: no-store`, since they carry
ntfy sign-in codes and passwords.

## Enrollment

Entry points: `enroll-portal-url` (returned by preauth) → `/enroll` behind the identity provider; or
`enroll-link <user>`, a single-use `/enroll?code=…` valid 5 minutes, for bootstrapping a user with no
second factor yet.

1. **Passkey**: `navigator.credentials.create()` with a platform authenticator, user verification
   required, direct attestation. Synced passkeys (BE flag) are refused unless `webauthn-allow-synced`.
2. **ntfy account**: provisioned as below.
3. **Topic grant**: `PUT /v1/users/access` read-only on the device's topic.
4. **Link**: an ntfy enrollment code (ntfy#597, `POST /v1/users/token/enroll`) in
   `ntfy://<host>/<topic>?user=<u>&code=<c>`, as a tap link and a QR. The result page also offers
   "Set an ntfy password" for apps that ignore `code=`, and "Resend setup push".
5. **Test push** with a "Finish setup" action to `/enroll/verify/<device>`, which activates the device.
   Devices never verified are hidden from preauth and purged after 24 h.

Order: verify the attestation (no writes); claim the code and insert the unverified device and passkey in
one transaction; then the remote steps. If a remote step fails, the device is removed and the code
released, so the same link works again. A crash between steps leaves an unverified device for the purge.

### Provisioning

`Provision(username)` is the one code path for `user provision`, `/provision` and enrollment: ensure the
ntfy user exists (random password, role `user`), apply `enroll-access`, record the grants. It is
idempotent and creates nothing push-related, so preauth still answers `enroll`.

`/provision` mints an ntfy enrollment code and renders by User-Agent: on phones, app install links and one
deep link per `default-topics` entry; on desktops, a QR and web-app links to
`<ntfy-base-url>/account/token/redeem#code=…&subscribe=…` (the fragment never reaches a server log).
Reloading supersedes the previous code.

Identity for `/enroll`, `/provision`, `/devices`: `auth-mode: forward` trusts `Remote-User` from
`trusted-proxies` only; `auth-mode: oidc` signs in with any OIDC provider (code + PKCE,
`preferred_username`). The Duo API routes and `/challenge/*` use neither. Use a `two_factor` policy for the
shim in the IdP: with `one_factor`, a stolen password could enroll an attacker's phone.

### IdP-driven enrollment

authentik calls `enroll`, shows `activation_barcode` (`/enroll/qr?value=<activation url>`, rendered only
for codes the shim issued), and polls `enroll_status`. The phone scans the code and enrolls through
`/enroll?code=…` without an IdP session; the code is the proof. Used codes are kept for the unverified
device lifetime, since the IdP keeps polling after the code's own expiry.

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

Revocation is resumable: if a remote step fails, the row keeps `revoked_at` and re-running the command
(or the purge job, every 10 minutes) retries the remote steps. A user or grant already missing in ntfy
counts as removed, so an interrupted reset resumes at recreation.

After a plain revoke, a lost phone cannot approve anything, but its ntfy token is user-wide: it keeps the
`enroll-access` grants and can read the push topics of the user's other phones, so it can deny their
logins. Only `--reset-ntfy-user` ends that; the `/devices` page offers it as a checkbox.

Everything above is audited (`audit`).

## Configuration

See [`deploy/server.yml`](deploy/server.yml). Keys mirror ntfy's `server.yml` style; every key can be set
as `NTFY_IDP_PUSH_<KEY>`; secrets (`duo-secret-key`, `duo-secret-key-previous`, `ntfy-admin-token`,
`oidc-client-secret`) can be read from a file with `<key>-file` or `NTFY_IDP_PUSH_<KEY>_FILE`. `SIGHUP`
reloads everything read per request (keys, kill switch, `enroll-access`, `push-timeout`, re-reading
secret files); listeners, TLS files, database and WebAuthn settings need a restart.

`enroll-access` rules are `<topic-pattern>:<access>`, with ntfy's access spellings and `*` wildcard;
`${user}` expands to the username. Validation refuses patterns that could match the push topic prefix,
`everyone`/`*`, two rules for the same pattern (ntfy keeps one per pattern), and `default-topics` entries
unreadable under the rule ntfy actually applies (user grants beat `everyone`, then the longest pattern,
then write over read).

Startup checks (fail closed): the ntfy token is valid and admin; `GET /v1/users` works and fits the
client's 1 MiB response cap; anonymous reads of push topics are refused; the shim can publish to them.

## TLS

Serve a certificate with `tls-cert-file`/`tls-key-file` (reloaded when the file changes), or run plain
HTTP behind a TLS proxy that preserves `Host` (`listen-http`). Duo clients pin Duo's CA bundle, so the IdP
must either trust the shim's certificate chain or have pinning disabled.

## ntfy prerequisites

```yaml
auth-default-access: deny-all
auth-users: ["idp-push:<bcrypt>:admin"]
auth-tokens: ["idp-push:tk_…:ntfy-idp-push"]
```

Optional upstream changes the shim uses when present, and degrades without:

- ntfy#597: `POST /v1/users/token/enroll`, `POST /v1/account/token/redeem` and the web route
  `/account/token/redeem`. Without them, phones sign in with a password set from the result page.
- ntfy-android / ntfy-ios handling of `user=` and `code=` in deep links: redeem when signed out, subscribe
  when signed in as that user, refuse when signed in as someone else.

## Testing

Integration tests drive the real `duo_api_golang` client (v2 form and v5 JSON signing) against the
server, with a fake ntfy that follows ntfy v2.30's error contract, a fake OIDC provider, and a software
WebAuthn authenticator: enrollment, push, passkey approval, deny, fraud, timeout, revocation and its
recovery, provisioning, OIDC sign-in, and config loading. Forms are submitted as a browser would,
with the Origin its referrer policy yields. `internal/ntfy`'s live test runs against a real ntfy server
when `NTFY_IDP_PUSH_TEST_NTFY_URL`/`_TOKEN` are set.

## Other IdPs

| IdP | Integration | Status |
|---|---|---|
| Authelia | `duo_api` (duo_api_golang, v2 form signing) | supported; portal enrollment |
| authentik | Duo stage (duo_client 5, v5 JSON signing) | supported; IdP-driven enrollment, `auth(factor=auto, device=auto, user_id)`; Admin API import is not |
| Keycloak | community plugins use Duo's Universal Prompt (Web SDK v4) | not supported; would need an OIDC-style facade |
| Zitadel, Kanidm | no Duo integration | not supported |
