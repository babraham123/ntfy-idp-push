# Architecture

ntfy-idp-push implements the Duo **Auth API**, allowing identity providers (Authelia `duo_api`, authentik's Duo stage) to deliver mobile push via ntfy. ntfy acts only as the transport layer; sign-in approval requires a signature from a device-bound passkey.

```
browser ──1FA──▶ IdP ──signed Duo API──▶ proxy ──▶ ntfy-idp-push ──publish──▶ ntfy ──▶ phone (ntfy app)
                  ▲                                     ▲                                  │
                  │        allow/deny                   │  WebAuthn assertion (browser)    │ tap Approve
                  └─────────────────────────────────────┴──────────────────────────────────┘
```

The shim sits behind the reverse proxy that fronts the IdP: the proxy terminates TLS for `duo-hostname`, forwards plain HTTP, and signs users into the self-service pages with the IdP's forward-auth.

A user directory (LDAP, or Authelia's file user database) controls who has an ntfy account. The shim polls the directory, creates and deletes accounts to match, and emails each new user their ntfy credentials (see Provisioning).

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
internal/app/        assembles store, directory source, mail sender, core, handlers, server timeouts, purge, sync and reload loops; serve and the harness both build from it
internal/config/     YAML + NTFY_IDP_PUSH_* env + <key>-file secrets; validation; enroll-access rules; which keys need a restart
internal/duoapi/     Duo Auth API: signature verification (v2/v5), replay guard; renames core's results into Duo's vocabulary
internal/core/       the running configuration; directory sync and welcome emails, provisioning, enrollment, login (eligibility, challenges), revocation, purge, startup checks; the failure vocabulary adapters map
internal/directory/  the user directory: LDAP (paged search, group filter) or Authelia's users_database.yml
internal/mail/       the welcome email (text + HTML templates) and SMTP delivery (STARTTLS or implicit TLS)
internal/model/      the records core reasons about and store persists (user, device, passkey, challenge, enrollment code)
internal/routes/     the public URL scheme: path prefixes and the links core pushes, built and parsed in one place
internal/webauthn/   passkey registration/assertion over stored passkeys (wraps go-webauthn); synced-passkey (BE flag) policy
internal/web/        enrollment, approval and device pages; identity from the proxy's header
internal/ntfy/       ntfy admin and publish client
internal/store/      SQLite (modernc.org/sqlite, pure Go), migrations
internal/token/      random secrets and the hashes stored in their place
internal/testutil/   integration harness over app: fake ntfy, fake directory, recording mail sender, software authenticator, test client as the proxy
```

## Data model

```
users         (id uuid, username UNIQUE, ntfy_grants_json, disabled_at, created_at, ntfy_reset_pending,
               email, display_name, synced_at, welcomed_at)
devices       (id uuid, user_id, name, ntfy_topic UNIQUE, verify_token_hash, verified_at, created_at,
               last_used_at, revoked_at, result_token_hash UNIQUE)
passkeys      (cred_id, device_id, credential_json, aaguid, sign_count, created_at)
challenges    (id, username, device_id, nonce, ipaddr, target_url, display_username,
               state pending|allow|deny|fraud|timeout, deny_token_hash, created_at, expires_at, decided_at)
enroll_codes  (code_hash, username, device_id, expires_at, used_at)
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
| `POST /auth/v2/enroll` | IdP-driven enrollment: returns `user_id`, `activation_code`, `activation_url`, `activation_barcode` (`/token/qr`), `expiration` |
| `POST /auth/v2/enroll_status` | `waiting` → `success` once the device is verified; `invalid` for an unknown, expired or revoked enrollment |

`/auth/v2/auth` blocks up to `push-timeout`, extending its write deadline. Reloading `push-timeout` applies to subsequent requests.

An `auth` for a device that already has a pending push joins that push instead of sending another: every login waiting on it gets its decision. Beyond that, each user gets a burst of 3 pushes refilled one per 30 s; further `auth` calls answer `deny` (`status_msg: Too many sign-in requests`) without touching the phone, so a stolen password cannot be turned into push bombing.

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
3. `POST /challenge/<id>/assert` verifies origin, RP ID, nonce, UP+UV, device credential ownership, and the BE flag (unless `webauthn-allow-synced`); a refused assertion is 403. State becomes `allow`.
4. `POST /challenge/<id>/deny` with the deny token yields `deny`; "This wasn't me" yields `fraud`.
5. The blocked `auth` wakes and responds to the IdP. The push is then deleted from the device (ntfy `DELETE /<topic>/<sequence_id>`).

Challenges are single-use; decisions or expiries return 410 for `/challenge/<id>`. State-changing browser POSTs require an `Origin` matching the shim and are bounded to 64 KiB. The ntfy app's `http` action omits `Origin`, so `/challenge/<id>/deny` relies on the deny token for authorization. Pages enforce `Referrer-Policy: same-origin`, not `no-referrer`: with `no-referrer`, browsers send `Origin: null` on form posts and the Activate and Revoke forms would be refused. Asset tags carry `referrerpolicy="no-referrer"` and the layout declares a `data:` icon, so a token URL never reaches the proxy's log as a Referer. HTML pages use `Cache-Control: no-store`, as they carry per-user content and token-bearing links, and a CSP that allows only same-origin scripts, forms and bases. Every response carries `X-Frame-Options: DENY` and `X-Robots-Tag: noindex` so a leaked approve or enrollment link is never indexed. `/static/` serves only the embedded files by name (no listing), with an ETag and a one-hour cache.

Unauthenticated routes (`/token/`, `/challenge/`) are rate limited per client address (IPv6 per /64), 20 burst and 1/s sustained, with the table of clients capped. Duo API rejections answer with Duo's error code only, the reason going to a sampled log line.

## Provisioning

The directory decides who has an account: `directory-type: ldap` (a paged search under `directory-ldap-base-dn` with `directory-ldap-users-filter`, narrowed to `directory-ldap-group-dn` when set) or `directory-type: file` (Authelia's `users_database.yml`, optionally one `directory-group`). `Sync` runs at startup and every `directory-sync-interval`. A round creates an account for each new person, records email and display name, deletes users the directory no longer lists or marks disabled (as `user delete` does), and sends owed welcome emails last, so mail trouble never delays a deletion. A directory error or an empty listing skips the round (`sync_skipped`), since deletes cannot be undone. A failure for one user is logged and does not stop the round. `user disable` belongs to the admin; the sync never touches it.

`Provision(username)` creates the ntfy user (random password, role `user`), applies `enroll-access`, and records grants. It is idempotent and lets preauth return `enroll`. Enrollment calls it for the signed-in user; `user provision <u>` accepts only a person the directory lists.

### Welcome email

`Welcome(username)` sets a new random ntfy password and emails it with the server URL, app links, the "Manage users" steps and one `ntfy://` link per `default-topics` entry. The password exists only in that email; signed-in apps keep their tokens. The welcome counts as owed (`welcomed_at` empty) from the moment the password changes until the mail server accepts the message, so a failure or crash anywhere between is retried by the next round, and welcomes for one user run one at a time. Every path that leaves a user without a known password ends in a welcome: a new account and every ntfy user reset. `user welcome <u>` resends it.

## Enrollment

Entry points: `enroll-portal-url` (via preauth) to `/enroll` behind the proxy's forward-auth; or `enroll-link <user>`, generating a single-use `/token/<code>` link (valid 5 minutes) to bootstrap users lacking a second factor. Both render the same page; it posts to `/enroll/begin` and `/enroll/finish` (identity routes) or `/token/begin` and `/token/finish` (code routes). A ceremony begun on one family cannot be finished on the other.

1. **Passkey**: `navigator.credentials.create()` requires a platform authenticator, user verification, and direct attestation. Synced passkeys (BE flag) are rejected unless `webauthn-allow-synced`; a passkey with no attestation statement (`fmt: none`) is rejected unless `webauthn-require-attestation: false`.
2. **ntfy account**: Provisioned as described in Provisioning.
3. **Topic grant**: `PUT /v1/users/access` grants read-only access to the device's topic.
4. **Link**: The result page hands out the device topic as `ntfy://<host>/<topic>?user=<u>` (plus `secure=false` for a plain-HTTP ntfy), laid out by User-Agent. Android gets the tap link, with the server URL and topic to add by hand if the app does not subscribe. iOS gets the server URL and topic with copy buttons and the manual steps (+, "Use another server", Subscribe), because the ntfy iOS app does not open `ntfy://` links. Desktops get a QR of the link plus both. The link carries no credentials: the phone's ntfy app must already be signed in with the credentials from the welcome email. The page also offers "Resend setup push".
5. **Test push**: Sends a "Finish setup" action to `/token/verify/<device>` to activate the device. Unverified devices are hidden from preauth and purged after 24 hours.

Execution order: verify attestation (read-only), claim the code and insert the unverified device/passkey in one transaction, then execute remote steps. Failed remote steps rollback the device and release the code for retry. Crashes leave unverified devices for the 24-hour purge.

### Identity

Identity for `/enroll` and `/devices`: the proxy's forward-auth step signs the user in and sets `identity-header` (default `Remote-User`); the shim believes it only when the request arrives from `trusted-proxies`, and answers 401 otherwise. There is no session, cookie or login page in the shim. The header is the whole login, so the proxy must overwrite or strip a client-sent copy on every route and the shim must be reachable only through it. `/token/*`, `/challenge/*` and the Duo API routes never read the header; their code, token, passkey or signature is the whole credential, which is what lets the proxy bypass them.
IdPs must require a second factor on the identity routes to prevent attackers from enrolling devices with just a stolen password. Users lacking a second factor enroll via: an existing IdP second-factor (e.g., TOTP), an admin `enroll-link`, or authentik's IdP-driven enrollment (bypassing the portal session).

### IdP-driven enrollment

authentik calls `enroll`, displays `activation_barcode` (`/token/qr?value=<activation url>`, generated only for shim-issued codes), and polls `enroll_status`. Phones scan the code and enroll via `/token/<code>` without an IdP session; the code serves as proof. Used codes persist for the unverified device's lifetime to accommodate IdP polling.

## Revocation

| Action | CLI | Effect |
|---|---|---|
| Revoke a phone | `device revoke <id>`, or `/devices` | locally first: `revoked_at`, passkeys deleted, pending challenges denied; then the topic grant is removed and the row deleted |
| …and cut its ntfy token | `device revoke <id> --reset-ntfy-user` | ntfy cannot revoke another user's tokens, so the user is deleted, recreated with its grants, and sent a new welcome email. Every phone must sign in with the credentials from the new welcome email. Refused if the ntfy user has grants the shim did not make, unless `--force` |
| Reset the ntfy user | `user reset-ntfy <u> [--force]` | the same reset with no device revoked |
| New ntfy password | `user welcome <u>` | the password is replaced and emailed; tokens of signed-in apps stay valid |
| Disable / enable | `user disable|enable <u>` | preauth/auth deny; nothing deleted. The sync never changes it |
| Delete | `user delete <u> [--keep-ntfy-user]`, or the directory | all devices revoked, ntfy user deleted unless kept. The sync deletes users the directory drops or marks disabled; a user it still lists is recreated and welcomed on the next round |
| Kill switch | `push-disabled: true` + `SIGHUP` | every preauth/auth denies |
| Rotate the IdP secret | `keygen --rotate` | new key written; the old one accepted for `duo-key-grace` |

Revocation is resumable. Failed remote steps retain `revoked_at`, allowing manual retries or the 10-minute purge job to complete them. ntfy user resets are recorded prior to execution and cleared upon completion, ensuring the purge job finishes them even if the device row is deleted. Missing ntfy users/grants count as removed, allowing interrupted resets to resume at recreation.

Revoked phones cannot approve requests, but their user-wide ntfy tokens retain `enroll-access` grants and can read push topics of the user's other devices (allowing them to deny logins). Only `--reset-ntfy-user` revokes this token. 

All actions are audited (`audit`).

## Configuration

See [`deploy/server.yml`](deploy/server.yml). Configuration mirrors ntfy's `server.yml`. Set keys via `NTFY_IDP_PUSH_<KEY>`. Secrets (`duo-secret-key`, `duo-secret-key-previous`, `ntfy-admin-token`, `directory-ldap-password`, `smtp-password`) support `<key>-file` or `NTFY_IDP_PUSH_<KEY>_FILE`. `directory-type`, `smtp-host` and `mail-from` are required; the directory source and the mail sender validate the rest of their keys at startup, without connecting. `SIGHUP` re-reads the configuration and applies it to the next request: keys, kill switch, `enroll-access`, `push-timeout`, `trusted-proxies`, `identity-header`, and the ntfy connection (`ntfy-base-url`, `ntfy-admin-token`, so a rotated token file takes effect without a restart). Keys bound at startup (`listen-http`, `database`, `public-url`, `webauthn-*`, `ntfy-topic-prefix`, and the `directory-*`, `smtp-*` and `mail-*` keys the directory source and mail sender are built from, secrets included) refuse the whole reload: the running configuration stays and the log names the keys.

### Failures

Every exported core operation fails with one of a closed set of errors, each of one kind: *refused* (policy: disabled user, revoked device, kill switch, passkey policy or verification, wrong deny token), *gone* (an expired code, link, handle or challenge), *not found* (unknown user or device), *invalid* (bad input), or *internal* (anything else). web maps the kind to a status once (403, 410, 404, 400, 500) and shows core's reason; duoapi maps it to Duo's `status_msg` once. Internal errors are logged and never echoed to clients.

`enroll-access` rules use `<topic-pattern>:<access>` matching ntfy's syntax, `*` wildcards, and `${user}` expansion. Validation rejects patterns matching the push topic prefix, `everyone`/`*`, duplicate pattern rules, and `default-topics` unreadable under ntfy's applied rules.

Startup checks (fail closed): Valid ntfy admin token; `GET /v1/users` succeeds under the 1 MiB response cap; anonymous push topic reads are refused; the shim can publish to push topics.

## Reverse proxy

The shim serves plain HTTP (`listen-http`) and has no TLS listener: it cannot be used without the proxy anyway, since the proxy is what signs users in. The proxy holds the certificate for `duo-hostname`, from any publicly trusted issuer, and must preserve `Host`, which Duo clients sign. The IdP's Duo client must not pin Duo's CA bundle (Authelia's does until it carries the change that skips pinning for non-Duo hostnames). Routes split into two families so the proxy's access rules can be written by prefix: identity routes (`/enroll`, `/devices`) behind forward-auth, everything else (`/token/`, `/challenge/`, `/auth/v2/`, `/static/`) bypassed.

## ntfy prerequisites

```yaml
auth-default-access: deny-all
auth-users: ["idp-push:<bcrypt>:admin"]
auth-tokens: ["idp-push:tk_…:ntfy-idp-push"]
```

## Testing

Integration tests execute `duo_api_golang` (v2 form and v5 JSON signing) against the handler `app` assembles for `serve`, using a fake ntfy (v2.30 error contract), a fake directory, a mail sender that records what it sends, and a software WebAuthn authenticator; the test client connects from the configured trusted proxy address and sets the identity header as forward-auth would. They cover directory sync (new users provisioned and welcomed once, dropped and disabled people deleted and recreated when they return, an admin's disable kept, deletions not held up by mail, one ntfy user listing per round, a broken or empty directory skipping the round, failed and interrupted welcomes retried, concurrent welcomes), welcome resends and the welcome after a reset, enrollment (including the per-platform result page), push, joining a pending push, the per-user push cap, passkey approval, deny, fraud, timeout, revocation recovery, provisioning, proxy identity (untrusted peers, forged headers on bypassed routes), config reload (token rotation, refused restart-only keys), the CLI, and config loading. Tests read state through core; the harness's store handle only fabricates what another process would have left. Forms simulate browser submissions, matching referrer policy Origins.
Live tests for `internal/ntfy` require a real ntfy server via `NTFY_IDP_PUSH_TEST_NTFY_URL`/`_TOKEN`.

## Other IdPs

| IdP | Integration | Status |
|---|---|---|
| Authelia | `duo_api` (duo_api_golang, v2 form signing) | supported; portal enrollment |
| authentik | Duo stage (duo_client 5, v5 JSON signing) | supported; IdP-driven enrollment, `auth(factor=auto, device=auto, user_id)`; Admin API import is not |
| Keycloak | community plugins use Duo's Universal Prompt (Web SDK v4) | not supported; would need an OIDC-style facade |
| Zitadel, Kanidm | no Duo integration | not supported |
