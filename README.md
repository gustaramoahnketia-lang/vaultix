# VAULTIXgusTAR

A secure personal information manager — password manager, encrypted secure
notes, personal details, a universal secure search, and a Security Centre —
with a **real** Node.js backend, a **real** SQLite database, **real**
scrypt-hashed authentication, and **real** AES-256-GCM encrypted vault
storage. Multiple users, each with a completely private, isolated vault.

This is a reference implementation built to run entirely offline with zero
npm installs (see "Why no dependencies" below). It is a serious starting
point for a production system, not a finished commercial product — the
"Honest limitations" section at the bottom says exactly where the line is.

---

## 1. Quick start

Requires **Node.js 22.5+** (uses the built-in `node:sqlite` module).

```bash
cd vaultix
cp .env.example .env        # then edit .env — see section 2
npm start                   # http://localhost:4173
```

That's it — there's nothing to `npm install`. The database file is created
automatically on first run at `./data/vaultix.db`.

Open `http://localhost:4173`, click **Create a vault**, and register an
account. You'll see your **recovery key exactly once** — save it before
continuing.

### Run the tests

```bash
npm test
```

This runs 20 tests with Node's built-in test runner covering registration,
login, wrong-password rejection, password-hash format, CSRF enforcement,
**user isolation (User A cannot read/edit/delete/search up User B's data)**,
vault CRUD, secure search scoping, PIN brute-force lockout, vault
lock/unlock, AES-GCM tamper detection, account recovery, session revocation,
and account deletion. All 20 currently pass against the real server (not
mocked) using a fresh temporary SQLite database per run.

### Development mode

```bash
npm run dev   # restarts on file changes (node --watch)
```

---

## 2. Configuring environment variables

Copy `.env.example` to `.env` and set:

- `PORT` — defaults to 4173.
- `VAULTIX_DATA_DIR` / `VAULTIX_DB_PATH` — where the SQLite file lives. Point
  this at a persistent volume in production.
- `VAULTIX_KEY_PEPPER` — a long random secret appended to every
  password/PIN before hashing and to every key derivation (see section 4).
  **Never commit this. Never store it in the database.** Generate one with:
  ```bash
  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  ```
- `SMTP_*` — placeholders for wiring up real email delivery (see section 9;
  not implemented in this offline build).

The server logs a warning on startup if `VAULTIX_KEY_PEPPER` is unset. It
still runs (for local development), but you should treat an unset pepper as
a blocker for any real deployment.

---

## 3. Why zero dependencies

This was built in a sandboxed environment with **no network access** — no
`npm install`, no `pip install`, nothing. Rather than fake a `package.json`
full of dependencies that were never actually installed or tested, this
project uses **only Node.js 22 built-ins**:

| Need | Used here | Real-world equivalent |
|---|---|---|
| HTTP server + router | `node:http` + a ~90-line router in `server/http-utils.js` | Express/Fastify |
| Database | `node:sqlite` (`DatabaseSync`, built-in, experimental) | Postgres via `pg`, or `better-sqlite3` |
| Password hashing / KDF | `crypto.scrypt` | **Argon2id** via the `argon2` npm package |
| Encryption | `crypto.createCipheriv('aes-256-gcm', ...)` | same — this one's already what the brief asked for |
| Sessions | Random tokens + SHA-256 lookup hash in the `sessions` table | same idea, or signed JWTs |

Every file that stands in for something you'd swap out in a networked
environment says so in a comment at the point where it matters, and this
README calls out the two biggest ones below.

### Swapping in real Argon2id

The brief specifically asks for Argon2id. `crypto.scrypt` (used here) is
also a memory-hard, GPU/ASIC-resistant password KDF — a legitimate
substitute, not a downgrade to something like plain SHA-256 — but it isn't
literally Argon2id. To switch:

1. `npm install argon2`
2. In `server/crypto.js`, replace `hashSecret`/`verifySecret`/`deriveKey`
   with calls to `argon2.hash(secret, { type: argon2.argon2id, ... })` and
   `argon2.verify(...)`. Keep the same function signatures so nothing else
   in the codebase needs to change.
3. Keep the `pepper()` concatenation — it composes with either KDF.

### Swapping SQLite for Postgres

`server/db.js` is the only file that touches SQL syntax and connection
setup. Replace `DatabaseSync` with a `pg.Pool`, translate the `CREATE TABLE`
statements (mostly compatible — `TEXT`/`INTEGER`/`BLOB` map to
`TEXT`/`BIGINT`/`BYTEA`), and update the `.prepare(...).run(...)` /
`.get(...)` / `.all(...)` call sites in `auth.js`, `vault.js`, and `app.js`
to the equivalent async `pool.query(...)` calls.

---

## 4. Encryption architecture

This is the part of the brief marked "extremely important," so here's
exactly how it works, plus the trade-offs.

**Three independent things, never conflated:**

1. **Authentication verifier** — proves you know your master password.
   `password_hash = scrypt(password + pepper, random_salt_A)`, stored as a
   self-describing string (`scrypt$N$r$p$salt$hash`). This is never used as
   an encryption key.
2. **Vault Encryption Key (VEK)** — one random 256-bit key per user,
   generated once at registration (`crypto.randomBytes(32)`), used to
   AES-256-GCM-encrypt every vault item's contents. **This key is never
   stored anywhere in plaintext.**
3. **Key-Encryption Keys (KEKs)** — derived from a low-entropy secret
   (master password, PIN, or device token) plus its own random salt:
   `kek = scrypt(secret + pepper, random_salt_B)`. A KEK's only job is to
   *wrap* (AES-256-GCM encrypt) a copy of the VEK. The wrapped VEK
   (ciphertext + IV + auth tag) is what's actually stored in the `users`
   table — one wrapped copy per unlock method:

   ```
   master password  ->  KEK_password  ->  wraps ->  VEK  (wrapped_vek*)
   PIN               ->  KEK_pin       ->  wraps ->  VEK  (wrapped_vek_pin*)
   device token      ->  KEK_device    ->  wraps ->  VEK  (wrapped_vek_device*)
   recovery key      ->  KEK_recovery  ->  wraps ->  VEK  (wrapped_vek_recovery*)
   ```

   Because all four wrap the *same* VEK, setting up a PIN or enabling
   biometrics doesn't require re-encrypting your entire vault — and
   resetting your master password via recovery doesn't lose access to old
   data (see section 6).

**Where the unwrapped VEK actually lives:** only in the Node process's
memory, in a `Map` keyed by session id (`server/store.js`), for as long as
the vault is unlocked. It is dropped on manual lock, auto-lock timeout,
logout, or session expiry. It is never logged, never sent to the client,
and never written to disk.

**Every encrypted record** (`vault_items.payload_ciphertext`) uses a fresh
random 96-bit IV per write (`crypto.randomBytes(12)`) and AES-256-GCM's
authentication tag, so tampering with stored ciphertext is detected on
decrypt rather than silently producing garbage — see
`tests/security.test.js`, "a tampered ciphertext fails AES-256-GCM
authentication."

---

## 5. Authentication & session security

- Registration requires an 8+ character master password; login uses a
  generic **"Invalid email or password"** message for both a wrong password
  and a nonexistent account, and runs `scrypt` against a decoy hash even
  when the account doesn't exist, to reduce (not eliminate — this is a
  single-process reference server, not a hardened production stack) timing-
  and enumeration-based account discovery.
- Failed logins increment a per-account counter with **exponential
  backoff** lockout (`server/auth.js`, `backoffMs`) on top of a simple
  per-IP sliding-window rate limiter (`server/store.js`) as defense in
  depth.
- Sessions are opaque random tokens; only their SHA-256 hash is stored
  server-side (same principle as password hashing — a stolen database
  backup shouldn't hand over live sessions). Cookies are `HttpOnly`,
  `SameSite=Strict`, and `Secure` (see section 10 for what `Secure` implies
  about needing HTTPS).
- **CSRF:** the login/register response includes a `csrfToken` the frontend
  must echo back in an `x-csrf-token` header on every mutating request;
  the server compares it against a per-session secret. A stolen cookie
  alone (e.g. via a CSRF-style cross-site form post) can't perform actions.
- **Auto-lock:** configurable (Never / 30s / 1m / 5m / 15m, default 5m),
  enforced server-side by timestamping last activity per session and
  refusing to serve the cached VEK once the idle window has passed
  (`server/store.js`, `getVek`) — not just a client-side timer that a
  modified frontend could ignore.

---

## 6. Recovery — and its honest trade-off

**Never implemented:** "forgot password -> email old password." The server
never has your plaintext password to send, and only ever compares its hash.

**What's implemented:**

```
Forgot Master Password
  -> Verify recovery email (generic response either way -- no enumeration)
  -> One-time verification code (10-minute expiry)
  -> Enter Recovery Key (shown once, at registration)
  -> Create new Master Password
  -> Server unwraps the VEK via the recovery-key path, re-wraps it under
     a fresh password-derived KEK -- the VEK itself never changes, so every
     existing record still decrypts normally afterward
```

**The trade-off, stated plainly:** the VEK can only ever be unwrapped by
one of four secrets — master password, PIN, a trusted device token, or the
recovery key. If you lose your master password **and** your recovery key
(and haven't set up a PIN or biometrics on a device you still have), the
encrypted data is cryptographically unrecoverable — by design. A system
that could recover your data from a bare password reset with no
independent key would mean the encryption isn't really protecting the data
from someone who steals the database. This is the same trade-off
established password managers like Bitwarden/1Password describe to their
own users.

**What's mocked because there's no network in this sandbox:** the
verification code is printed to the server console
(`[VAULTIXgusTAR] Recovery code for user ...`) instead of emailed. Wiring
real SMTP delivery is a small, isolated change — see `.env.example`'s
`SMTP_*` placeholders and `server/store.js`'s `issueRecoveryCode`.

---

## 7. User isolation

This is the property the brief calls "one of the most important
requirements," so it's worth being explicit about where it's enforced.

Every function in `server/vault.js` takes `userId` as an explicit parameter
sourced **only** from the authenticated session (`req.user.id`, set by
`authenticate()` in `server/auth.js` from the verified session cookie) —
never from a URL parameter, request body, or query string. Every SQL query
in that file includes `WHERE user_id = ?` bound to that value, and
`fetchOwnedRow` re-checks `row.user_id === userId` even though the SQL
already filtered on it, specifically so a future refactor that forgets the
`WHERE` clause fails closed instead of silently leaking data.

A request for someone else's item returns **404 Not Found**, not 403 —
so an attacker probing IDs can't even learn "that ID exists, you're just
not allowed to see it." This is verified directly in
`tests/isolation.test.js`, whose central assertion is literally: *User A
cannot access, edit, delete, or search up User B's vault items* — the
mandatory test called out in the brief.

---

## 8. Secure search architecture

The brief warns against "decrypt the entire database for every search" and
against "search entire database, filter later." Here's the actual design:

- Each `vault_items` row stores a **non-secret plaintext `title`** (e.g.
  "Google" — a label, not a secret), an optional plaintext `category`, and
  an explicitly-allowed-to-be-searchable `search_username` (per the brief's
  own "search by username/email where securely supported"). Everything
  else — passwords, note bodies, personal details, ID numbers — lives only
  inside the AES-256-GCM-encrypted `payload_ciphertext` column.
- `GET /api/search` (`server/vault.js`, `searchItems`) runs a single SQL
  query: `WHERE user_id = ? AND (title LIKE ? OR search_username LIKE ? OR
  category LIKE ?)`. It never touches `payload_ciphertext`, so a search
  never decrypts anything, and the ownership filter is baked into the same
  query as the match — there is no separate "fetch everything, then check
  ownership" step for search to get wrong.
- Search results returned to the client are metadata only (id, type,
  category, title, searchUsername, timestamps) — never the decrypted
  `payload`. Opening a result calls `GET /api/vault/items/:id` (ownership-
  checked, as above) to fetch the full record, and revealing a password
  within it requires the separate re-authentication step described next.

---

## 9. What's genuinely mocked, and why (read this before a demo)

Being upfront about this matters more than pretending it's all real:

- **Biometric unlock** is real on the *server* side — enabling it creates
  an actual random device token, hashes it, and wraps a real copy of the
  VEK under a KEK derived from that token (`POST /api/auth/biometric/*` in
  `server/app.js`). What's necessarily out of scope for a plain web backend
  is the *device* side: gating that token behind actual Face ID/Touch
  ID/Android biometrics requires either a native app (Keychain/Keystore) or
  WebAuthn platform authenticators in a browser. This reference frontend
  stores the token in `localStorage` as the closest available stand-in —
  clearly commented in `public/app.js` — which is **not** hardware-backed
  and should be replaced with WebAuthn before this touches real users.
- **Email delivery** (recovery codes) goes to the server console instead of
  a real inbox, because this sandbox has no network egress to reach an SMTP
  provider. See section 6 and `.env.example`.
- **Two-factor authentication** is a stored on/off flag and factors into
  the Security Centre score, but there's no second-factor challenge (TOTP/
  SMS) actually wired into the login flow yet — the brief lists 2FA as
  optional, and this build treats the toggle as a placeholder for a real
  TOTP implementation (e.g. `otplib`) rather than faking a fake code.
- **Account/session edit and per-session revoke-by-id** in Settings are
  intentionally limited to "sign out all other devices" in the UI; the API
  (`/api/auth/sessions`) already lists individual sessions, revoking a
  single one by id is a small addition left as a TODO rather than wired
  into a button that would look like it does more than it does.
- **HTTPS** isn't configured — see section 10.

Nothing above is presented as more finished than it is inside the app
itself: the Security Centre's "How search stays secure" note and this
README are the same story told twice, not a polished UI hiding a rougher
reality.

---

## 10. Production hardening checklist (not done here, on purpose)

This app runs over plain HTTP on localhost, which is fine for development
and grading but not for real users. Before deploying:

- [ ] Put it behind HTTPS (reverse proxy like Caddy/nginx, or a platform
      that terminates TLS for you) — cookies are marked `Secure`, so they
      **will not be sent at all** over plain HTTP in a real browser once
      you're not on `localhost`.
- [ ] Set `VAULTIX_KEY_PEPPER` to a real secret from a secrets manager.
- [ ] Add HSTS, and tighten the `Content-Security-Policy` in
      `server/http-utils.js` for your actual asset origins.
- [ ] Move the SQLite file to a backed-up, access-controlled volume, or
      migrate to Postgres (section 3).
- [ ] Replace `localStorage`-based biometric token storage with WebAuthn.
- [ ] Wire real SMTP for recovery codes.
- [ ] Add structured, shippable audit logging for `security_events` (today
      it's just a table you can query — fine for the in-app Activity Log,
      not yet fine for compliance-grade audit export).
- [ ] Run a real dependency and secret-scanning pipeline once you add the
      `argon2`/Postgres/WebAuthn/SMTP packages this README describes.

---

## 11. API reference (summary)

All endpoints are JSON. Mutating endpoints (`POST`/`PUT`/`DELETE`) require
the `x-csrf-token` header described in section 5.

```
POST   /api/auth/register              create account, returns recoveryKey once
POST   /api/auth/login                 email + password
POST   /api/auth/logout
GET    /api/auth/me                    current user + lock state
POST   /api/auth/lock
POST   /api/auth/unlock/password
POST   /api/auth/unlock/pin            also transparently handles the duress PIN — see section 14
POST   /api/auth/unlock/device
POST   /api/auth/change-password       requires unlocked vault
POST   /api/auth/pin                   set/change PIN, requires unlocked vault
POST   /api/auth/duress-pin            set/change duress PIN, requires unlocked vault
DELETE /api/auth/duress-pin
POST   /api/auth/biometric/enable      requires unlocked vault
POST   /api/auth/biometric/disable
POST   /api/auth/2fa                   { enabled: bool }
POST   /api/auth/autolock              { ms: 0|30000|60000|300000|900000 }
GET    /api/auth/sessions
POST   /api/auth/sessions/revoke-others
DELETE /api/auth/account               { confirmText: "DELETE MY ACCOUNT", password }

POST   /api/profile/avatar             { mimeType, dataBase64 } — requires unlocked vault
GET    /api/profile/avatar
DELETE /api/profile/avatar

GET    /api/vault/summary
GET    /api/vault/items?type=password
POST   /api/vault/items                requires unlocked vault
GET    /api/vault/items/:id            requires unlocked vault
PUT    /api/vault/items/:id            requires unlocked vault
DELETE /api/vault/items/:id
POST   /api/vault/items/:id/reveal     { reauth: { method: "password"|"pin", value } }
GET    /api/search?q=&category=

POST   /api/vault/items/:id/file       { fileName, mimeType, dataBase64 } — requires unlocked vault
GET    /api/vault/items/:id/file/meta  metadata only — no decrypt, no activity log entry
GET    /api/vault/items/:id/file       requires unlocked vault
DELETE /api/vault/items/:id/file

POST   /api/vault/items/:id/share      { ciphertext, iv, tag, maxUses, ttlMs } — server never sees the key
GET    /api/share/:id                  public, unauthenticated, single-use/expiring

POST   /api/vault/export               { exportPassword } — requires unlocked vault
POST   /api/vault/import               { exportPassword, backup } — requires unlocked vault

GET    /api/security/status
GET    /api/security/activity
GET    /api/security/activity/verify   recomputes the hash chain — see section 14
GET    /api/security/health            requires unlocked vault — see section 14
POST   /api/tools/generate-password    { length, upper, lower, numbers, symbols }

POST   /api/recovery/request           { email }
POST   /api/recovery/verify-code       { email, code }
POST   /api/recovery/reset             { email, code, recoveryKey, newPassword }
```

---

## 12. Project structure

```
vaultix/
  server/
    crypto.js        scrypt KDF, AES-256-GCM, key wrapping -- the only file that touches keys
    db.js             SQLite schema + connection (node:sqlite)
    store.js          in-memory unlocked-VEK cache, recovery codes, IP rate limiting
    auth.js           registration, login, sessions, CSRF, lock/unlock, hash-chained logging, security score
    vault.js          vault item CRUD, secure search, file attachments, share links, vault health -- user isolation lives here
    http-utils.js     tiny dependency-free router (stands in for Express)
    app.js            every HTTP route, wired to the modules above
    index.js          entry point -- static file serving + API dispatch
  public/
    index.html, app.js, styles.css   vanilla-JS SPA, no build step, no framework
    share.html                       standalone recipient page for self-destructing share links
  tests/
    helpers.js, auth.test.js, isolation.test.js, vault.test.js, security.test.js, expansion.test.js
  .env.example
  package.json        zero dependencies -- see section 3
  README.md            (this file)
```

---

## 14. Expansion features

Everything below was added after the initial build, in response to a request to cover more real-world data categories and a set of "enterprise-grade" security features. Each is real and tested (32/32 tests, `npm test`) -- none of it is a UI mockup.

### More vault item types

Seven new types beyond the original password/email/personal/id/note/wifi/contact/account set: **API keys & secrets**, **SSH keys**, **crypto wallets** (seed phrases, private keys, addresses), **physical access codes** (door PINs, safe combinations, alarm codes), **software licenses**, **medical/emergency profiles**, and **digital inheritance notes**. All use the exact same AES-256-GCM encrypted-payload architecture as everything else -- see `server/vault.js`'s `ALLOWED_TYPES` and `public/app.js`'s `FIELD_CONFIGS`.

List screens for these types show a small non-secret preview (e.g. "AWS" under an API key titled "AWS Production") using the same plaintext `searchUsername` metadata column passwords already use for their username/email preview -- never the decrypted payload. An earlier draft of this feature fetched full decrypted records just to populate that preview; it was caught and reverted specifically because it would have put SSH private keys and wallet seed phrases into browser memory the instant a list screen opened, without any re-authentication step. The current version never decrypts anything until you explicitly click Reveal.

### Encrypted file attachments

`vault_files` stores AES-256-GCM encrypted file bytes (separate table from `vault_items` so large BLOBs don't sit on every list/search query). Uploads are capped at 6MB, restricted to PDF/PNG/JPEG/WEBP, and ownership-checked exactly like every other resource. A metadata-only endpoint (`GET .../file/meta`) lets the UI show "a file is attached" without decrypting it or logging a download event -- only actually fetching the file logs one.

### Encrypted profile picture

Uploadable at registration or from Settings -> Account. Encrypted with the same per-user VEK as everything else, so -- deliberately -- it's only visible once the vault is unlocked, not on the lock screen.

### Duress ("panic") PIN

Set a second PIN in Settings -> Security that's required to differ from your real one. Entering it at the lock screen looks completely ordinary and lands on a small decoy dashboard (fixed fake passwords/notes/activity), while the real vault stays genuinely locked. Two things make this safe rather than cosmetic:

1. **Server-side:** `checkDuressPin()` never touches the VEK cache. `POST /api/auth/unlock/pin` checks the duress PIN first, before even looking at the real PIN's lockout state -- so a duress unlock can never be blocked by (or count against) real-PIN rate limiting.
2. **Client-side:** once `state.duress` is set, `api()` refuses every call except lock/logout/me -- see `DURESS_ALLOWED_PATHS` in `public/app.js`. The decoy screens never touch a real endpoint at all, so even a UI bug can't leak real data through this path.

The duress unlock is still logged (`"Vault unlocked using duress PIN"`) -- invisible from inside the decoy session, but visible as an alert the next time you unlock for real.

### Tamper-evident activity log

Every `security_events` row stores a hash covering the previous row's hash (`server/auth.js logEvent`/`verifyEventChain`). Editing or deleting a past entry breaks every hash after it. "Verify log integrity" on the Activity Log screen recomputes the chain and reports exactly where it breaks, if it does. This detects tampering; it doesn't prevent someone with direct database access from rewriting the chain forward from a tampered point -- a real anchor against that (e.g. periodically publishing the latest hash somewhere append-only) is out of scope here and noted as such in the code.

### Vault Health Scoring

`GET /api/security/health` (requires unlocked vault) checks your own saved passwords and Wi-Fi credentials for reuse, weak entropy, age over 6 months, and default-looking Wi-Fi keys (`12345678`, `password`, etc.) -- entirely server-side, entirely local to your own data, nothing sent anywhere external. This is distinct from breach checking below.

### Have I Been Pwned breach checking

Real k-anonymity implementation, entirely client-side: the revealed password is SHA-1 hashed in the browser via `crypto.subtle.digest`, and only the first 5 hex characters of that hash are sent to `api.pwnedpasswords.com` -- never the password, never the full hash, and never through this app's own server at all. **This cannot be exercised from the sandbox this was built in** (no outbound network access there); the code follows HIBP's documented protocol exactly, but you should verify the live fetch once this is running somewhere with normal internet access.

### Self-destructing share links

`POST /api/vault/items/:id/share` stores ciphertext only -- the AES-256-GCM key is generated in the browser (`crypto.subtle.generateKey`), never sent to the server, and embedded only in the resulting URL's fragment (`#key=...`), which browsers never transmit in HTTP requests. `public/share.html` is a small standalone page (no session, no auth) that reads the key from `location.hash` and decrypts client-side. Links expire after a configurable time and use count (default: 1 use); the server deletes the ciphertext the moment the use limit is hit, not just marks it used.

### Encrypted portable backups (.vaultx)

`POST /api/vault/export` bundles every item, decrypts it with your real VEK, and re-encrypts the bundle under a key derived from a **separate password you choose at export time** -- deliberately independent of your master password, so a leaked backup file doesn't also compromise your live vault, and a compromised live password doesn't retroactively expose every backup you've ever taken. Import re-inserts items under the importing account's own VEK; nothing from the backup file is trusted or used directly.

### Profile picture, revisited

Asked for explicitly: upload at registration (optional) or any time from Settings. Same encryption, same "requires unlocked vault to view" rule as the rest of the app.

---

## 15. Deferred, on purpose -- not built, with a real plan

Four requested features are genuinely out of scope for this pass -- each is a multi-day project in its own right, and two of them (WebAuthn, zero-knowledge search) are exactly the kind of security-critical cryptographic code that's dangerous to ship half-verified. Rather than fake them, here's what each actually requires:

**True zero-knowledge client-side encryption + blind-indexed search.** Right now the server derives your KEK and unwraps your VEK during login/unlock -- meaning the server process does, briefly, handle key material (never storing it, but touching it). A genuine zero-knowledge architecture moves key derivation entirely into the browser (Web Crypto's `PBKDF2`/`deriveKey`, no WASM or network needed -- it's built in) so the server only ever receives and stores ciphertext, never anything it could use to decrypt. Search becomes the hard part: with the server unable to decrypt, `LIKE '%term%'` queries no longer work, so search needs blind indexing -- HMAC-SHA256 tokens of normalized keywords, computed client-side with a key derived from your VEK, sent instead of plaintext search terms. This is a full rearchitecture of `server/auth.js`, `server/vault.js`, and the unlock flow, not an incremental patch.

**FIDO2/WebAuthn hardware keys and passkeys.** The actual cryptographic ceremony (`navigator.credentials.create/get`) is a browser-native, no-network-dependency W3C standard -- that part's genuinely approachable. What makes it a separate, careful effort is the server-side verification: parsing CBOR-encoded attestation objects, extracting and validating COSE public keys, and verifying ECDSA/RSA signatures correctly is exactly the kind of narrow, security-critical parsing code where a subtle bug becomes an authentication bypass. It deserves dedicated implementation and testing time, not a rushed addition alongside a dozen other features.

**OS Keystore/TPM integration** (iOS Keychain, Android Keystore, TPM 2.0). This one isn't a "not yet" so much as a "not from a web app" -- hardware-backed secure storage is inherently a native-app capability. A web browser has no API to store a secret behind Face ID in the actual Secure Enclave; that requires a native iOS/Android app (or Electron wrapper with native modules), a different application shell entirely.

**PWA offline encrypted cache.** Storing an AES-GCM encrypted copy of the vault in IndexedDB for offline access is buildable without new architecture, but needs a service worker, a sync/conflict strategy for changes made while offline, and careful cache invalidation on lock/logout so stale decrypted data doesn't linger -- enough moving parts to deserve its own focused pass rather than being bolted onto this one.

Also not built: the multi-party **emergency access request/veto flow** (a contact requests access, the owner has N days to veto, access releases automatically otherwise) -- the underlying "release a re-wrapped key after a deadline" mechanic is straightforward given the existing KEK/VEK architecture, but the surrounding surface area (inviting a contact, notifying them, an accept/veto UI, tracking pending requests) is a genuinely separate feature, not an extension of anything already here.

---

## 16. Security review (honest self-assessment)

Per the brief's instruction not to claim "100% secure" — a plain summary of
where this stands:

**Solid:** user isolation (tested), AES-256-GCM with per-record IVs and
tamper detection (tested), password/PIN hashing never stores plaintext
(tested), generic auth error messages, CSRF tokens on mutating routes,
PIN brute-force lockout with exponential backoff (tested), master
password/PIN/device/recovery key all independently wrap the same VEK
so no single reset path can silently expose or lose data, search never
decrypts to build results.

**Real gaps, not hidden:** scrypt substitutes for Argon2id (section 3);
biometric unlock's device-bound secret sits in `localStorage`, not a
hardware-backed keystore (section 9); no HTTPS/TLS termination configured
(section 10); no automated dependency/secret scanning; no real 2FA
challenge; single-process in-memory rate limiting won't survive a
multi-instance deployment (would need Redis or similar); the VEK cache in
`server/store.js` is per-process memory, so restarting the server logs
every unlocked session out (arguably a feature — no VEK survives a
restart — but worth knowing).
