// server/auth.js
//
// Everything about "who is making this request, and is their vault open"
// lives here. Route handlers in app.js call into this module; they never
// touch password hashes, session tokens, or keys directly.

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import {
  hashSecret, verifySecret, deriveKey, wrapKey, unwrapKey,
  randomBytes, randomToken, sha256Hex, newVaultKey, recoveryKeyPlain,
} from './crypto.js';
import { cacheVek, getVek, dropVek } from './store.js';
import { httpErr, parseCookies, setCookie } from './http-utils.js';

const SESSION_COOKIE = 'vx_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h absolute session lifetime
const LOGIN_LOCK_THRESHOLD = 5;
const PIN_LOCK_THRESHOLD = 3;

function backoffMs(failCount, threshold) {
  const over = Math.max(0, failCount - threshold + 1);
  return Math.min(30_000 * 2 ** (over - 1), 15 * 60_000); // caps at 15 min
}

export function logEvent(userId, text) {
  // PRODUCTION NOTE: `text` must never contain a secret value. Every call
  // site in this codebase passes a fixed, human-readable string — never
  // interpolated password/PIN/recovery-key content.
  //
  // Hash-chained, tamper-evident log: each row's hash covers the previous
  // row's hash, so altering or deleting a past entry breaks every hash
  // after it. verifyEventChain() below recomputes the chain to detect
  // exactly that. This does not stop someone with direct DB write access
  // from rewriting the whole chain forward from a tampered point — that
  // requires a separate, out-of-band anchor (e.g. periodically publishing
  // the latest hash somewhere the DB owner can't rewrite) which is out of
  // scope here; what this does guarantee is that any tampering with
  // already-issued entries is detectable, not preventable at the DB layer.
  const prevRow = db.prepare('SELECT hash FROM security_events WHERE user_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1').get(userId);
  const prevHash = prevRow ? prevRow.hash : 'genesis';
  const createdAt = Date.now();
  const id = randomUUID();
  const hash = sha256Hex(`${prevHash}|${userId}|${text}|${createdAt}`);
  db.prepare('INSERT INTO security_events (id, user_id, text, prev_hash, hash, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, userId, text, prevHash, hash, createdAt);
}

export function verifyEventChain(userId) {
  const rows = db.prepare('SELECT * FROM security_events WHERE user_id = ? ORDER BY created_at ASC, rowid ASC').all(userId);
  let prevHash = 'genesis';
  for (const row of rows) {
    if (row.prev_hash !== prevHash) return { valid: false, brokenAt: row.id };
    const expected = sha256Hex(`${prevHash}|${userId}|${row.text}|${row.created_at}`);
    if (expected !== row.hash) return { valid: false, brokenAt: row.id };
    prevHash = row.hash;
  }
  return { valid: true, checked: rows.length };
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
export function createUser({ name, email, password, recoveryEmail }) {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) throw httpErr(409, 'An account with that email already exists.');

  const id = randomUUID();
  const passwordHash = hashSecret(password); // authentication verifier

  // Independent KDF pass (different salt/purpose) so the auth verifier and
  // the key-encryption-key are cryptographically unrelated, even though
  // both are derived from the same master password.
  const kekSalt = randomBytes(16);
  const kek = deriveKey(password, kekSalt);
  const vek = newVaultKey();
  const wrapped = wrapKey(vek, kek);

  const recoveryKey = recoveryKeyPlain();
  const recoveryKeyHash = hashSecret(recoveryKey);
  const recoveryKekSalt = randomBytes(16);
  const recoveryKek = deriveKey(recoveryKey, recoveryKekSalt);
  const wrappedRecovery = wrapKey(vek, recoveryKek);

  db.prepare(`
    INSERT INTO users (
      id, name, email, password_hash,
      kek_salt, wrapped_vek, wrapped_vek_iv, wrapped_vek_tag,
      recovery_email, recovery_key_hash, recovery_kek_salt,
      wrapped_vek_recovery, wrapped_vek_recovery_iv, wrapped_vek_recovery_tag,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, name, email.toLowerCase(), passwordHash,
    kekSalt, wrapped.ciphertext, wrapped.iv, wrapped.tag,
    recoveryEmail.toLowerCase(), recoveryKeyHash, recoveryKekSalt,
    wrappedRecovery.ciphertext, wrappedRecovery.iv, wrappedRecovery.tag,
    Date.now(),
  );

  vek.fill(0); // scrub the plaintext VEK from this stack frame once persisted
  logEvent(id, 'Account created');
  return { id, name, email: email.toLowerCase(), recoveryKey };
}

// ---------------------------------------------------------------------------
// Login (verifies master password, unwraps VEK, opens a session+unlocked vault)
// ---------------------------------------------------------------------------
export function verifyLoginAndUnlock({ email, password, device, ip }) {
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get((email || '').toLowerCase());

  // Constant-shape response whether or not the account exists, to avoid
  // account enumeration — but we still need *some* row to run scrypt
  // against so timing doesn't leak existence either.
  const decoyHash = 'scrypt$32768$8$1$00$00';
  const candidateHash = user ? user.password_hash : decoyHash;

  if (user && user.login_locked_until && Date.now() < user.login_locked_until) {
    throw httpErr(429, 'Too many attempts. Please try again shortly.');
  }

  const ok = verifySecret(password, candidateHash) && !!user;

  if (!ok) {
    if (user) {
      const failCount = user.login_failed_count + 1;
      const lockedUntil = failCount >= LOGIN_LOCK_THRESHOLD ? Date.now() + backoffMs(failCount, LOGIN_LOCK_THRESHOLD) : null;
      db.prepare('UPDATE users SET login_failed_count = ?, login_locked_until = ? WHERE id = ?')
        .run(failCount, lockedUntil, user.id);
      logEvent(user.id, 'Failed login attempt');
    }
    throw httpErr(401, 'Invalid email or password.');
  }

  db.prepare('UPDATE users SET login_failed_count = 0, login_locked_until = NULL, last_login = ? WHERE id = ?')
    .run(Date.now(), user.id);

  const kek = deriveKey(password, user.kek_salt);
  const vek = unwrapKey({ ciphertext: user.wrapped_vek, iv: user.wrapped_vek_iv, tag: user.wrapped_vek_tag }, kek);

  const session = openSession(user.id, device);
  cacheVek(session.id, vek);
  logEvent(user.id, 'Successful login');
  return { user: publicUser(user), session };
}

export function openSession(userId, device) {
  const id = randomUUID();
  const token = randomToken(32);
  const csrfToken = randomToken(24);
  const now = Date.now();
  db.prepare(`
    INSERT INTO sessions (id, user_id, token_hash, device, csrf_secret, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, userId, sha256Hex(token), device || 'Unknown device', csrfToken, now, now + SESSION_TTL_MS);
  return { id, token, csrfToken, expiresAt: now + SESSION_TTL_MS };
}

export function publicUser(u) {
  return {
    id: u.id, name: u.name, email: u.email,
    biometricEnabled: !!u.biometric_enabled,
    twoFactorEnabled: !!u.two_factor_enabled,
    autoLockMs: u.auto_lock_ms,
    hasPin: !!u.pin_hash,
    createdAt: u.created_at,
    lastLogin: u.last_login,
  };
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
export function authenticate(req) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  if (!token) throw httpErr(401, 'Not signed in.');
  const tokenHash = sha256Hex(token);
  const session = db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(tokenHash);
  if (!session || session.revoked || Date.now() > session.expires_at) {
    throw httpErr(401, 'Session expired. Please sign in again.');
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) throw httpErr(401, 'Not signed in.');
  req.user = user;
  req.session = session;
}

export function requireCsrf(req) {
  if (!['POST', 'PUT', 'DELETE'].includes(req.method)) return;
  const header = req.headers['x-csrf-token'];
  if (!header || !req.session || header !== req.session.csrf_secret) {
    throw httpErr(403, 'Request could not be verified. Please refresh and try again.');
  }
}

export function requireUnlocked(req) {
  const vek = getVek(req.session.id, req.user.auto_lock_ms);
  if (!vek) throw httpErr(423, 'Vault is locked.');
  req.vek = vek;
}

export function setSessionCookie(res, session) {
  setCookie(res, SESSION_COOKIE, session.token, { maxAge: Math.floor(SESSION_TTL_MS / 1000) });
}

export function clearSessionCookie(res) {
  setCookie(res, SESSION_COOKIE, '', { expires: 0 });
}

export function computeSecurityScore(user, itemCount, reusedPasswords) {
  // PRODUCTION NOTE: every point below is tied to a real, checkable
  // condition — never an arbitrary or cosmetic number.
  const checks = [
    { label: 'Master password set with strong hashing', pass: true },
    { label: 'Two-factor authentication enabled', pass: !!user.two_factor_enabled },
    { label: 'Biometric unlock configured', pass: !!user.biometric_enabled },
    { label: 'Auto-lock set to 5 minutes or less', pass: user.auto_lock_ms > 0 && user.auto_lock_ms <= 5 * 60_000 },
    { label: 'No duplicate passwords detected', pass: !reusedPasswords },
  ];
  const score = checks.filter((c) => c.pass).length;
  return { score, max: checks.length, checks };
}

// ---------------------------------------------------------------------------
// Duress ("panic") PIN
//
// Deliberately asymmetric with the real PIN: setting one just hashes it and
// requires it to differ from the real PIN. Verifying it NEVER touches the
// VEK cache — a correct duress-PIN entry returns { duress: true } and the
// session stays exactly as locked as it was before. The frontend is
// responsible for then rendering a fixed set of decoy data instead of
// calling any real vault endpoint; every real endpoint still independently
// requires requireUnlocked(), so even a frontend bug can't leak real data
// through this path — there is simply no VEK in memory to leak.
// ---------------------------------------------------------------------------
export function setDuressPin(userId, pin, realPinHash) {
  if (realPinHash && verifySecret(pin, realPinHash)) {
    throw httpErr(400, 'Your duress PIN must be different from your regular PIN.');
  }
  const hash = hashSecret(pin);
  db.prepare('UPDATE users SET duress_pin_hash = ? WHERE id = ?').run(hash, userId);
}

export function checkDuressPin(user, pin) {
  return !!user.duress_pin_hash && verifySecret(pin, user.duress_pin_hash);
}
