// server/store.js
//
// Deliberately-volatile runtime state. Nothing sensitive that lives in this
// file is ever written to disk.
//
// unlockedVaults: sessionId -> { vek: Buffer, lastActivity: number }
//   The unwrapped Vault Encryption Key only ever exists in server process
//   memory, for the lifetime of an unlocked session, and is dropped on
//   lock/logout/expiry/idle-timeout. It is never logged, never persisted,
//   and never sent to the client.
//
// recoveryCodes: userId -> { code, expiresAt }
//   Stand-in for "email delivery of a one-time code". This sandbox can't
//   send real email (no network egress), so the code is written to the
//   server console instead of a real inbox — see README for what changes
//   in a networked deployment.

const unlockedVaults = new Map();
const recoveryCodes = new Map();

export function cacheVek(sessionId, vek) {
  unlockedVaults.set(sessionId, { vek, lastActivity: Date.now() });
}

export function getVek(sessionId, autoLockMs) {
  const entry = unlockedVaults.get(sessionId);
  if (!entry) return null;
  if (autoLockMs > 0 && Date.now() - entry.lastActivity > autoLockMs) {
    unlockedVaults.delete(sessionId);
    return null;
  }
  entry.lastActivity = Date.now();
  return entry.vek;
}

export function dropVek(sessionId) {
  unlockedVaults.delete(sessionId);
}

export function issueRecoveryCode(userId) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  recoveryCodes.set(userId, { code, expiresAt: Date.now() + 10 * 60 * 1000 });
  // eslint-disable-next-line no-console
  console.log(`[VAULTIXgusTAR] Recovery code for user ${userId}: ${code} (would be emailed in production)`);
  return code;
}

export function checkRecoveryCode(userId, code) {
  const entry = recoveryCodes.get(userId);
  if (!entry) return false;
  if (Date.now() > entry.expiresAt) { recoveryCodes.delete(userId); return false; }
  return entry.code === code;
}

export function consumeRecoveryCode(userId) {
  recoveryCodes.delete(userId);
}

// --- Simple sliding-window IP rate limiter for auth endpoints (defense in
// depth on top of the per-account DB-backed lockout in auth.js) ---
const ipHits = new Map();

export function ipRateLimited(ip, limit = 20, windowMs = 60_000) {
  const now = Date.now();
  const hits = (ipHits.get(ip) || []).filter((t) => now - t < windowMs);
  hits.push(now);
  ipHits.set(ip, hits);
  return hits.length > limit;
}
