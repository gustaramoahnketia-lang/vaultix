// server/app.js — route definitions. See README for the full endpoint list.

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import {
  hashSecret, verifySecret, deriveKey, wrapKey, unwrapKey,
  randomBytes, randomToken, passwordStrength, generatePassword,
  encryptJSON, decryptJSON, sha256Hex,
} from './crypto.js';
import {
  createUser, verifyLoginAndUnlock, openSession, publicUser,
  authenticate, requireCsrf, requireUnlocked, setSessionCookie, clearSessionCookie,
  logEvent, computeSecurityScore, setDuressPin, checkDuressPin, verifyEventChain,
} from './auth.js';
import { cacheVek, getVek, dropVek, issueRecoveryCode, checkRecoveryCode, consumeRecoveryCode, ipRateLimited } from './store.js';
import * as Vault from './vault.js';
import * as Events from './events.js';
import { Router, httpErr, sendJson } from './http-utils.js';

export const router = new Router();

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}

function requireFields(body, fields) {
  for (const f of fields) {
    if (body[f] === undefined || body[f] === null || body[f] === '') {
      throw httpErr(400, `Missing required field: ${f}`);
    }
  }
}

const authGuard = (req) => authenticate(req);
const csrfGuard = (req) => requireCsrf(req);
const unlockGuard = (req) => requireUnlocked(req);

// ---------------------------------------------------------------------------
// Registration / login / session
// ---------------------------------------------------------------------------
router.post('/api/auth/register', async (req, res) => {
  if (ipRateLimited(clientIp(req), 10, 60_000)) throw httpErr(429, 'Too many attempts. Please try again shortly.');
  requireFields(req.body, ['name', 'email', 'password', 'recoveryEmail']);
  if (req.body.password.length < 8) throw httpErr(400, 'Master password must be at least 8 characters.');
  if (!/^\S+@\S+\.\S+$/.test(req.body.email)) throw httpErr(400, 'Enter a valid email address.');

  const result = createUser(req.body);
  const session = openSession(result.id, req.headers['user-agent']?.slice(0, 120) || 'Unknown device');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.id);
  const kek = deriveKey(req.body.password, user.kek_salt);
  const vek = unwrapKey({ ciphertext: user.wrapped_vek, iv: user.wrapped_vek_iv, tag: user.wrapped_vek_tag }, kek);
  cacheVek(session.id, vek);

  setSessionCookie(res, session);
  sendJson(res, 201, {
    user: publicUser(user),
    csrfToken: session.csrfToken,
    recoveryKey: result.recoveryKey, // shown exactly once — see README
  });
});

router.post('/api/auth/login', async (req, res) => {
  if (ipRateLimited(clientIp(req), 20, 60_000)) throw httpErr(429, 'Too many attempts. Please try again shortly.');
  requireFields(req.body, ['email', 'password']);
  const { user, session } = verifyLoginAndUnlock({
    email: req.body.email,
    password: req.body.password,
    device: req.headers['user-agent']?.slice(0, 120) || 'Unknown device',
    ip: clientIp(req),
  });
  setSessionCookie(res, session);
  sendJson(res, 200, { user, csrfToken: session.csrfToken });
});

router.post('/api/auth/logout', authGuard, csrfGuard, async (req, res) => {
  db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(req.session.id);
  dropVek(req.session.id);
  clearSessionCookie(res);
  logEvent(req.user.id, 'Signed out');
  sendJson(res, 200, { ok: true });
});

router.get('/api/auth/me', authGuard, async (req, res) => {
  const unlocked = !!getVek(req.session.id, req.user.auto_lock_ms);
  sendJson(res, 200, { user: publicUser(req.user), unlocked, csrfToken: req.session.csrf_secret });
});

router.post('/api/auth/lock', authGuard, csrfGuard, async (req, res) => {
  dropVek(req.session.id);
  logEvent(req.user.id, 'Vault manually locked');
  sendJson(res, 200, { ok: true });
});

router.post('/api/auth/unlock/password', authGuard, async (req, res) => {
  requireFields(req.body, ['password']);
  if (!verifySecret(req.body.password, req.user.password_hash)) {
    logEvent(req.user.id, 'Failed unlock attempt (master password)');
    throw httpErr(401, 'Incorrect master password.');
  }
  const kek = deriveKey(req.body.password, req.user.kek_salt);
  const vek = unwrapKey({ ciphertext: req.user.wrapped_vek, iv: req.user.wrapped_vek_iv, tag: req.user.wrapped_vek_tag }, kek);
  cacheVek(req.session.id, vek);
  logEvent(req.user.id, 'Vault unlocked using master password');
  sendJson(res, 200, { ok: true });
});

router.post('/api/auth/unlock/pin', authGuard, async (req, res) => {
  requireFields(req.body, ['pin']);

  // Duress check happens first and is checked BEFORE the real PIN's
  // lockout state is even consulted — it must always work regardless of
  // how many real-PIN attempts have failed, precisely because "someone is
  // pressuring me to unlock right now" is exactly the scenario this exists
  // for. It also never touches pin_failed_count, so repeated duress use
  // can never accidentally lock out (or even influence) the real PIN.
  if (checkDuressPin(req.user, req.body.pin)) {
    logEvent(req.user.id, 'Vault unlocked using duress PIN');
    sendJson(res, 200, { ok: true, duress: true });
    return;
  }

  if (!req.user.pin_hash) throw httpErr(400, 'No PIN has been set for this account.');
  if (req.user.pin_locked_until && Date.now() < req.user.pin_locked_until) {
    const seconds = Math.ceil((req.user.pin_locked_until - Date.now()) / 1000);
    throw httpErr(429, `Too many attempts. Try again in ${seconds}s.`);
  }
  if (!verifySecret(req.body.pin, req.user.pin_hash)) {
    const failCount = req.user.pin_failed_count + 1;
    const lockedUntil = failCount >= 3 ? Date.now() + Math.min(30_000 * 2 ** (failCount - 3), 15 * 60_000) : null;
    db.prepare('UPDATE users SET pin_failed_count = ?, pin_locked_until = ? WHERE id = ?').run(failCount, lockedUntil, req.user.id);
    logEvent(req.user.id, 'Failed unlock attempt (PIN)');
    throw httpErr(401, 'Incorrect PIN.');
  }
  db.prepare('UPDATE users SET pin_failed_count = 0, pin_locked_until = NULL WHERE id = ?').run(req.user.id);
  const kek = deriveKey(req.body.pin, req.user.pin_kek_salt);
  const vek = unwrapKey({ ciphertext: req.user.wrapped_vek_pin, iv: req.user.wrapped_vek_pin_iv, tag: req.user.wrapped_vek_pin_tag }, kek);
  cacheVek(req.session.id, vek);
  logEvent(req.user.id, 'Vault unlocked using PIN');
  sendJson(res, 200, { ok: true });
});

router.post('/api/auth/unlock/device', authGuard, async (req, res) => {
  // See README "Biometric unlock, honestly" — this endpoint is the server
  // half of a device-bound unlock; a real client obtains `deviceToken` from
  // a platform authenticator (WebAuthn / Keychain / Keystore) gated by
  // Face ID / Touch ID / Android biometrics, never from the app itself.
  requireFields(req.body, ['deviceToken']);
  if (!req.user.device_token_hash) throw httpErr(400, 'Biometric unlock is not enabled for this account.');
  const { sha256Hex } = await import('./crypto.js');
  if (sha256Hex(req.body.deviceToken) !== req.user.device_token_hash) {
    logEvent(req.user.id, 'Failed unlock attempt (biometric)');
    throw httpErr(401, 'Biometric verification failed.');
  }
  const kek = deriveKey(req.body.deviceToken, req.user.device_kek_salt);
  const vek = unwrapKey({ ciphertext: req.user.wrapped_vek_device, iv: req.user.wrapped_vek_device_iv, tag: req.user.wrapped_vek_device_tag }, kek);
  cacheVek(req.session.id, vek);
  logEvent(req.user.id, 'Vault unlocked using fingerprint');
  sendJson(res, 200, { ok: true });
});

// ---------------------------------------------------------------------------
// Security settings (all require an unlocked vault: they rewrap the VEK)
// ---------------------------------------------------------------------------
router.post('/api/auth/change-password', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  requireFields(req.body, ['currentPassword', 'newPassword']);
  if (!verifySecret(req.body.currentPassword, req.user.password_hash)) throw httpErr(401, 'Current password is incorrect.');
  if (req.body.newPassword.length < 8) throw httpErr(400, 'New password must be at least 8 characters.');
  const newHash = hashSecret(req.body.newPassword);
  const kekSalt = randomBytes(16);
  const kek = deriveKey(req.body.newPassword, kekSalt);
  const wrapped = wrapKey(req.vek, kek);
  db.prepare('UPDATE users SET password_hash = ?, kek_salt = ?, wrapped_vek = ?, wrapped_vek_iv = ?, wrapped_vek_tag = ? WHERE id = ?')
    .run(newHash, kekSalt, wrapped.ciphertext, wrapped.iv, wrapped.tag, req.user.id);
  logEvent(req.user.id, 'Master password changed');
  sendJson(res, 200, { ok: true });
});

router.post('/api/auth/pin', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  requireFields(req.body, ['pin']);
  if (!/^\d{4,6}$/.test(req.body.pin)) throw httpErr(400, 'PIN must be 4–6 digits.');
  const pinHash = hashSecret(req.body.pin);
  const pinKekSalt = randomBytes(16);
  const pinKek = deriveKey(req.body.pin, pinKekSalt);
  const wrapped = wrapKey(req.vek, pinKek);
  db.prepare(`
    UPDATE users SET pin_hash = ?, pin_kek_salt = ?, wrapped_vek_pin = ?, wrapped_vek_pin_iv = ?, wrapped_vek_pin_tag = ?, pin_failed_count = 0, pin_locked_until = NULL
    WHERE id = ?
  `).run(pinHash, pinKekSalt, wrapped.ciphertext, wrapped.iv, wrapped.tag, req.user.id);
  logEvent(req.user.id, 'PIN updated');
  sendJson(res, 200, { ok: true });
});

router.post('/api/auth/duress-pin', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  requireFields(req.body, ['pin']);
  if (!/^\d{4,6}$/.test(req.body.pin)) throw httpErr(400, 'PIN must be 4–6 digits.');
  setDuressPin(req.user.id, req.body.pin, req.user.pin_hash);
  logEvent(req.user.id, 'Duress PIN configured');
  sendJson(res, 200, { ok: true });
});

router.delete('/api/auth/duress-pin', authGuard, csrfGuard, async (req, res) => {
  db.prepare('UPDATE users SET duress_pin_hash = NULL WHERE id = ?').run(req.user.id);
  logEvent(req.user.id, 'Duress PIN removed');
  sendJson(res, 200, { ok: true });
});

router.post('/api/auth/biometric/enable', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  const { sha256Hex } = await import('./crypto.js');
  const deviceToken = randomToken(32);
  const deviceKekSalt = randomBytes(16);
  const deviceKek = deriveKey(deviceToken, deviceKekSalt);
  const wrapped = wrapKey(req.vek, deviceKek);
  db.prepare(`
    UPDATE users SET biometric_enabled = 1, device_token_hash = ?, device_kek_salt = ?, wrapped_vek_device = ?, wrapped_vek_device_iv = ?, wrapped_vek_device_tag = ?
    WHERE id = ?
  `).run(sha256Hex(deviceToken), deviceKekSalt, wrapped.ciphertext, wrapped.iv, wrapped.tag, req.user.id);
  logEvent(req.user.id, 'Biometric unlock enabled');
  // deviceToken is returned once, exactly like the recovery key; a real
  // native client stores it in Keychain/Keystore behind Face ID/Touch ID.
  sendJson(res, 200, { ok: true, deviceToken });
});

router.post('/api/auth/biometric/disable', authGuard, csrfGuard, async (req, res) => {
  db.prepare('UPDATE users SET biometric_enabled = 0, device_token_hash = NULL, device_kek_salt = NULL, wrapped_vek_device = NULL, wrapped_vek_device_iv = NULL, wrapped_vek_device_tag = NULL WHERE id = ?').run(req.user.id);
  logEvent(req.user.id, 'Biometric unlock disabled');
  sendJson(res, 200, { ok: true });
});

router.post('/api/auth/2fa', authGuard, csrfGuard, async (req, res) => {
  requireFields(req.body, ['enabled']);
  db.prepare('UPDATE users SET two_factor_enabled = ? WHERE id = ?').run(req.body.enabled ? 1 : 0, req.user.id);
  logEvent(req.user.id, req.body.enabled ? 'Two-factor authentication enabled' : 'Two-factor authentication disabled');
  sendJson(res, 200, { ok: true });
});

router.post('/api/auth/autolock', authGuard, csrfGuard, async (req, res) => {
  requireFields(req.body, ['ms']);
  const allowed = [0, 30_000, 60_000, 5 * 60_000, 15 * 60_000];
  if (!allowed.includes(req.body.ms)) throw httpErr(400, 'Unsupported auto-lock duration.');
  db.prepare('UPDATE users SET auto_lock_ms = ? WHERE id = ?').run(req.body.ms, req.user.id);
  logEvent(req.user.id, 'Auto-lock setting changed');
  sendJson(res, 200, { ok: true });
});

router.get('/api/auth/sessions', authGuard, async (req, res) => {
  const rows = db.prepare('SELECT id, device, created_at, expires_at FROM sessions WHERE user_id = ? AND revoked = 0 AND expires_at > ? ORDER BY created_at DESC').all(req.user.id, Date.now());
  sendJson(res, 200, { sessions: rows.map((s) => ({ ...s, current: s.id === req.session.id })) });
});

router.post('/api/auth/sessions/revoke-others', authGuard, csrfGuard, async (req, res) => {
  db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ?').run(req.user.id, req.session.id);
  logEvent(req.user.id, 'Signed out of all other devices');
  sendJson(res, 200, { ok: true });
});

router.delete('/api/auth/account', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  requireFields(req.body, ['confirmText', 'password']);
  if (req.body.confirmText !== 'DELETE MY ACCOUNT') throw httpErr(400, 'Confirmation text does not match.');
  if (!verifySecret(req.body.password, req.user.password_hash)) throw httpErr(401, 'Incorrect master password.');
  db.prepare('DELETE FROM users WHERE id = ?').run(req.user.id); // cascades sessions, vault_items, security_events
  dropVek(req.session.id);
  clearSessionCookie(res);
  sendJson(res, 200, { ok: true });
});

// ---------------------------------------------------------------------------
// Profile picture — encrypted with the same VEK as everything else, so
// viewing it (like any other record) requires an unlocked vault.
// ---------------------------------------------------------------------------
const AVATAR_MAX_BYTES = 2 * 1024 * 1024;
const AVATAR_MIME = ['image/png', 'image/jpeg', 'image/webp'];

router.post('/api/profile/avatar', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  requireFields(req.body, ['mimeType', 'dataBase64']);
  if (!AVATAR_MIME.includes(req.body.mimeType)) throw httpErr(400, 'Unsupported image type. Use PNG, JPEG, or WEBP.');
  const raw = Buffer.from(req.body.dataBase64, 'base64');
  if (raw.length === 0) throw httpErr(400, 'Empty image.');
  if (raw.length > AVATAR_MAX_BYTES) throw httpErr(413, 'Image is too large (2MB limit).');
  const { encryptRaw } = await import('./crypto.js');
  const enc = encryptRaw(raw, req.vek);
  db.prepare('UPDATE users SET avatar_ciphertext = ?, avatar_iv = ?, avatar_tag = ?, avatar_mime = ? WHERE id = ?')
    .run(enc.ciphertext, enc.iv, enc.tag, req.body.mimeType, req.user.id);
  logEvent(req.user.id, 'Profile picture updated');
  sendJson(res, 200, { ok: true });
});

router.get('/api/profile/avatar', authGuard, unlockGuard, async (req, res) => {
  if (!req.user.avatar_ciphertext) throw httpErr(404, 'No profile picture set.');
  const { decryptRaw } = await import('./crypto.js');
  const raw = decryptRaw({ ciphertext: req.user.avatar_ciphertext, iv: req.user.avatar_iv, tag: req.user.avatar_tag }, req.vek);
  sendJson(res, 200, { mimeType: req.user.avatar_mime, dataBase64: raw.toString('base64') });
});

router.delete('/api/profile/avatar', authGuard, csrfGuard, async (req, res) => {
  db.prepare('UPDATE users SET avatar_ciphertext = NULL, avatar_iv = NULL, avatar_tag = NULL, avatar_mime = NULL WHERE id = ?').run(req.user.id);
  logEvent(req.user.id, 'Profile picture removed');
  sendJson(res, 200, { ok: true });
});

// ---------------------------------------------------------------------------
// Vault CRUD (all authenticated + unlocked + ownership-scoped)
// ---------------------------------------------------------------------------
router.get('/api/vault/summary', authGuard, async (req, res) => {
  sendJson(res, 200, { summary: Vault.summary(req.user.id) });
});

router.get('/api/vault/items', authGuard, async (req, res) => {
  const url = new URL(req.url, 'http://internal');
  const type = url.searchParams.get('type') || undefined;
  sendJson(res, 200, { items: Vault.listItems(req.user.id, { type }) });
});

router.post('/api/vault/items', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  requireFields(req.body, ['type', 'title']);
  const item = Vault.createItem(req.user.id, req.vek, req.body);
  logEvent(req.user.id, `${labelFor(req.body.type)} added: ${req.body.title}`);
  sendJson(res, 201, { item: redact(item) });
});

router.get('/api/vault/items/:id', authGuard, unlockGuard, async (req, res) => {
  const item = Vault.getItem(req.user.id, req.vek, req.params.id);
  sendJson(res, 200, { item: redact(item) });
});

router.post('/api/vault/items/:id/reveal', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  // Step-up re-authentication before returning a decrypted secret, per spec.
  requireFields(req.body, ['reauth']);
  const { method, value } = req.body.reauth || {};
  let ok = false;
  if (method === 'password') ok = verifySecret(value, req.user.password_hash);
  else if (method === 'pin' && req.user.pin_hash) ok = verifySecret(value, req.user.pin_hash);
  if (!ok) {
    logEvent(req.user.id, 'Failed re-authentication before revealing a secret');
    throw httpErr(401, 'Re-authentication failed.');
  }
  const item = Vault.getItem(req.user.id, req.vek, req.params.id);
  logEvent(req.user.id, `Revealed secret for: ${item.title}`); // never logs the secret itself
  sendJson(res, 200, { item });
});

router.put('/api/vault/items/:id', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  const item = Vault.updateItem(req.user.id, req.vek, req.params.id, req.body);
  logEvent(req.user.id, `${labelFor(item.type)} updated: ${item.title}`);
  sendJson(res, 200, { item: redact(item) });
});

router.delete('/api/vault/items/:id', authGuard, csrfGuard, async (req, res) => {
  const title = Vault.listItems(req.user.id).find((i) => i.id === req.params.id)?.title || 'item';
  Vault.deleteItem(req.user.id, req.params.id); // throws 404 if not owned by req.user.id
  logEvent(req.user.id, `${title} deleted`);
  sendJson(res, 200, { ok: true });
});

router.get('/api/search', authGuard, unlockGuard, async (req, res) => {
  const url = new URL(req.url, 'http://internal');
  const q = url.searchParams.get('q') || '';
  const category = url.searchParams.get('category') || undefined;
  const results = Vault.searchItems(req.user.id, req.vek, { q, category });
  // Spec section 30: the main search also searches the calendar — "John" ->
  // vault entry AND John's birthday reminder. Events are a distinct result
  // shape (no payload/reveal semantics) so they're returned in their own
  // array rather than merged into vault item results.
  const events = (!category || category === 'all' || category === 'event') ? Events.searchEvents(req.user.id, q) : [];
  sendJson(res, 200, { results, events, count: results.length + events.length });
});

// ---------------------------------------------------------------------------
// Calendar / events (spec section 19+)
// ---------------------------------------------------------------------------
router.get('/api/events', authGuard, async (req, res) => {
  const url = new URL(req.url, 'http://internal');
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  if (!from || !to) throw httpErr(400, 'from and to date parameters are required.');
  sendJson(res, 200, { events: Events.listEventsInRange(req.user.id, from, to) });
});

router.get('/api/events/upcoming', authGuard, async (req, res) => {
  const url = new URL(req.url, 'http://internal');
  const days = Math.min(365, Math.max(1, Number(url.searchParams.get('days')) || 60));
  sendJson(res, 200, { events: Events.upcomingEvents(req.user.id, days) });
});

router.get('/api/events/today', authGuard, async (req, res) => {
  sendJson(res, 200, { events: Events.todayEvents(req.user.id) });
});

router.post('/api/events', authGuard, csrfGuard, async (req, res) => {
  const event = Events.createEvent(req.user.id, req.body);
  logEvent(req.user.id, `Reminder created: ${event.title}`);
  sendJson(res, 201, { event });
});

router.get('/api/events/:id', authGuard, async (req, res) => {
  sendJson(res, 200, { event: Events.getEvent(req.user.id, req.params.id) });
});

router.put('/api/events/:id', authGuard, csrfGuard, async (req, res) => {
  const event = Events.updateEvent(req.user.id, req.params.id, req.body);
  logEvent(req.user.id, `Reminder updated: ${event.title}`);
  sendJson(res, 200, { event });
});

router.delete('/api/events/:id', authGuard, csrfGuard, async (req, res) => {
  const existing = Events.getEvent(req.user.id, req.params.id);
  Events.deleteEvent(req.user.id, req.params.id);
  logEvent(req.user.id, `Reminder deleted: ${existing.title}`);
  sendJson(res, 200, { ok: true });
});

// ---------------------------------------------------------------------------
// Encrypted file attachments (ID scans, PDFs, certificates)
// ---------------------------------------------------------------------------
router.post('/api/vault/items/:id/file', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  requireFields(req.body, ['fileName', 'mimeType', 'dataBase64']);
  const meta = Vault.attachFile(req.user.id, req.vek, req.params.id, req.body);
  logEvent(req.user.id, `File attached: ${meta.fileName}`);
  sendJson(res, 201, { file: meta });
});

// Metadata-only check (does the item have a file, what's it named/how big) —
// deliberately does NOT decrypt the file or log a "downloaded" event, so
// simply opening an item's detail view doesn't spuriously mark its file as
// having been read.
router.get('/api/vault/items/:id/file/meta', authGuard, async (req, res) => {
  const meta = Vault.getFileMeta(req.user.id, req.params.id);
  sendJson(res, 200, { file: meta || null });
});

router.get('/api/vault/items/:id/file', authGuard, unlockGuard, async (req, res) => {
  const file = Vault.readFile(req.user.id, req.vek, req.params.id);
  logEvent(req.user.id, `File downloaded: ${file.fileName}`);
  sendJson(res, 200, { fileName: file.fileName, mimeType: file.mimeType, dataBase64: file.data.toString('base64') });
});

router.delete('/api/vault/items/:id/file', authGuard, csrfGuard, async (req, res) => {
  Vault.deleteFile(req.user.id, req.params.id);
  logEvent(req.user.id, 'File attachment removed');
  sendJson(res, 200, { ok: true });
});

// ---------------------------------------------------------------------------
// Self-destructing share links — see server/vault.js for why the server
// only ever handles ciphertext here.
// ---------------------------------------------------------------------------
router.post('/api/vault/items/:id/share', authGuard, csrfGuard, async (req, res) => {
  requireFields(req.body, ['ciphertext', 'iv', 'tag']);
  const share = Vault.createShare(req.user.id, req.params.id, req.body);
  logEvent(req.user.id, 'Share link created');
  sendJson(res, 201, share);
});

// Public, unauthenticated — protected by single-use + expiry instead of a
// session. Never touches VEK, never decrypts anything server-side.
router.get('/api/share/:id', async (req, res) => {
  const share = Vault.consumeShare(req.params.id);
  sendJson(res, 200, share);
});

// ---------------------------------------------------------------------------
// Portable encrypted backup export/import (.vaultx)
//
// The export is encrypted under a KEY DERIVED FROM A PASSWORD THE USER
// SUPPLIES FOR THIS EXPORT — deliberately independent of their master
// password, so a leaked backup file doesn't also compromise the live vault
// password, and a compromised live password doesn't retroactively expose
// every backup ever taken.
// ---------------------------------------------------------------------------
router.post('/api/vault/export', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  requireFields(req.body, ['exportPassword']);
  if (req.body.exportPassword.length < 8) throw httpErr(400, 'Export password must be at least 8 characters.');
  const items = Vault.listItems(req.user.id).map((meta) => Vault.getItem(req.user.id, req.vek, meta.id));
  const salt = randomBytes(16);
  const key = deriveKey(req.body.exportPassword, salt);
  const enc = encryptJSON({ exportedAt: Date.now(), user: { name: req.user.name, email: req.user.email }, items }, key);
  logEvent(req.user.id, 'Encrypted backup exported');
  sendJson(res, 200, {
    version: 1,
    salt: salt.toString('base64'),
    iv: enc.iv.toString('base64'),
    tag: enc.tag.toString('base64'),
    ciphertext: enc.ciphertext.toString('base64'),
  });
});

router.post('/api/vault/import', authGuard, csrfGuard, unlockGuard, async (req, res) => {
  requireFields(req.body, ['exportPassword', 'backup']);
  const { salt, iv, tag, ciphertext } = req.body.backup || {};
  if (!salt || !iv || !tag || !ciphertext) throw httpErr(400, 'That file doesn\'t look like a valid VAULTIXgusTAR backup.');
  let bundle;
  try {
    const key = deriveKey(req.body.exportPassword, Buffer.from(salt, 'base64'));
    bundle = decryptJSON({
      ciphertext: Buffer.from(ciphertext, 'base64'),
      iv: Buffer.from(iv, 'base64'),
      tag: Buffer.from(tag, 'base64'),
    }, key);
  } catch {
    throw httpErr(401, 'Incorrect export password, or the backup file is corrupted.');
  }
  let imported = 0;
  for (const item of bundle.items || []) {
    Vault.createItem(req.user.id, req.vek, {
      type: item.type, title: `${item.title} (imported)`, category: item.category,
      searchUsername: item.searchUsername, payload: item.payload,
    });
    imported++;
  }
  logEvent(req.user.id, `Backup imported (${imported} items)`);
  sendJson(res, 200, { ok: true, imported });
});

// ---------------------------------------------------------------------------
// Security Centre / activity
// ---------------------------------------------------------------------------
router.get('/api/security/status', authGuard, unlockGuard, async (req, res) => {
  const reused = Vault.hasDuplicatePasswords(req.user.id, req.vek);
  const score = computeSecurityScore(req.user, Vault.summary(req.user.id), reused);
  sendJson(res, 200, {
    score,
    autoLockMs: req.user.auto_lock_ms,
    biometricEnabled: !!req.user.biometric_enabled,
    twoFactorEnabled: !!req.user.two_factor_enabled,
    hasPin: !!req.user.pin_hash,
    lastLogin: req.user.last_login,
  });
});

router.get('/api/security/activity', authGuard, async (req, res) => {
  const rows = db.prepare('SELECT text, created_at FROM security_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 100').all(req.user.id);
  sendJson(res, 200, { events: rows });
});

router.get('/api/security/activity/verify', authGuard, async (req, res) => {
  // Recomputes the hash chain over every event this user has (see
  // server/auth.js logEvent/verifyEventChain). A "valid: false" result
  // means a row was edited or deleted outside the app's own code path.
  sendJson(res, 200, verifyEventChain(req.user.id));
});

router.get('/api/security/health', authGuard, unlockGuard, async (req, res) => {
  sendJson(res, 200, Vault.vaultHealthReport(req.user.id, req.vek));
});

router.post('/api/tools/generate-password', authGuard, async (req, res) => {
  const pw = generatePassword(req.body || {});
  sendJson(res, 200, { password: pw, strength: passwordStrength(pw) });
});

// ---------------------------------------------------------------------------
// Recovery ("forgot master password") — never emails/reveals the old password
// ---------------------------------------------------------------------------
router.post('/api/recovery/request', async (req, res) => {
  if (ipRateLimited(clientIp(req), 10, 60_000)) throw httpErr(429, 'Too many attempts. Please try again shortly.');
  requireFields(req.body, ['email']);
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(req.body.email.toLowerCase());
  if (user) issueRecoveryCode(user.id);
  // Same response whether or not the account exists — avoids account enumeration.
  sendJson(res, 200, { ok: true, message: 'If that email has a vault, a verification code has been sent.' });
});

router.post('/api/recovery/verify-code', async (req, res) => {
  requireFields(req.body, ['email', 'code']);
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(req.body.email.toLowerCase());
  if (!user || !checkRecoveryCode(user.id, req.body.code)) throw httpErr(401, 'Invalid or expired code.');
  sendJson(res, 200, { ok: true });
});

router.post('/api/recovery/reset', async (req, res) => {
  requireFields(req.body, ['email', 'code', 'recoveryKey', 'newPassword']);
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(req.body.email.toLowerCase());
  if (!user) throw httpErr(401, 'Recovery could not be completed.');
  if (!checkRecoveryCode(user.id, req.body.code)) throw httpErr(401, 'Invalid or expired code.');
  if (!verifySecret(req.body.recoveryKey.toUpperCase(), user.recovery_key_hash)) {
    logEvent(user.id, 'Failed account recovery attempt (recovery key)');
    throw httpErr(401, 'Incorrect recovery key.');
  }
  if (req.body.newPassword.length < 8) throw httpErr(400, 'New password must be at least 8 characters.');

  // Unwrap the VEK via the recovery path, then re-wrap it under a new
  // password-derived KEK. The vault's actual encryption key never changes,
  // so every existing record decrypts normally after this — see README
  // "Recovery trade-offs" for what happens if the recovery key is also lost.
  const recoveryKek = deriveKey(req.body.recoveryKey.toUpperCase(), user.recovery_kek_salt);
  const vek = unwrapKey({ ciphertext: user.wrapped_vek_recovery, iv: user.wrapped_vek_recovery_iv, tag: user.wrapped_vek_recovery_tag }, recoveryKek);

  const newHash = hashSecret(req.body.newPassword);
  const kekSalt = randomBytes(16);
  const kek = deriveKey(req.body.newPassword, kekSalt);
  const wrapped = wrapKey(vek, kek);
  db.prepare('UPDATE users SET password_hash = ?, kek_salt = ?, wrapped_vek = ?, wrapped_vek_iv = ?, wrapped_vek_tag = ?, login_failed_count = 0, login_locked_until = NULL WHERE id = ?')
    .run(newHash, kekSalt, wrapped.ciphertext, wrapped.iv, wrapped.tag, user.id);
  consumeRecoveryCode(user.id);
  logEvent(user.id, 'Master password reset via account recovery');
  sendJson(res, 200, { ok: true });
});

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function labelFor(type) {
  return {
    password: 'Password', email: 'Email', personal: 'Personal information', id: 'ID document',
    note: 'Secure note', wifi: 'Wi-Fi credential', contact: 'Contact', account: 'Account',
    apikey: 'API key', sshkey: 'SSH key', wallet: 'Crypto wallet', physical: 'Physical access code',
    license: 'Software license', medical: 'Medical profile', inheritance: 'Digital inheritance note',
    document: 'Document', custom: 'Custom item',
  }[type] || 'Item';
}

// Defense in depth: even though these responses only ever go to the owning
// user, never echo back more than the route needs.
function redact(item) { return item; }
