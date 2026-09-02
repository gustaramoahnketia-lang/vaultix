// server/vault.js
//
// USER ISOLATION LIVES HERE.
//
// Every single query in this file includes `user_id = ?` bound to the
// authenticated caller — never to a client-supplied id. getItem() re-checks
// ownership even though the SQL already filtered by it, specifically so
// that a future refactor which forgets the WHERE clause still fails closed
// instead of silently returning someone else's record. This is exactly the
// property tests/isolation.test.js exists to pin down.

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import { encryptJSON, decryptJSON, encryptRaw, decryptRaw } from './crypto.js';
import { httpErr } from './http-utils.js';

const ALLOWED_TYPES = [
  'password', 'email', 'personal', 'id', 'note', 'wifi', 'contact', 'account',
  // Added for the developer/crypto/physical/medical/estate expansion:
  'apikey',      // cloud & service API keys/secrets
  'sshkey',      // SSH private keys, passphrases, host/port
  'wallet',      // crypto wallet seed phrases, private keys, addresses
  'physical',    // door PINs, safe combinations, alarm codes, gate remotes
  'license',     // software license/serial/activation keys
  'medical',     // blood type, conditions, medications, emergency contacts
  'inheritance', // digital-estate / "in case of emergency" instructions
  'document',    // metadata for an attached encrypted file — see vault_files
  'custom',      // fully user-defined field names/values — payload: { fields: [{name,value,sensitive}], notes }
];

function encryptPayload(payload, vek) {
  return encryptJSON(payload, vek);
}

function rowToSummary(row) {
  return {
    id: row.id,
    type: row.type,
    category: row.category,
    title: row.title,
    searchUsername: row.search_username,
    updatedAt: row.updated_at,
    createdAt: row.created_at,
  };
}

export function createItem(userId, vek, { type, title, category, searchUsername, payload }) {
  if (!ALLOWED_TYPES.includes(type)) throw httpErr(400, 'Unknown information type.');
  if (!title || typeof title !== 'string') throw httpErr(400, 'A title is required.');
  const id = randomUUID();
  const now = Date.now();
  const enc = encryptPayload(payload || {}, vek);
  db.prepare(`
    INSERT INTO vault_items (id, user_id, type, category, title, search_username, payload_ciphertext, payload_iv, payload_tag, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, userId, type, category || null, title.trim(), (searchUsername || '').trim() || null, enc.ciphertext, enc.iv, enc.tag, now, now);
  return getItem(userId, vek, id);
}

function fetchOwnedRow(userId, id) {
  const row = db.prepare('SELECT * FROM vault_items WHERE id = ? AND user_id = ?').get(id, userId);
  if (!row) throw httpErr(404, 'Item not found.');
  // Belt-and-braces ownership re-check (see file header) — must always be true here.
  if (row.user_id !== userId) throw httpErr(404, 'Item not found.');
  return row;
}

export function getItem(userId, vek, id) {
  const row = fetchOwnedRow(userId, id);
  const payload = decryptJSON({ ciphertext: row.payload_ciphertext, iv: row.payload_iv, tag: row.payload_tag }, vek);
  return { ...rowToSummary(row), payload };
}

export function listItems(userId, { type } = {}) {
  const rows = type
    ? db.prepare('SELECT * FROM vault_items WHERE user_id = ? AND type = ? ORDER BY updated_at DESC').all(userId, type)
    : db.prepare('SELECT * FROM vault_items WHERE user_id = ? ORDER BY updated_at DESC').all(userId);
  return rows.map(rowToSummary);
}

export function updateItem(userId, vek, id, { title, category, searchUsername, payload }) {
  const row = fetchOwnedRow(userId, id);
  const merged = payload === undefined ? decryptJSON({ ciphertext: row.payload_ciphertext, iv: row.payload_iv, tag: row.payload_tag }, vek) : payload;
  const enc = encryptPayload(merged, vek);
  db.prepare(`
    UPDATE vault_items SET title = ?, category = ?, search_username = ?, payload_ciphertext = ?, payload_iv = ?, payload_tag = ?, updated_at = ?
    WHERE id = ? AND user_id = ?
  `).run(
    title !== undefined ? title.trim() : row.title,
    category !== undefined ? category : row.category,
    searchUsername !== undefined ? searchUsername : row.search_username,
    enc.ciphertext, enc.iv, enc.tag, Date.now(), id, userId,
  );
  return getItem(userId, vek, id);
}

export function deleteItem(userId, id) {
  fetchOwnedRow(userId, id);
  db.prepare('DELETE FROM vault_items WHERE id = ? AND user_id = ?').run(id, userId);
}

export function summary(userId) {
  const rows = db.prepare('SELECT type, COUNT(*) as n FROM vault_items WHERE user_id = ? GROUP BY type').all(userId);
  const counts = Object.fromEntries(rows.map((r) => [r.type, r.n]));
  return {
    passwords: counts.password || 0,
    emails: counts.email || 0,
    personal: counts.personal || 0,
    notes: counts.note || 0,
    ids: counts.id || 0,
    wifi: counts.wifi || 0,
    contacts: counts.contact || 0,
    accounts: counts.account || 0,
    apikeys: counts.apikey || 0,
    sshkeys: counts.sshkey || 0,
    wallets: counts.wallet || 0,
    physical: counts.physical || 0,
    licenses: counts.license || 0,
    medical: counts.medical || 0,
    inheritance: counts.inheritance || 0,
    documents: counts.document || 0,
    custom: counts.custom || 0,
  };
}

/**
 * Secure search: matches ONLY against non-secret, plaintext metadata
 * (title, category, and the explicitly-searchable username/email field) —
 * never against decrypted secret payloads. See README "Search architecture"
 * for why the encrypted content itself is not searched.
 */
// Field names treated as sensitive by default (mirrors the client's
// SENSITIVE_KEYS in public/app.js) — their VALUES are never included in a
// search-result preview, even though the field still counts as a match.
// A custom field can also mark itself sensitive explicitly (see
// flattenFields below) regardless of its name.
const SENSITIVE_FIELD_NAMES = new Set([
  'password', 'secretkey', 'privatekey', 'seedphrase', 'passphrase', 'code',
  'policynumber', 'licensekey', 'exchangeapikey',
]);

// Built-in item types store abbreviated JSON keys ('dob', 'fullName') but
// users search by the human-readable label they actually see on screen
// ("Date of Birth", "Full Name") — mirrors the field labels in
// public/app.js's PERSONAL_FIELDS / FIELD_CONFIGS. Without this map,
// searching the exact phrase "Date of Birth" would fail to match a field
// whose JSON key is just "dob", even though the value search would still
// work. A 'custom' item's field name IS already the user's own label, so
// this map only matters for the fixed built-in types.
const FIELD_LABELS = {
  fullname: 'Full Name', dob: 'Date of Birth', phone: 'Phone Number', email: 'Email',
  address: 'Address', occupation: 'Occupation', emergencycontact: 'Emergency Contact',
  network: 'Network Name', password: 'Password', notes: 'Notes', website: 'Website',
  username: 'Username', service: 'Service', keyid: 'Key ID / Access Key', secretkey: 'Secret Key',
  environment: 'Environment', host: 'Host', port: 'Port', privatekey: 'Private Key',
  passphrase: 'Passphrase', seedphrase: 'Seed Phrase', exchangeapikey: 'Exchange API Key',
  location: 'Location', code: 'Code / PIN', software: 'Software', licensekey: 'License Key',
  edition: 'Edition', bloodtype: 'Blood Type', conditions: 'Conditions', medications: 'Medications',
  allergies: 'Allergies', emergencydoctor: 'Emergency Doctor', doctorphone: 'Doctor Phone',
  insuranceprovider: 'Insurance Provider', policynumber: 'Policy Number', instructions: 'Instructions',
  description: 'Description',
};

/** Turns any item payload into a flat list of {name, label, value, sensitive} to search over. */
// Custom fields let the user mark sensitivity themselves, but that's not
// trusted as the ONLY safeguard — a field a user names "Password" or "PIN"
// is treated as sensitive regardless of whether they remembered to check
// the box. This is a floor, not a ceiling: it can only turn sensitivity ON
// (defense in depth), never override an explicit `sensitive: true` back to
// false.
const AUTO_SENSITIVE_NAME_RE = /password|passphrase|\bpin\b|\bcvv\b|\bssn\b|secret|private\s*key|seed\s*phrase|license\s*key/i;

function flattenFields(payload) {
  if (!payload || typeof payload !== 'object') return [];
  if (Array.isArray(payload.fields)) {
    // 'custom' type: the user's own field name already IS the label they'd search for.
    const out = payload.fields
      .filter((f) => f && (f.name || f.value))
      .map((f) => ({
        name: String(f.name || ''), label: String(f.name || ''), value: String(f.value ?? ''),
        sensitive: !!f.sensitive || AUTO_SENSITIVE_NAME_RE.test(String(f.name || '')),
      }));
    if (payload.notes) out.push({ name: 'notes', label: 'Notes', value: String(payload.notes), sensitive: false });
    return out;
  }
  return Object.entries(payload)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => ({
      name: k,
      label: FIELD_LABELS[k.toLowerCase()] || k,
      value: String(v),
      sensitive: SENSITIVE_FIELD_NAMES.has(k.toLowerCase()) || AUTO_SENSITIVE_NAME_RE.test(k),
    }));
}

function normalize(s) {
  // Case-insensitive, and tolerant of the punctuation/whitespace variation
  // real user queries have — "15/05/2000" vs "15-05-2000", "Date of Birth"
  // vs "date-of-birth", extra spaces, etc.
  return String(s ?? '').toLowerCase().trim().replace(/\s+/g, ' ');
}
function normalizeLoose(s) {
  return normalize(s).replace(/[\s\-_/.,]+/g, '');
}

/**
 * Real vault-wide content search. Requires the caller's own unlocked VEK —
 * this decrypts each of THIS USER's OWN items (never another user's; the
 * SQL below is scoped by user_id exactly like every other query in this
 * file) to search field names and values, not just the title. That's a
 * deliberate trade-off documented in README "Search architecture v2": for a
 * personal vault's scale (tens to low hundreds of items), decrypting the
 * caller's own records on every search is cheap and correct; it is not the
 * same as building a searchable index of ciphertext, and it never touches
 * any other user's data.
 *
 * Sensitive field values (passwords, PINs, private keys, etc.) are matched
 * against but their VALUE is never included in the response — only that a
 * sensitive field matched, per spec section 11 ("do not expose sensitive
 * password/PIN values directly in search-result previews").
 */
export function searchItems(userId, vek, { q = '', category } = {}) {
  const queryNorm = normalize(q);
  const queryLoose = normalizeLoose(q);
  if (!queryNorm) return [];

  const rows = category && category !== 'all'
    ? db.prepare('SELECT * FROM vault_items WHERE user_id = ? AND type = ? ORDER BY updated_at DESC LIMIT 500').all(userId, category)
    : db.prepare('SELECT * FROM vault_items WHERE user_id = ? ORDER BY updated_at DESC LIMIT 500').all(userId);

  const results = [];
  for (const row of rows) {
    const titleNorm = normalize(row.title);
    const catNorm = normalize(row.category);
    const userNorm = normalize(row.search_username);

    // Rank 0: title/heading — the most important match, per spec section 2.
    if (titleNorm.includes(queryNorm) || normalizeLoose(row.title).includes(queryLoose)) {
      results.push({ ...rowToSummary(row), rank: 0, matchedIn: 'heading', matchedField: null, matchedExcerpt: null });
      continue;
    }
    if (userNorm && userNorm.includes(queryNorm)) {
      results.push({ ...rowToSummary(row), rank: 1, matchedIn: 'field', matchedField: 'Username/Email', matchedExcerpt: row.search_username });
      continue;
    }
    if (catNorm && catNorm.includes(queryNorm)) {
      results.push({ ...rowToSummary(row), rank: 4, matchedIn: 'category', matchedField: 'Category', matchedExcerpt: row.category });
      continue;
    }

    // Rank 2/3: decrypt and scan actual field names + values. This is the
    // fix for the core bug — "Date of Birth: 15/05/2000" is now findable by
    // searching "birth", "date of birth", or "15/05/2000".
    let payload;
    try {
      payload = decryptJSON({ ciphertext: row.payload_ciphertext, iv: row.payload_iv, tag: row.payload_tag }, vek);
    } catch { continue; } // tampered/corrupt row — exclude rather than crash the whole search
    const fields = flattenFields(payload);

    let matched = null;
    for (const f of fields) {
      const nameNorm = normalize(f.name);
      const labelNorm = normalize(f.label);
      const valueNorm = normalize(f.value);
      const valueLoose = normalizeLoose(f.value);
      if (nameNorm.includes(queryNorm) || labelNorm.includes(queryNorm)) {
        matched = { rank: 3, matchedIn: 'field-name', matchedField: f.label, sensitive: f.sensitive, excerpt: f.sensitive ? null : f.value };
        break;
      }
      if (valueNorm.includes(queryNorm) || (queryLoose.length >= 3 && valueLoose.includes(queryLoose))) {
        matched = { rank: 2, matchedIn: 'field-value', matchedField: f.label, sensitive: f.sensitive, excerpt: f.sensitive ? null : f.value };
        break;
      }
    }
    if (matched) {
      results.push({
        ...rowToSummary(row), rank: matched.rank, matchedIn: matched.matchedIn,
        matchedField: matched.matchedField,
        matchedExcerpt: matched.sensitive ? null : truncate(matched.excerpt, 80),
        matchedSensitive: matched.sensitive,
      });
    }
  }

  results.sort((a, b) => a.rank - b.rank || b.updatedAt - a.updatedAt);
  return results.slice(0, 50);
}

function truncate(s, n) {
  if (!s) return s;
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

export function hasDuplicatePasswords(userId, vek) {
  const rows = db.prepare("SELECT payload_ciphertext, payload_iv, payload_tag FROM vault_items WHERE user_id = ? AND type = 'password'").all(userId);
  const seen = new Set();
  for (const row of rows) {
    try {
      const payload = decryptJSON({ ciphertext: row.payload_ciphertext, iv: row.payload_iv, tag: row.payload_tag }, vek);
      if (payload.password) {
        if (seen.has(payload.password)) return true;
        seen.add(payload.password);
      }
    } catch { /* tampered/corrupt row — ignore for scoring purposes */ }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Vault Health Scoring — a fully offline/local report over the caller's OWN
// decrypted items (never sent anywhere, never touches a third party). This
// is distinct from the HIBP breach check, which the frontend runs entirely
// client-side against a real password the user has just revealed — see
// public/app.js `checkBreach()` and README "Breach monitoring" for why that
// one can't be implemented (or meaningfully tested) from this server.
// ---------------------------------------------------------------------------
const WEAK_WIFI_PATTERNS = [/^\d{8}$/, /^(12345678|password|qwertyui|11111111|00000000)$/i];
const OLD_PASSWORD_MS = 180 * 24 * 60 * 60 * 1000; // 180 days

export function vaultHealthReport(userId, vek) {
  const rows = db.prepare("SELECT * FROM vault_items WHERE user_id = ? AND type IN ('password','wifi')").all(userId);
  const seenPasswords = new Map(); // password -> [titles]
  const findings = [];
  let weakCount = 0, oldCount = 0, reusedCount = 0, defaultWifiCount = 0;

  for (const row of rows) {
    let payload;
    try {
      payload = decryptJSON({ ciphertext: row.payload_ciphertext, iv: row.payload_iv, tag: row.payload_tag }, vek);
    } catch { continue; }
    const pw = payload.password;
    if (!pw) continue;
    const issues = [];

    if (pw.length < 10 || !/[0-9]/.test(pw) || !/[A-Za-z]/.test(pw) || pw === pw.toLowerCase() || pw === pw.toUpperCase()) {
      issues.push('weak'); weakCount++;
    }
    if (row.updated_at < Date.now() - OLD_PASSWORD_MS) {
      issues.push('old'); oldCount++;
    }
    if (row.type === 'wifi' && WEAK_WIFI_PATTERNS.some((re) => re.test(pw))) {
      issues.push('default-looking-wifi-key'); defaultWifiCount++;
    }
    if (seenPasswords.has(pw)) {
      issues.push('reused');
      reusedCount++;
      const first = seenPasswords.get(pw);
      if (!first.issues.includes('reused')) { first.issues.push('reused'); reusedCount++; }
    } else {
      seenPasswords.set(pw, { id: row.id, title: row.title, issues });
    }
    if (issues.length) findings.push({ id: row.id, title: row.title, type: row.type, issues });
  }

  return {
    itemsChecked: rows.length,
    weakCount, oldCount, reusedCount, defaultWifiCount,
    findings: findings.filter((f, i, arr) => arr.findIndex((x) => x.id === f.id) === i),
  };
}

// ---------------------------------------------------------------------------
// Encrypted file attachments (ID scans, PDFs, certificates)
// ---------------------------------------------------------------------------
const MAX_FILE_BYTES = 6 * 1024 * 1024; // 6MB — see README for why this is a JSON/base64 upload, not multipart
const ALLOWED_MIME = ['application/pdf', 'image/png', 'image/jpeg', 'image/webp'];

export function attachFile(userId, vek, itemId, { fileName, mimeType, dataBase64 }) {
  fetchOwnedRow(userId, itemId); // ownership check on the parent item
  if (!ALLOWED_MIME.includes(mimeType)) throw httpErr(400, 'Unsupported file type. Allowed: PDF, PNG, JPEG, WEBP.');
  const raw = Buffer.from(dataBase64, 'base64');
  if (raw.length === 0) throw httpErr(400, 'Empty file.');
  if (raw.length > MAX_FILE_BYTES) throw httpErr(413, 'File is too large (6MB limit).');
  const enc = encryptRaw(raw, vek);
  const id = randomUUID();
  db.prepare(`
    INSERT INTO vault_files (id, item_id, user_id, file_name, mime_type, size_bytes, ciphertext, iv, tag, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, itemId, userId, (fileName || 'file').slice(0, 200), mimeType, raw.length, enc.ciphertext, enc.iv, enc.tag, Date.now());
  return { id, fileName, mimeType, sizeBytes: raw.length };
}

export function getFileMeta(userId, itemId) {
  fetchOwnedRow(userId, itemId);
  return db.prepare('SELECT id, file_name, mime_type, size_bytes, created_at FROM vault_files WHERE item_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 1').get(itemId, userId);
}

export function readFile(userId, vek, itemId) {
  fetchOwnedRow(userId, itemId);
  const row = db.prepare('SELECT * FROM vault_files WHERE item_id = ? AND user_id = ? ORDER BY created_at DESC LIMIT 1').get(itemId, userId);
  if (!row) throw httpErr(404, 'No file attached to this item.');
  const raw = decryptRaw({ ciphertext: row.ciphertext, iv: row.iv, tag: row.tag }, vek);
  return { fileName: row.file_name, mimeType: row.mime_type, data: raw };
}

export function deleteFile(userId, itemId) {
  fetchOwnedRow(userId, itemId);
  db.prepare('DELETE FROM vault_files WHERE item_id = ? AND user_id = ?').run(itemId, userId);
}

// ---------------------------------------------------------------------------
// Self-destructing share links
//
// The server stores ciphertext only. The frontend generates a random
// ephemeral AES key client-side, encrypts the already-decrypted item
// payload with it, and sends only the ciphertext here — never the key. The
// key is appended to the resulting URL as a fragment (`#key=...`), which
// browsers never transmit in the HTTP request, so it never reaches this
// server or its logs. See public/app.js `createShareLink`.
// ---------------------------------------------------------------------------
export function createShare(userId, itemId, { ciphertext, iv, tag, maxUses, ttlMs }) {
  fetchOwnedRow(userId, itemId);
  const id = randomUUID();
  const now = Date.now();
  const uses = Math.min(Math.max(1, Number(maxUses) || 1), 10);
  const ttl = Math.min(Math.max(60_000, Number(ttlMs) || 3_600_000), 7 * 24 * 60 * 60 * 1000); // 1min..7d
  db.prepare(`
    INSERT INTO shares (id, user_id, item_id, ciphertext, iv, tag, max_uses, use_count, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
  `).run(id, userId, itemId, Buffer.from(ciphertext, 'base64'), Buffer.from(iv, 'base64'), Buffer.from(tag, 'base64'), uses, now + ttl, now);
  return { id, expiresAt: now + ttl, maxUses: uses };
}

/** Public, unauthenticated — but single-use/expiring and never decrypts anything server-side. */
export function consumeShare(id) {
  const row = db.prepare('SELECT * FROM shares WHERE id = ?').get(id);
  if (!row) throw httpErr(404, 'This link is invalid or has already been used.');
  if (Date.now() > row.expires_at || row.use_count >= row.max_uses) {
    db.prepare('DELETE FROM shares WHERE id = ?').run(id);
    throw httpErr(410, 'This link has expired or reached its use limit.');
  }
  db.prepare('UPDATE shares SET use_count = use_count + 1 WHERE id = ?').run(id);
  if (row.use_count + 1 >= row.max_uses) {
    // Self-destruct: ciphertext is gone from the DB the moment it's been
    // read the agreed number of times, not just "hidden".
    db.prepare('DELETE FROM shares WHERE id = ?').run(id);
  }
  return {
    ciphertext: row.ciphertext.toString('base64'),
    iv: row.iv.toString('base64'),
    tag: row.tag.toString('base64'),
  };
}
