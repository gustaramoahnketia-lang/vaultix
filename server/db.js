// server/db.js
//
// Persistence layer. Uses Node's built-in `node:sqlite` (no npm install,
// no network access required — this sandbox has none). Swapping to Postgres
// for production is a matter of replacing this file's DatabaseSync calls
// with a `pg` pool and updating the SQL dialect where noted; the rest of
// the app talks to this module only, never to raw SQL directly.

import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import os from 'node:os';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Test runs (node --test sets NODE_TEST_CONTEXT) get their own temporary folder,
// so they never write into a real vault.
const IS_TEST = !!process.env.NODE_TEST_CONTEXT;
// The default lives in your home folder, NOT inside the project. Replacing or
// re-unzipping the project therefore never deletes your accounts.
const DEFAULT_DIR = IS_TEST
  ? fs.mkdtempSync(path.join(os.tmpdir(), 'vaultix-test-'))
  : path.join(os.homedir(), 'VaultixData');
export const DATA_DIR = process.env.VAULTIX_DATA_DIR || DEFAULT_DIR;
fs.mkdirSync(DATA_DIR, { recursive: true });
export const DB_PATH = process.env.VAULTIX_DB_PATH || path.join(DATA_DIR, 'vaultix.db');

// Older versions kept the database inside the project folder. If that copy exists
// and the new location is empty, move it across once, so nothing is lost.
const LEGACY_DB = path.join(__dirname, '..', 'data', 'vaultix.db');
if (!IS_TEST && !process.env.VAULTIX_DATA_DIR && !process.env.VAULTIX_DB_PATH
    && !fs.existsSync(DB_PATH) && fs.existsSync(LEGACY_DB)) {
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(LEGACY_DB + suffix)) fs.copyFileSync(LEGACY_DB + suffix, DB_PATH + suffix);
  }
  console.log(`[VAULTIXgusTAR] Copied your existing database to ${DB_PATH}`);
}

export const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,

  -- authentication (never the same derivation as encryption keys — see crypto.js)
  password_hash TEXT NOT NULL,

  -- master-password-wrapped Vault Encryption Key
  kek_salt BLOB NOT NULL,
  wrapped_vek BLOB NOT NULL,
  wrapped_vek_iv BLOB NOT NULL,
  wrapped_vek_tag BLOB NOT NULL,

  -- PIN unlock (optional second independent wrap of the same VEK)
  pin_hash TEXT,
  pin_kek_salt BLOB,
  wrapped_vek_pin BLOB,
  wrapped_vek_pin_iv BLOB,
  wrapped_vek_pin_tag BLOB,
  pin_failed_count INTEGER NOT NULL DEFAULT 0,
  pin_locked_until INTEGER,

  -- device/biometric unlock (see README: real Face/Touch ID needs WebAuthn
  -- on a native or browser client; this is the server-side half of that)
  biometric_enabled INTEGER NOT NULL DEFAULT 0,
  device_token_hash TEXT,
  device_kek_salt BLOB,
  wrapped_vek_device BLOB,
  wrapped_vek_device_iv BLOB,
  wrapped_vek_device_tag BLOB,

  two_factor_enabled INTEGER NOT NULL DEFAULT 0,
  auto_lock_ms INTEGER NOT NULL DEFAULT 300000,

  recovery_email TEXT NOT NULL,
  recovery_key_hash TEXT NOT NULL,
  recovery_kek_salt BLOB NOT NULL,
  wrapped_vek_recovery BLOB NOT NULL,
  wrapped_vek_recovery_iv BLOB NOT NULL,
  wrapped_vek_recovery_tag BLOB NOT NULL,

  login_failed_count INTEGER NOT NULL DEFAULT 0,
  login_locked_until INTEGER,

  -- profile picture: encrypted with the same VEK as everything else, so
  -- viewing it requires an unlocked vault just like any other record
  avatar_ciphertext BLOB,
  avatar_iv BLOB,
  avatar_tag BLOB,
  avatar_mime TEXT,

  -- duress ("panic") PIN — see server/auth.js unlockDuress(). Deliberately
  -- NEVER wraps a copy of the VEK. Entering it succeeds but never grants
  -- access to real data; it exists purely as a coercion signal.
  duress_pin_hash TEXT,

  created_at INTEGER NOT NULL,
  last_login INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  device TEXT,
  csrf_secret TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS vault_items (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL,             -- password | email | personal | id | note | wifi | contact | account
  category TEXT,
  title TEXT NOT NULL,            -- non-secret label, e.g. "Google" — searchable in plaintext
  search_username TEXT,           -- explicitly allowed searchable field per spec (username/email)
  payload_ciphertext BLOB NOT NULL, -- AES-256-GCM of the actual sensitive fields (JSON)
  payload_iv BLOB NOT NULL,
  payload_tag BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vault_user ON vault_items(user_id);
CREATE INDEX IF NOT EXISTS idx_vault_user_title ON vault_items(user_id, title);
CREATE INDEX IF NOT EXISTS idx_vault_user_type ON vault_items(user_id, type);

-- One encrypted file per vault item (ID scans, PDFs, certificates). The
-- file's bytes are AES-256-GCM encrypted exactly like any other payload —
-- this table exists separately from vault_items just to keep large BLOBs
-- out of the row you touch on every list/search query.
CREATE TABLE IF NOT EXISTS vault_files (
  id TEXT PRIMARY KEY,
  item_id TEXT NOT NULL REFERENCES vault_items(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  file_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  iv BLOB NOT NULL,
  tag BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_item ON vault_files(item_id);
CREATE INDEX IF NOT EXISTS idx_files_user ON vault_files(user_id);

-- Self-destructing share links. The server only ever stores ciphertext —
-- the AES key lives in the URL fragment the server never receives
-- (fragments aren't sent in HTTP requests). See server/vault.js createShare.
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  item_id TEXT NOT NULL REFERENCES vault_items(id) ON DELETE CASCADE,
  ciphertext BLOB NOT NULL,
  iv BLOB NOT NULL,
  tag BLOB NOT NULL,
  max_uses INTEGER NOT NULL DEFAULT 1,
  use_count INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

-- Calendar / reminders (spec section 19+). Deliberately stored in plaintext
-- columns, not AES-256-GCM encrypted like vault_items' secrets — the same
-- pattern vault_items already uses for its own title/category/searchUsername
-- metadata, and for the same reason: the calendar needs to list/sort/filter
-- by date without decrypting every row on every dashboard load. Ownership
-- (user_id) is still enforced on every query exactly like everywhere else in
-- this file. If an event is linked to a vault entry (linked_item_id), the
-- entry's own encrypted secrets are still only reachable through the normal
-- unlock-gated vault item endpoints — linking never exposes vault contents
-- through the calendar.
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  event_type TEXT NOT NULL DEFAULT 'personal', -- personal | birthday | appointment | medication | water | payment | security | task | custom
  start_date TEXT NOT NULL,   -- 'YYYY-MM-DD'
  start_time TEXT,            -- 'HH:MM', optional
  end_time TEXT,
  location TEXT,
  description TEXT,
  category TEXT,
  recurrence TEXT NOT NULL DEFAULT 'none', -- none | daily | weekly | monthly | annually
  reminders TEXT NOT NULL DEFAULT '[]',    -- JSON: [{minutesBefore}] -- see server/events.js
  completed INTEGER NOT NULL DEFAULT 0,
  timezone TEXT,               -- IANA name captured at creation, informational -- see README "Timezone support"
  linked_item_id TEXT REFERENCES vault_items(id) ON DELETE SET NULL,
  notify_enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_user_date ON events(user_id, start_date);

-- GPS walking sessions (spec section 19) -- the one piece of "activity
-- tracking" that's actually possible from a web browser (via the real
-- Geolocation API, explicitly user-started). Distance is recomputed
-- server-side from the raw points, never trusted from the client, so a
-- tampered request can't claim an impossible distance.
CREATE TABLE IF NOT EXISTS walking_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  start_time INTEGER NOT NULL,
  end_time INTEGER NOT NULL,
  duration_seconds INTEGER NOT NULL,
  distance_meters REAL NOT NULL,
  points TEXT NOT NULL DEFAULT '[]', -- JSON: [[lat,lng,timestamp], ...] -- this session's route only
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_walking_user_time ON walking_sessions(user_id, start_time);

-- The one walk in progress for an account. The session clock lives here, so it
-- survives closing or minimizing the app. state holds the classifier's values.
CREATE TABLE IF NOT EXISTS active_walks (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  started_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  state TEXT NOT NULL
);

-- Account-level preferences (one row per user). Stored server-side so a
-- preference follows the account to every device, instead of living in one
-- browser's localStorage. Only fields the server validates are accepted.
-- One row per registered browser/device for Web Push. The endpoint is the
-- push service URL the browser gave us; p256dh and auth_key are the public
-- encryption keys the browser supplied. None of these are secrets, but they
-- are personal device identifiers, so they are only ever returned to the
-- owning user. The VAPID private key is NOT stored here -- it lives in an
-- environment variable on the server only.
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh_key TEXT NOT NULL,
  auth_key TEXT NOT NULL,
  device_name TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_used_at INTEGER,
  last_seen_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_push_user ON push_subscriptions(user_id, active);

-- Records every reminder that has been sent, keyed by the exact occurrence
-- and offset. The primary key is what stops the same reminder being delivered
-- twice, even if the scheduler runs twice or the server restarts mid-run.
CREATE TABLE IF NOT EXISTS reminder_deliveries (
  trigger_key TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sent_at INTEGER NOT NULL,
  PRIMARY KEY (trigger_key, user_id)
);

-- Emergency access. The owner designates a contact and a waiting period. The
-- vault key is wrapped under a key derived from a secret generated for the
-- contact; the server never stores that secret, only the wrapped key and a hash
-- used to check it. Status moves: invited -> requested -> released | revoked.
CREATE TABLE IF NOT EXISTS emergency_access (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_name TEXT NOT NULL,
  contact_email TEXT NOT NULL,
  wait_days INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'invited',
  secret_hash TEXT NOT NULL,
  kek_salt BLOB NOT NULL,
  wrapped_vek BLOB NOT NULL,
  wrapped_vek_iv BLOB NOT NULL,
  wrapped_vek_tag BLOB NOT NULL,
  requested_at INTEGER,
  release_at INTEGER,
  released_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ea_owner ON emergency_access(owner_id);

CREATE TABLE IF NOT EXISTS user_preferences (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  upcoming_window_days INTEGER NOT NULL DEFAULT 60,
  updated_at INTEGER NOT NULL
);

-- Personal activity goals (spec section 24/53). One row per user. The goal
-- is the user's own target, never a recommendation: there is no default
-- target and no "healthy" number. Progress is never stored here; it is
-- computed on read from walking_sessions, so it cannot drift from the data.
CREATE TABLE IF NOT EXISTS activity_goals (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  daily_distance_miles REAL,        -- NULL = no distance goal
  daily_walk_minutes INTEGER,       -- NULL = no time goal
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,             -- human-readable only; NEVER a secret value
  prev_hash TEXT NOT NULL,        -- hash-chain: see server/auth.js logEvent
  hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_user ON security_events(user_id, created_at DESC);
`;

db.exec(SCHEMA);
// Migration for databases created before session time was recorded separately.
// Adding a column that already exists throws, which is expected and ignored.
try { db.exec('ALTER TABLE walking_sessions ADD COLUMN session_seconds INTEGER'); } catch { /* already present */ }

export function resetDatabaseForTests() {
  db.exec('DELETE FROM shares; DELETE FROM events; DELETE FROM walking_sessions; DELETE FROM active_walks; DELETE FROM activity_goals; DELETE FROM user_preferences; DELETE FROM emergency_access; DELETE FROM push_subscriptions; DELETE FROM reminder_deliveries; DELETE FROM vault_files; DELETE FROM security_events; DELETE FROM vault_items; DELETE FROM sessions; DELETE FROM users;');
}

/**
 * Keeps one copy of the database per day for the last 14 days, in
 * <data folder>/backups. Called once at server start, never during tests.
 */
export function backupIfDue() {
  if (IS_TEST) return;
  const dir = path.join(DATA_DIR, 'backups');
  fs.mkdirSync(dir, { recursive: true });
  const today = new Date().toISOString().slice(0, 10);
  const target = path.join(dir, `vaultix-${today}.db`);
  try {
    if (!fs.existsSync(target)) {
      db.exec('PRAGMA wal_checkpoint(FULL)');
      fs.copyFileSync(DB_PATH, target);
    }
    const copies = fs.readdirSync(dir).filter((f) => /^vaultix-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort();
    for (const f of copies.slice(0, -14)) fs.rmSync(path.join(dir, f), { force: true });
  } catch (err) {
    console.error('[VAULTIXgusTAR] Backup skipped:', err.message);
  }
}
