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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.VAULTIX_DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = process.env.VAULTIX_DB_PATH || path.join(DATA_DIR, 'vaultix.db');

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
  event_type TEXT NOT NULL DEFAULT 'general', -- birthday | expiry | medication | water | general
  start_date TEXT NOT NULL,   -- 'YYYY-MM-DD'
  start_time TEXT,            -- 'HH:MM', optional
  end_time TEXT,
  location TEXT,
  description TEXT,
  category TEXT,
  recurrence TEXT NOT NULL DEFAULT 'none', -- none | daily | weekly | monthly | annually
  reminders TEXT NOT NULL DEFAULT '[]',    -- JSON: [{daysBefore, time}]
  linked_item_id TEXT REFERENCES vault_items(id) ON DELETE SET NULL,
  notify_enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_user_date ON events(user_id, start_date);

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

export function resetDatabaseForTests() {
  db.exec('DELETE FROM shares; DELETE FROM events; DELETE FROM vault_files; DELETE FROM security_events; DELETE FROM vault_items; DELETE FROM sessions; DELETE FROM users;');
}
