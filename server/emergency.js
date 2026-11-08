// server/emergency.js
//
// Emergency access (spec: digital inheritance). Owner invites a contact and sets
// a waiting period. The contact can request access; the owner can veto during
// the waiting period; if not vetoed, access is released at the deadline.
//
// Key handling: at invite time the owner's vault key is wrapped under a key
// derived from a random secret, which is returned to the owner once to pass to
// the contact. The server keeps only the wrapped key and a hash of the secret.
// Release does not decrypt anything server-side; it only makes the wrapped key
// available to the contact, who can unwrap it with their secret.

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import { httpErr } from './http-utils.js';
import { hashSecret, verifySecret, deriveKey, wrapKey, unwrapKey, randomBytes, randomToken, decryptJSON } from './crypto.js';

export const WAIT_OPTIONS = [7, 14, 30];
const DAY_MS = 24 * 60 * 60 * 1000;

function toPublic(row) {
  return {
    id: row.id,
    contactName: row.contact_name,
    contactEmail: row.contact_email,
    waitDays: row.wait_days,
    status: row.status,
    requestedAt: row.requested_at,
    releaseAt: row.release_at,
    releasedAt: row.released_at,
    createdAt: row.created_at,
  };
}

function ownedRow(ownerId, id) {
  const row = db.prepare('SELECT * FROM emergency_access WHERE id = ? AND owner_id = ?').get(id, ownerId);
  if (!row) throw httpErr(404, 'Emergency contact not found.');
  return row;
}

/** Owner invites a contact. Requires the vault to be unlocked, because the vault key is needed to wrap it. */
export function invite(ownerId, vek, { contactName, contactEmail, waitDays }) {
  const name = String(contactName || '').trim();
  const email = String(contactEmail || '').trim().toLowerCase();
  const days = Number(waitDays);
  if (!name || name.length > 80) throw httpErr(400, 'Enter the contact\'s name (1-80 characters).');
  if (!/^\S+@\S+\.\S+$/.test(email) || email.length > 254) throw httpErr(400, 'Enter a valid contact email.');
  if (!WAIT_OPTIONS.includes(days)) throw httpErr(400, 'Choose a waiting period of 7, 14, or 30 days.');

  const secret = randomToken(24);          // handed to the contact once, never stored
  const kekSalt = randomBytes(16);
  const kek = deriveKey(secret, kekSalt);
  const wrapped = wrapKey(vek, kek);
  const id = randomUUID();
  const now = Date.now();
  db.prepare(`
    INSERT INTO emergency_access (id, owner_id, contact_name, contact_email, wait_days, status, secret_hash,
      kek_salt, wrapped_vek, wrapped_vek_iv, wrapped_vek_tag, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'invited', ?, ?, ?, ?, ?, ?, ?)
  `).run(id, ownerId, name, email, days, hashSecret(secret), kekSalt, wrapped.ciphertext, wrapped.iv, wrapped.tag, now, now);
  return { contact: toPublic(db.prepare('SELECT * FROM emergency_access WHERE id = ?').get(id)), secret };
}

export function listForOwner(ownerId) {
  return db.prepare('SELECT * FROM emergency_access WHERE owner_id = ? ORDER BY created_at DESC').all(ownerId).map(toPublic);
}

/** Contact asks for access. Starts the waiting period. Nothing is released yet. */
export function requestAccess(id, secret) {
  const row = db.prepare('SELECT * FROM emergency_access WHERE id = ?').get(id);
  if (!row || !verifySecret(String(secret || ''), row.secret_hash)) throw httpErr(401, 'That request could not be verified.');
  if (row.status === 'revoked') throw httpErr(403, 'This access has been revoked by the owner.');
  if (row.status === 'released') throw httpErr(409, 'Access has already been released.');
  if (row.status === 'requested') return toPublic(row);
  const now = Date.now();
  db.prepare("UPDATE emergency_access SET status = 'requested', requested_at = ?, release_at = ?, updated_at = ? WHERE id = ?")
    .run(now, now + row.wait_days * DAY_MS, now, id);
  return toPublic(db.prepare('SELECT * FROM emergency_access WHERE id = ?').get(id));
}

/** Owner vetoes a pending request. Only possible while the request is pending. */
export function veto(ownerId, id) {
  const row = ownedRow(ownerId, id);
  if (row.status !== 'requested') throw httpErr(409, 'There is no pending request to veto.');
  db.prepare("UPDATE emergency_access SET status = 'invited', requested_at = NULL, release_at = NULL, updated_at = ? WHERE id = ?").run(Date.now(), id);
  return toPublic(db.prepare('SELECT * FROM emergency_access WHERE id = ?').get(id));
}

/** Owner revokes a contact entirely. Their wrapped key is discarded. */
export function revoke(ownerId, id) {
  ownedRow(ownerId, id);
  db.prepare("UPDATE emergency_access SET status = 'revoked', updated_at = ? WHERE id = ?").run(Date.now(), id);
  return toPublic(db.prepare('SELECT * FROM emergency_access WHERE id = ?').get(id));
}

/** Contact retrieves the wrapped key once access is released. Returns it so the contact can unwrap with their secret. */
export function fetchReleased(id, secret) {
  const row = db.prepare('SELECT * FROM emergency_access WHERE id = ?').get(id);
  if (!row || !verifySecret(String(secret || ''), row.secret_hash)) throw httpErr(401, 'That request could not be verified.');
  if (row.status !== 'released') throw httpErr(403, 'Access has not been released.');
  // SQLite returns BLOBs as Uint8Array, and Uint8Array.toString() does not
  // produce base64. Wrap each in Buffer before encoding, or the bytes are corrupted.
  const b64 = (v) => Buffer.from(v).toString('base64');
  return { kekSalt: b64(row.kek_salt), wrappedVek: b64(row.wrapped_vek), iv: b64(row.wrapped_vek_iv), tag: b64(row.wrapped_vek_tag) };
}

/** Releases every request whose waiting period has passed without a veto. Run on a timer. */
export function releaseDue(now = Date.now()) {
  const result = db.prepare("UPDATE emergency_access SET status = 'released', released_at = ?, updated_at = ? WHERE status = 'requested' AND release_at <= ?").run(now, now, now);
  return result.changes;
}

/**
 * Lets a contact read the owner's vault, but only after release, and only with
 * the contact's own secret. The vault key is unwrapped here with that secret, the
 * owner's items are decrypted, and the result is returned once. Nothing is cached
 * or stored. The secret is never logged.
 */
export function viewReleased(id, secret) {
  const row = db.prepare('SELECT * FROM emergency_access WHERE id = ?').get(id);
  if (!row || !verifySecret(String(secret || ''), row.secret_hash)) throw httpErr(401, 'That request could not be verified.');
  if (row.status !== 'released') throw httpErr(403, 'Access has not been released.');
  let vek;
  try {
    vek = unwrapKey(
      { ciphertext: Buffer.from(row.wrapped_vek), iv: Buffer.from(row.wrapped_vek_iv), tag: Buffer.from(row.wrapped_vek_tag) },
      deriveKey(String(secret), Buffer.from(row.kek_salt)),
    );
  } catch {
    throw httpErr(401, 'That request could not be verified.');
  }
  const items = db.prepare('SELECT id, type, title, category, search_username, payload_ciphertext, payload_iv, payload_tag FROM vault_items WHERE user_id = ? ORDER BY title').all(row.owner_id);
  const out = [];
  for (const it of items) {
    try {
      const payload = decryptJSON({ ciphertext: Buffer.from(it.payload_ciphertext), iv: Buffer.from(it.payload_iv), tag: Buffer.from(it.payload_tag) }, vek);
      out.push({ id: it.id, type: it.type, title: it.title, category: it.category, searchUsername: it.search_username, payload });
    } catch { /* a corrupt row is skipped, never shown half-decrypted */ }
  }
  return { ownerContactName: row.contact_name, items: out };
}

/** Lets the contact see where their request stands, without exposing any vault data. */
export function getStatus(id, secret) {
  const row = db.prepare('SELECT * FROM emergency_access WHERE id = ?').get(id);
  if (!row || !verifySecret(String(secret || ''), row.secret_hash)) throw httpErr(401, 'That access code could not be verified.');
  return { status: row.status, releaseAt: row.release_at, contactName: row.contact_name };
}
