// server/push.js
//
// Web Push subscription management. Every function takes userId from the
// authenticated session. A browser's subscription is validated before it is
// stored, and an endpoint that already belongs to a different account is
// refused rather than moved, so a device can never be taken over by another
// user through this API.

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import { httpErr } from './http-utils.js';

const MAX_DEVICES_PER_USER = 10;
// Push-service endpoints are HTTPS URLs. Restricting the length and scheme
// stops the server from being used as a generic outbound-request target.
const MAX_ENDPOINT_LEN = 2048;
const KEY_PATTERN = /^[A-Za-z0-9_\-+/=]{1,512}$/;

function validateSubscription(sub) {
  if (!sub || typeof sub !== 'object') throw httpErr(400, 'Notification registration was incomplete. Please try again.');
  const endpoint = sub.endpoint;
  if (typeof endpoint !== 'string' || endpoint.length === 0 || endpoint.length > MAX_ENDPOINT_LEN) {
    throw httpErr(400, 'Notification registration was incomplete. Please try again.');
  }
  let url;
  try { url = new URL(endpoint); } catch { throw httpErr(400, 'Notification registration was incomplete. Please try again.'); }
  if (url.protocol !== 'https:') throw httpErr(400, 'Notification registration was incomplete. Please try again.');
  const keys = sub.keys || {};
  if (typeof keys.p256dh !== 'string' || !KEY_PATTERN.test(keys.p256dh)) throw httpErr(400, 'Notification registration was incomplete. Please try again.');
  if (typeof keys.auth !== 'string' || !KEY_PATTERN.test(keys.auth)) throw httpErr(400, 'Notification registration was incomplete. Please try again.');
  return { endpoint, p256dh: keys.p256dh, auth: keys.auth };
}

function cleanDeviceName(name) {
  if (typeof name !== 'string') return 'This device';
  const trimmed = name.replace(/[^\w .()-]/g, '').trim().slice(0, 60);
  return trimmed || 'This device';
}

function toPublic(row) {
  return {
    id: row.id,
    deviceName: row.device_name,
    active: !!row.active,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    lastUsedAt: row.last_used_at,
  };
}

export function registerSubscription(userId, body) {
  const { endpoint, p256dh, auth } = validateSubscription(body?.subscription);
  const deviceName = cleanDeviceName(body?.deviceName);
  const now = Date.now();

  const existing = db.prepare('SELECT * FROM push_subscriptions WHERE endpoint = ?').get(endpoint);
  if (existing && existing.user_id !== userId) {
    // Refuse, never move: this device is already registered to another account.
    throw httpErr(409, 'This device is already registered. Remove it from its original account first.');
  }
  if (existing) {
    db.prepare('UPDATE push_subscriptions SET p256dh_key = ?, auth_key = ?, device_name = ?, active = 1, updated_at = ?, last_seen_at = ? WHERE id = ? AND user_id = ?')
      .run(p256dh, auth, deviceName, now, now, existing.id, userId);
    return toPublic(db.prepare('SELECT * FROM push_subscriptions WHERE id = ? AND user_id = ?').get(existing.id, userId));
  }

  const count = db.prepare('SELECT COUNT(*) AS n FROM push_subscriptions WHERE user_id = ? AND active = 1').get(userId).n;
  if (count >= MAX_DEVICES_PER_USER) throw httpErr(400, `You can register up to ${MAX_DEVICES_PER_USER} devices. Remove one to add another.`);

  const id = randomUUID();
  db.prepare(`
    INSERT INTO push_subscriptions (id, user_id, endpoint, p256dh_key, auth_key, device_name, active, created_at, updated_at, last_seen_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
  `).run(id, userId, endpoint, p256dh, auth, deviceName, now, now, now);
  return toPublic(db.prepare('SELECT * FROM push_subscriptions WHERE id = ? AND user_id = ?').get(id, userId));
}

export function listDevices(userId) {
  return db.prepare('SELECT * FROM push_subscriptions WHERE user_id = ? ORDER BY created_at DESC').all(userId).map(toPublic);
}

export function removeDevice(userId, id) {
  const row = db.prepare('SELECT * FROM push_subscriptions WHERE id = ? AND user_id = ?').get(id, userId);
  if (!row) throw httpErr(404, 'Device not found.');
  db.prepare('DELETE FROM push_subscriptions WHERE id = ? AND user_id = ?').run(id, userId);
}

// Called by the delivery code when a push service reports a subscription as
// gone (HTTP 404/410). Deactivating, not just deleting, keeps the record for
// the device list and makes the failure visible to the user.
export function deactivateEndpoint(endpoint) {
  db.prepare('UPDATE push_subscriptions SET active = 0, updated_at = ? WHERE endpoint = ?').run(Date.now(), endpoint);
}

export function activeSubscriptionsFor(userId) {
  return db.prepare('SELECT * FROM push_subscriptions WHERE user_id = ? AND active = 1').all(userId);
}
