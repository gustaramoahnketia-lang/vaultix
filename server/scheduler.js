// server/scheduler.js
//
// Decides which reminders are due for each user, and delivers each one to that
// user's active devices exactly once. Delivery is injected as a function, so
// the scheduling and duplicate logic can be tested without a real push service.
// The real sender lives in server/push-delivery.js and needs the `web-push`
// package, which is not installed in the development sandbox.

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import { dueReminders } from './events.js';
import { activeSubscriptionsFor, deactivateEndpoint } from './push.js';

// A reminder is only sent within this many minutes of its scheduled moment.
// A reminder that was due hours ago (for example, the server was down) is
// skipped rather than sent late, because a stale "meeting in 5 minutes" is
// worse than none.
export const LATE_SEND_WINDOW_MINUTES = 15;

function alreadySent(triggerKey, userId) {
  return !!db.prepare('SELECT 1 FROM reminder_deliveries WHERE trigger_key = ? AND user_id = ?').get(triggerKey, userId);
}

function markSent(triggerKey, userId) {
  db.prepare('INSERT OR IGNORE INTO reminder_deliveries (trigger_key, user_id, sent_at) VALUES (?, ?, ?)')
    .run(triggerKey, userId, Date.now());
}

/**
 * Runs one scheduling pass for a single user.
 * `send(subscription, payload)` must return a promise resolving to
 * { ok: true } or { ok: false, gone: true|false }. Only successful sends are
 * recorded, so a failed send is retried on the next pass.
 */
export async function runForUser(userId, send, { withinMinutes = LATE_SEND_WINDOW_MINUTES } = {}) {
  const due = dueReminders(userId, withinMinutes);
  const devices = activeSubscriptionsFor(userId);
  const summary = { due: due.length, sent: 0, skippedDuplicate: 0, failed: 0, deactivated: 0 };
  if (devices.length === 0) return summary;

  for (const reminder of due) {
    if (alreadySent(reminder.triggerKey, userId)) { summary.skippedDuplicate++; continue; }
    // The payload carries only the event title and timing, never vault contents.
    const payload = {
      title: 'VAULTIXgusTAR',
      body: `${reminder.title} ${reminder.reminderMinutesBefore === 0 ? 'is now' : `is in ${reminder.reminderMinutesBefore} min`}.`,
      eventId: reminder.id,
      triggerKey: reminder.triggerKey,
    };
    let delivered = 0;
    for (const device of devices) {
      const result = await send(device, payload);
      if (result.ok) { delivered++; summary.sent++; continue; }
      summary.failed++;
      if (result.gone) { deactivateEndpoint(device.endpoint); summary.deactivated++; }
    }
    // Recorded only if at least one device received it. If every device failed,
    // the next pass tries again, rather than marking a reminder as delivered when
    // nothing reached the user.
    if (delivered > 0) markSent(reminder.triggerKey, userId);
  }
  return summary;
}

// Random ids are only used for logging in this module, not for security.
export function newRunId() { return randomUUID(); }
