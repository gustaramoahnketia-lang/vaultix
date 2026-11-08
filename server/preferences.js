// server/preferences.js
//
// Account-level preferences. Every function takes userId from the server-side
// authenticated session (req.user.id), never from the request body or URL.
// Values are checked against a fixed allowlist before anything is stored.

import { db } from './db.js';
import { httpErr } from './http-utils.js';

export const UPCOMING_WINDOW_OPTIONS = [30, 60, 90, 180, 365];
const DEFAULT_UPCOMING_WINDOW = 60;

export function getPreferences(userId) {
  const row = db.prepare('SELECT * FROM user_preferences WHERE user_id = ?').get(userId);
  return {
    upcomingWindowDays: row ? row.upcoming_window_days : DEFAULT_UPCOMING_WINDOW,
    upcomingWindowOptions: UPCOMING_WINDOW_OPTIONS,
  };
}

export function setUpcomingWindow(userId, days) {
  const n = Number(days);
  if (!Number.isInteger(n) || !UPCOMING_WINDOW_OPTIONS.includes(n)) {
    throw httpErr(400, 'Choose one of the listed upcoming windows.');
  }
  db.prepare(`
    INSERT INTO user_preferences (user_id, upcoming_window_days, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET upcoming_window_days = excluded.upcoming_window_days, updated_at = excluded.updated_at
  `).run(userId, n, Date.now());
  return getPreferences(userId);
}
