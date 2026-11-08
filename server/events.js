// server/events.js
//
// Calendar and reminders. Ownership is enforced the same way as
// server/vault.js: every query is scoped to `user_id = ?` bound from the
// authenticated session, never from a client-supplied id.
//
// Recurrence is expanded on read, not stored as materialized rows -- a
// "birthday" is one database row with recurrence='annually'; every place
// that needs actual calendar dates (month view, upcoming list, today's
// events, search) calls expandOccurrences() to compute which real dates
// that row lands on within a given range, fresh, every time. Nothing here
// is ever hardcoded -- "17 days remaining" is always today's date subtracted
// from a freshly computed next occurrence.

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import { httpErr } from './http-utils.js';

export const EVENT_TYPES = ['personal', 'birthday', 'appointment', 'medication', 'water', 'payment', 'security', 'task', 'custom'];
const RECURRENCES = ['none', 'daily', 'weekly', 'monthly', 'annually'];
// Reminder presets, spec section 2 -- every reminder is stored uniformly as
// { minutesBefore }, computed against the event's actual start time (or a
// default of 09:00 if no time was set). "At event time" is minutesBefore=0;
// "Custom" is just any other minute count the user typed in.
export const REMINDER_PRESETS = [0, 5, 15, 30, 60, 120, 1440, 10080];

function toDateOnly(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function parseDateOnly(s) {
  const [y, m, d] = s.split('-').map(Number);
  return new Date(y, m - 1, d);
}
function daysInMonth(year, monthIndex) {
  return new Date(year, monthIndex + 1, 0).getDate();
}
function eventDateTime(dateStr, timeStr) {
  const [y, mo, d] = dateStr.split('-').map(Number);
  const [h, mi] = (timeStr || '09:00').split(':').map(Number);
  return new Date(y, mo - 1, d, h, mi);
}

/**
 * Returns every date (as 'YYYY-MM-DD' strings) this event's recurrence rule
 * lands on within [fromStr, toStr] inclusive. `none` yields at most one date.
 */
export function expandOccurrences(event, fromStr, toStr) {
  const start = parseDateOnly(event.start_date);
  const from = parseDateOnly(fromStr);
  const to = parseDateOnly(toStr);
  const out = [];

  if (event.recurrence === 'none') {
    if (start >= from && start <= to) out.push(toDateOnly(start));
    return out;
  }

  if (event.recurrence === 'daily') {
    const first = start > from ? start : from;
    for (let d = new Date(first); d <= to; d.setDate(d.getDate() + 1)) {
      if (d >= start) out.push(toDateOnly(d));
    }
    return out;
  }

  if (event.recurrence === 'weekly') {
    let d = new Date(start);
    if (d < from) {
      const diffDays = Math.floor((from - d) / 86400000);
      const weeksToAdd = Math.ceil(diffDays / 7);
      d.setDate(d.getDate() + weeksToAdd * 7);
    }
    for (; d <= to; d.setDate(d.getDate() + 7)) {
      if (d >= start) out.push(toDateOnly(d));
    }
    return out;
  }

  if (event.recurrence === 'monthly') {
    const day = start.getDate();
    let year = from.getFullYear(), month = from.getMonth();
    for (;;) {
      const candidate = new Date(year, month, Math.min(day, daysInMonth(year, month)));
      if (candidate > to) break;
      if (candidate >= start && candidate >= from) out.push(toDateOnly(candidate));
      month++;
      if (month > 11) { month = 0; year++; }
    }
    return out;
  }

  if (event.recurrence === 'annually') {
    const month = start.getMonth(), day = start.getDate();
    for (let year = from.getFullYear(); year <= to.getFullYear(); year++) {
      const candidate = new Date(year, month, Math.min(day, daysInMonth(year, month)));
      if (candidate >= start && candidate >= from && candidate <= to) out.push(toDateOnly(candidate));
    }
    return out;
  }

  return out;
}

function parseReminders(json) {
  try {
    const arr = JSON.parse(json || '[]');
    return Array.isArray(arr) ? arr.filter((r) => r && Number.isFinite(r.minutesBefore)) : [];
  } catch { return []; }
}

function sanitizeReminders(input) {
  if (!Array.isArray(input)) return [];
  const seen = new Set();
  const out = [];
  for (const r of input) {
    const minutes = Math.max(0, Math.round(Number(r?.minutesBefore)));
    if (!Number.isFinite(minutes) || seen.has(minutes)) continue;
    seen.add(minutes);
    out.push({ minutesBefore: minutes });
  }
  return out.sort((a, b) => a.minutesBefore - b.minutesBefore);
}

function rowToEvent(row) {
  return {
    id: row.id,
    title: row.title,
    eventType: row.event_type,
    startDate: row.start_date,
    startTime: row.start_time,
    endTime: row.end_time,
    location: row.location,
    description: row.description,
    category: row.category,
    recurrence: row.recurrence,
    reminders: parseReminders(row.reminders),
    completed: !!row.completed,
    timezone: row.timezone,
    linkedItemId: row.linked_item_id,
    notifyEnabled: !!row.notify_enabled,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function createEvent(userId, data) {
  const type = EVENT_TYPES.includes(data.eventType) ? data.eventType : 'personal';
  const recurrence = RECURRENCES.includes(data.recurrence) ? data.recurrence : 'none';
  if (!data.title || !String(data.title).trim()) throw httpErr(400, 'A title is required.');
  if (!data.startDate || !/^\d{4}-\d{2}-\d{2}$/.test(data.startDate)) throw httpErr(400, 'A valid date (YYYY-MM-DD) is required.');
  if (data.linkedItemId) {
    const owned = db.prepare('SELECT id FROM vault_items WHERE id = ? AND user_id = ?').get(data.linkedItemId, userId);
    if (!owned) throw httpErr(404, 'Linked item not found.');
  }
  const id = randomUUID();
  const now = Date.now();
  db.prepare(`
    INSERT INTO events (id, user_id, title, event_type, start_date, start_time, end_time, location, description, category, recurrence, reminders, completed, timezone, linked_item_id, notify_enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
  `).run(
    id, userId, String(data.title).trim(), type, data.startDate, data.startTime || null, data.endTime || null,
    data.location || null, data.description || null, data.category || null, recurrence,
    JSON.stringify(sanitizeReminders(data.reminders)),
    data.timezone || null,
    data.linkedItemId || null, data.notifyEnabled === false ? 0 : 1, now, now,
  );
  return getEvent(userId, id);
}

function fetchOwnedRow(userId, id) {
  const row = db.prepare('SELECT * FROM events WHERE id = ? AND user_id = ?').get(id, userId);
  if (!row || row.user_id !== userId) throw httpErr(404, 'Event not found.');
  return row;
}

export function getEvent(userId, id) {
  return rowToEvent(fetchOwnedRow(userId, id));
}

export function updateEvent(userId, id, data) {
  const row = fetchOwnedRow(userId, id);
  if (data.linkedItemId) {
    const owned = db.prepare('SELECT id FROM vault_items WHERE id = ? AND user_id = ?').get(data.linkedItemId, userId);
    if (!owned) throw httpErr(404, 'Linked item not found.');
  }
  const type = data.eventType !== undefined ? (EVENT_TYPES.includes(data.eventType) ? data.eventType : row.event_type) : row.event_type;
  const recurrence = data.recurrence !== undefined ? (RECURRENCES.includes(data.recurrence) ? data.recurrence : row.recurrence) : row.recurrence;
  db.prepare(`
    UPDATE events SET title = ?, event_type = ?, start_date = ?, start_time = ?, end_time = ?, location = ?, description = ?, category = ?, recurrence = ?, reminders = ?, linked_item_id = ?, notify_enabled = ?, updated_at = ?
    WHERE id = ? AND user_id = ?
  `).run(
    data.title !== undefined ? String(data.title).trim() : row.title,
    type,
    data.startDate !== undefined ? data.startDate : row.start_date,
    data.startTime !== undefined ? data.startTime : row.start_time,
    data.endTime !== undefined ? data.endTime : row.end_time,
    data.location !== undefined ? data.location : row.location,
    data.description !== undefined ? data.description : row.description,
    data.category !== undefined ? data.category : row.category,
    recurrence,
    data.reminders !== undefined ? JSON.stringify(sanitizeReminders(data.reminders)) : row.reminders,
    data.linkedItemId !== undefined ? data.linkedItemId : row.linked_item_id,
    data.notifyEnabled !== undefined ? (data.notifyEnabled ? 1 : 0) : row.notify_enabled,
    Date.now(), id, userId,
  );
  return getEvent(userId, id);
}

export function setCompleted(userId, id, completed) {
  fetchOwnedRow(userId, id);
  db.prepare('UPDATE events SET completed = ?, updated_at = ? WHERE id = ? AND user_id = ?').run(completed ? 1 : 0, Date.now(), id, userId);
  return getEvent(userId, id);
}

export function duplicateEvent(userId, id) {
  const row = fetchOwnedRow(userId, id);
  return createEvent(userId, {
    title: `${row.title} (Copy)`, eventType: row.event_type, startDate: row.start_date, startTime: row.start_time,
    endTime: row.end_time, location: row.location, description: row.description, category: row.category,
    recurrence: row.recurrence, reminders: parseReminders(row.reminders), timezone: row.timezone,
  });
}

export function deleteEvent(userId, id) {
  fetchOwnedRow(userId, id);
  db.prepare('DELETE FROM events WHERE id = ? AND user_id = ?').run(id, userId); // reminders live as embedded JSON on this row -- deleting it cancels them too
}

export function listEventsInRange(userId, fromStr, toStr, { includeCompleted = true } = {}) {
  const rows = db.prepare('SELECT * FROM events WHERE user_id = ?').all(userId);
  const out = [];
  for (const row of rows) {
    if (!includeCompleted && row.completed) continue;
    const occurrences = expandOccurrences(row, fromStr, toStr);
    for (const date of occurrences) out.push({ ...rowToEvent(row), occurrenceDate: date });
  }
  out.sort((a, b) => a.occurrenceDate.localeCompare(b.occurrenceDate));
  return out;
}

export function upcomingEvents(userId, days = 60) {
  const today = new Date();
  const from = toDateOnly(today);
  const to = toDateOnly(new Date(today.getTime() + days * 86400000));
  const occurrences = listEventsInRange(userId, from, to, { includeCompleted: false });
  const seen = new Set();
  const out = [];
  for (const occ of occurrences) {
    if (seen.has(occ.id)) continue;
    seen.add(occ.id);
    const daysRemaining = Math.round((parseDateOnly(occ.occurrenceDate) - parseDateOnly(from)) / 86400000);
    out.push({ ...occ, daysRemaining });
  }
  return out;
}

export function todayEvents(userId) {
  const today = toDateOnly(new Date());
  return listEventsInRange(userId, today, today, { includeCompleted: false });
}

export function completedEvents(userId, limit = 100) {
  const rows = db.prepare('SELECT * FROM events WHERE user_id = ? AND completed = 1 ORDER BY updated_at DESC LIMIT ?').all(userId, limit);
  return rows.map(rowToEvent);
}

/**
 * Server-computed "what's due right now" (spec sections 3, 4, 6) -- the
 * client polls this on an interval instead of reimplementing recurrence +
 * reminder-offset math itself. Correctly handles multiple reminders per
 * event and recurring events (a reminder is evaluated against each
 * upcoming OCCURRENCE's actual date/time, not just the row's base date).
 */
export function dueReminders(userId, withinMinutes = 3) {
  const now = Date.now();
  const from = toDateOnly(new Date());
  const to = toDateOnly(new Date(now + 8 * 86400000)); // 1-week-before reminders need up to 8 days of lookahead
  const occurrences = listEventsInRange(userId, from, to, { includeCompleted: false });
  const due = [];
  for (const occ of occurrences) {
    if (!occ.notifyEnabled) continue;
    const evDateTime = eventDateTime(occ.occurrenceDate, occ.startTime).getTime();
    for (const r of occ.reminders) {
      const triggerAt = evDateTime - r.minutesBefore * 60000;
      if (Math.abs(now - triggerAt) <= withinMinutes * 60000) {
        due.push({ ...occ, reminderMinutesBefore: r.minutesBefore, triggerKey: `${occ.id}|${occ.occurrenceDate}|${r.minutesBefore}` });
      }
    }
  }
  return due;
}

/** Vault-wide search integration -- matches title/description/location/category/type, case-insensitive. */
export function searchEvents(userId, q) {
  const term = q.trim().toLowerCase();
  if (!term) return [];
  const rows = db.prepare('SELECT * FROM events WHERE user_id = ?').all(userId);
  const monthNames = ['january','february','march','april','may','june','july','august','september','october','november','december'];
  return rows.filter((row) => {
    const hay = [row.title, row.description, row.location, row.category, row.event_type].filter(Boolean).join(' ').toLowerCase();
    if (hay.includes(term)) return true;
    const d = parseDateOnly(row.start_date);
    const monthName = monthNames[d.getMonth()];
    if (monthName.includes(term)) return true;
    if (term.includes(monthName) && term.includes(String(d.getDate()))) return true;
    return false;
  }).map(rowToEvent);
}
