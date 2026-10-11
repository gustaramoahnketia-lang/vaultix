// server/active-walk.js
//
// A walking session that survives closing the app, minimizing it, or reopening
// it. The session clock lives on the server, so it keeps running when the app
// is closed. Movement is only recorded from GPS samples the app actually sends.
//
// Two numbers are kept apart on purpose:
//   - session time: wall-clock time since the session started (server clock)
//   - moving time:  time the classifier judged the person to be moving, from
//                   samples received. Standing still does not count, and neither
//                   does any gap with no samples (for example, app fully closed).

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import { httpErr } from './http-utils.js';
import { MAX_ROUTE_POINTS } from './activity.js';

export const STILL_RADIUS_M = 10;        // moving from the anchor by more than this = moving (GPS noise is usually under ~5 m)
export const STILL_AFTER_MS = 30000;     // stays within the radius this long = standing still
export const MAX_GAP_MS = 60000;         // no samples for longer than this: that gap earns no moving time
export const MAX_SPEED_MPS = 10;         // faster than this between fixes is a GPS jump, not movement
export const MAX_SESSION_MS = 12 * 60 * 60 * 1000;
const MAX_BATCH = 200;

const R = 6371000;
function hav(lat1, lng1, lat2, lng2) {
  const t = (d) => (d * Math.PI) / 180;
  const dLat = t(lat2 - lat1), dLng = t(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(t(lat1)) * Math.cos(t(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

export function initialState() {
  return { lastLat: null, lastLng: null, lastT: null, anchorLat: null, anchorLng: null, anchorT: null, moving: false, movingMs: 0, distanceM: 0, points: [] };
}

/**
 * Pure classifier: applies one GPS sample [lat, lng, t] to the state and returns
 * the new state. No database, no clock, so it can be tested with long walks.
 */
export function applySample(st, [lat, lng, t]) {
  const points = st.points.length < MAX_ROUTE_POINTS ? [...st.points, [lat, lng, t]] : st.points;
  if (st.lastT === null) {
    return { ...st, points, lastLat: lat, lastLng: lng, lastT: t, anchorLat: lat, anchorLng: lng, anchorT: t, moving: false };
  }
  const dt = t - st.lastT;
  if (dt <= 0) return st; // out of order or duplicate: ignore, never count backwards
  if (dt > MAX_GAP_MS) {
    // No data for too long (for example, the app was closed). Reset the reference
    // point and credit nothing for the gap.
    return { ...st, points, lastLat: lat, lastLng: lng, lastT: t, anchorLat: lat, anchorLng: lng, anchorT: t, moving: false };
  }
  let anchorLat = st.anchorLat, anchorLng = st.anchorLng, anchorT = st.anchorT;
  let moving = st.moving;
  if (hav(anchorLat, anchorLng, lat, lng) > STILL_RADIUS_M) {
    moving = true; anchorLat = lat; anchorLng = lng; anchorT = t;
  } else if (t - anchorT >= STILL_AFTER_MS) {
    moving = false;
  }
  let movingMs = st.movingMs, distanceM = st.distanceM;
  const seg = hav(st.lastLat, st.lastLng, lat, lng);
  // Credit only when moving on both sides of the interval, and only at a
  // believable speed. Otherwise a transition or a GPS jump would add time.
  if (st.moving && moving && seg / (dt / 1000) <= MAX_SPEED_MPS) {
    movingMs += dt; distanceM += seg;
  }
  return { ...st, points, lastLat: lat, lastLng: lng, lastT: t, anchorLat, anchorLng, anchorT, moving, movingMs, distanceM };
}

function validSample(s, startedAt, now) {
  if (!Array.isArray(s) || s.length !== 3) return false;
  const [lat, lng, t] = s;
  return typeof lat === 'number' && lat >= -90 && lat <= 90
    && typeof lng === 'number' && lng >= -180 && lng <= 180
    && typeof t === 'number' && Number.isFinite(t)
    && t <= now + 60000 && t >= startedAt - 60000; // tolerance for phone clocks that drift a little
}

function rowFor(userId) {
  return db.prepare('SELECT * FROM active_walks WHERE user_id = ?').get(userId);
}

function view(row, now = Date.now()) {
  const st = JSON.parse(row.state);
  return {
    id: row.id,
    startedAt: row.started_at,
    elapsedSeconds: Math.round((now - row.started_at) / 1000),
    movingSeconds: Math.round(st.movingMs / 1000),
    distanceMeters: st.distanceM,
    distanceMiles: st.distanceM / 1609.344,
    status: st.moving ? 'moving' : 'still',
    pointCount: st.points.length,
    lastSampleAt: st.lastT,
  };
}

// Ends the session: saves it to history and removes the active row.
function finish(userId, row, endMs) {
  const st = JSON.parse(row.state);
  const id = randomUUID();
  const sessionSeconds = Math.max(0, Math.round((endMs - row.started_at) / 1000));
  const movingSeconds = Math.round(st.movingMs / 1000);
  db.prepare(`
    INSERT INTO walking_sessions (id, user_id, start_time, end_time, duration_seconds, distance_meters, points, created_at, session_seconds)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, userId, row.started_at, endMs, movingSeconds, st.distanceM, JSON.stringify(st.points), Date.now(), sessionSeconds);
  db.prepare('DELETE FROM active_walks WHERE id = ? AND user_id = ?').run(row.id, userId);
  return id;
}

/** Returns the active session, or null. Ends it automatically if it has run past the 12-hour limit. */
export function getActive(userId, now = Date.now()) {
  const row = rowFor(userId);
  if (!row) return null;
  if (now - row.started_at > MAX_SESSION_MS) {
    finish(userId, row, row.started_at + MAX_SESSION_MS);
    return null;
  }
  return view(row, now);
}

/** Starts a session, or resumes the one already running. Only one active session per account. */
export function startOrResume(userId, now = Date.now()) {
  const existing = getActive(userId, now);
  if (existing) return { active: existing, resumed: true };
  const id = randomUUID();
  db.prepare('INSERT INTO active_walks (id, user_id, started_at, updated_at, state) VALUES (?, ?, ?, ?, ?)')
    .run(id, userId, now, now, JSON.stringify(initialState()));
  return { active: view(rowFor(userId), now), resumed: false };
}

/** Applies a batch of samples in order. Invalid samples are refused as a whole. */
export function addSamples(userId, samples, now = Date.now()) {
  const row = rowFor(userId);
  if (!row) throw httpErr(404, 'There is no active walk. Start one first.');
  if (now - row.started_at > MAX_SESSION_MS) { finish(userId, row, row.started_at + MAX_SESSION_MS); throw httpErr(409, 'This walk reached its 12-hour limit and was saved.'); }
  if (!Array.isArray(samples) || samples.length === 0 || samples.length > MAX_BATCH) throw httpErr(400, `Send between 1 and ${MAX_BATCH} samples at a time.`);
  for (const s of samples) if (!validSample(s, row.started_at, now)) throw httpErr(400, 'A location sample was invalid and was not saved.');
  let st = JSON.parse(row.state);
  for (const s of samples) st = applySample(st, s);
  db.prepare('UPDATE active_walks SET state = ?, updated_at = ? WHERE id = ? AND user_id = ?').run(JSON.stringify(st), now, row.id, userId);
  return view({ ...row, state: JSON.stringify(st) }, now);
}

/** Ends the active session and saves it to history. */
export function stop(userId, now = Date.now()) {
  const row = rowFor(userId);
  if (!row) throw httpErr(404, 'There is no active walk to stop.');
  const sessionId = finish(userId, row, now);
  return sessionId;
}
