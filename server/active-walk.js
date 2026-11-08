// server/active-walk.js
//
// A walk that survives closing or minimizing the app. The session clock lives on
// the server. Movement comes from server/movement.js, which combines GPS (with its
// accuracy) and phone motion into WALKING / STATIONARY / MOVING_OTHER / UNCERTAIN.
//
// Two clocks are kept apart on purpose:
//   - session time: wall-clock time since the walk started (server clock)
//   - walking time: time confirmed as walking from motion evidence
// A stationary period never stops the session clock.

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import { httpErr } from './http-utils.js';
import {
  initialState, normalize, applyGps, applyMotion, movementView,
  BASE_RADIUS_M, GPS_STILL_AFTER_MS, MAX_GAP_MS, MAX_SPEED_MPS,
} from './movement.js';
import { turnSummary } from './route.js';

// Kept under the old names, so existing code and tests keep working.
export const STILL_RADIUS_M = BASE_RADIUS_M;
export const STILL_AFTER_MS = GPS_STILL_AFTER_MS;
export { MAX_GAP_MS, MAX_SPEED_MPS, initialState };

export const MAX_SESSION_MS = 12 * 60 * 60 * 1000;
const MAX_BATCH = 200;
const MAX_MOTION_BATCH = 300;
const TIME_TOLERANCE_MS = 60000;

/** Applies one GPS sample [lat, lng, t, accuracy?] to the movement state. */
export function applySample(st, sample) {
  return applyGps(st, sample);
}

function validSample(s, startedAt, now) {
  if (!Array.isArray(s) || (s.length !== 3 && s.length !== 4)) return false;
  const [lat, lng, t] = s;
  const accOk = s.length === 3 || (typeof s[3] === 'number' && Number.isFinite(s[3]) && s[3] >= 0 && s[3] <= 10000);
  return accOk
    && typeof lat === 'number' && lat >= -90 && lat <= 90
    && typeof lng === 'number' && lng >= -180 && lng <= 180
    && typeof t === 'number' && Number.isFinite(t)
    && t <= now + TIME_TOLERANCE_MS && t >= startedAt - TIME_TOLERANCE_MS;
}

function validMotion(b, startedAt, now) {
  return b && typeof b === 'object'
    && typeof b.t === 'number' && Number.isFinite(b.t)
    && b.t <= now + TIME_TOLERANCE_MS && b.t >= startedAt - TIME_TOLERANCE_MS
    && Number.isInteger(b.steps) && b.steps >= 0 && b.steps <= 50
    && typeof b.rms === 'number' && Number.isFinite(b.rms) && b.rms >= 0 && b.rms <= 100;
}

function rowFor(userId) {
  return db.prepare('SELECT * FROM active_walks WHERE user_id = ?').get(userId);
}

function view(row, now = Date.now()) {
  const st = normalize(JSON.parse(row.state));
  const mv = movementView(st, now);
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
    movement: mv,
    turns: turnSummary(st.points),
  };
}

// Ends the session: saves it to history and removes the active row.
function finish(userId, row, endMs) {
  const st = normalize(JSON.parse(row.state));
  const id = randomUUID();
  const sessionSeconds = Math.max(0, Math.round((endMs - row.started_at) / 1000));
  const walkingSeconds = Math.round(st.walkingMs / 1000);
  // duration_seconds keeps the GPS moving time, as before. walking_seconds is the
  // motion-confirmed time, when motion data was available.
  db.prepare(`
    INSERT INTO walking_sessions (id, user_id, start_time, end_time, duration_seconds, distance_meters, points, created_at, session_seconds, walking_seconds)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, userId, row.started_at, endMs, Math.round(st.movingMs / 1000), st.distanceM, JSON.stringify(st.points), Date.now(), sessionSeconds, walkingSeconds);
  db.prepare('DELETE FROM active_walks WHERE id = ? AND user_id = ?').run(row.id, userId);
  return id;
}

/** Returns the active session, or null. Ends it automatically past the 12-hour limit. */
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

/**
 * Applies GPS samples and motion buckets, merged in time order. An invalid item
 * refuses the whole batch, so the stored state never holds half a batch.
 */
export function addSamples(userId, samples = [], now = Date.now(), motion = []) {
  const row = rowFor(userId);
  if (!row) throw httpErr(404, 'There is no active walk. Start one first.');
  if (now - row.started_at > MAX_SESSION_MS) {
    finish(userId, row, row.started_at + MAX_SESSION_MS);
    throw httpErr(409, 'This walk reached its 12-hour limit and was saved.');
  }
  if (!Array.isArray(samples) || samples.length > MAX_BATCH) throw httpErr(400, `Send at most ${MAX_BATCH} location samples at a time.`);
  if (!Array.isArray(motion) || motion.length > MAX_MOTION_BATCH) throw httpErr(400, `Send at most ${MAX_MOTION_BATCH} motion readings at a time.`);
  if (samples.length === 0 && motion.length === 0) throw httpErr(400, 'Send at least one sample or motion reading.');
  for (const s of samples) if (!validSample(s, row.started_at, now)) throw httpErr(400, 'A location sample was invalid and was not saved.');
  for (const b of motion) if (!validMotion(b, row.started_at, now)) throw httpErr(400, 'A motion reading was invalid and was not saved.');

  const events = [
    ...samples.map((s) => ({ t: s[2], kind: 'gps', s })),
    ...motion.map((b) => ({ t: b.t, kind: 'motion', b })),
  ].sort((x, y) => x.t - y.t || (x.kind === 'gps' ? -1 : 1));

  let st = normalize(JSON.parse(row.state));
  for (const e of events) {
    st = e.kind === 'gps' ? applyGps(st, e.s) : applyMotion(st, e.b);
  }
  db.prepare('UPDATE active_walks SET state = ?, updated_at = ? WHERE id = ? AND user_id = ?')
    .run(JSON.stringify(st), now, row.id, userId);
  return view({ ...row, state: JSON.stringify(st) }, now);
}

/** Ends the active session and saves it to history. */
export function stop(userId, now = Date.now()) {
  const row = rowFor(userId);
  if (!row) throw httpErr(404, 'There is no active walk to stop.');
  return finish(userId, row, now);
}
