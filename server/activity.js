// server/activity.js
//
// GPS walking sessions -- see README "Activity module: what's real and what
// isn't" for the full explanation. Short version: there is no web-platform
// equivalent to Apple HealthKit or Android Health Connect, so this module
// does not and cannot provide step counts or sensor-derived distance. What
// it does provide is real: a user-started GPS-tracked walking session,
// using the browser's actual Geolocation API, with distance computed
// server-side from the raw recorded points (never trusted from the client,
// so a tampered request can't claim an impossible distance).

import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import { httpErr } from './http-utils.js';

const EARTH_RADIUS_METERS = 6371000;

// Location-retention policy (spec section 26: do not keep location data longer
// than necessary). The route trail is kept for ROUTE_RETENTION_MS after a
// session ends, then removed by pruneExpiredRoutes(). The session summary
// (times, distance, duration) is kept, because history depends on it. 30 days
// is a judgment call, not a legal standard; change it here if your policy says
// otherwise.
export const ROUTE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
// Server-side cap. The client also caps itself, but a direct API call must not
// be able to store an unbounded trail.
export const MAX_ROUTE_POINTS = 2000;

function haversineMeters(lat1, lng1, lat2, lng2) {
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return EARTH_RADIUS_METERS * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/** Sums point-to-point distance across a route, ignoring GPS jitter jumps that are physically implausible for walking (>15 m/s between consecutive fixes, about 33mph). */
function computeRouteDistance(points) {
  let total = 0;
  for (let i = 1; i < points.length; i++) {
    const [lat1, lng1, t1] = points[i - 1];
    const [lat2, lng2, t2] = points[i];
    const segment = haversineMeters(lat1, lng1, lat2, lng2);
    const seconds = Math.max(1, (t2 - t1) / 1000);
    if (segment / seconds > 15) continue; // implausible jump -- GPS noise, not a step
    total += segment;
  }
  return total;
}

function validatePoints(points) {
  if (!Array.isArray(points) || points.length < 2) throw httpErr(400, 'A walking session needs at least two recorded points.');
  if (points.length > MAX_ROUTE_POINTS) throw httpErr(400, 'This walk has too many recorded points.');
  for (const p of points) {
    if (!Array.isArray(p) || p.length < 3) throw httpErr(400, 'Each point must be [lat, lng, timestamp].');
    const [lat, lng, t] = p;
    if (typeof lat !== 'number' || lat < -90 || lat > 90) throw httpErr(400, 'Invalid latitude in route data.');
    if (typeof lng !== 'number' || lng < -180 || lng > 180) throw httpErr(400, 'Invalid longitude in route data.');
    if (typeof t !== 'number' || t <= 0) throw httpErr(400, 'Invalid timestamp in route data.');
  }
}

function rowToSession(row) {
  const points = JSON.parse(row.points || '[]');
  return {
    id: row.id,
    startTime: row.start_time,
    endTime: row.end_time,
    durationSeconds: row.duration_seconds,
    distanceMeters: row.distance_meters,
    distanceMiles: row.distance_meters / 1609.344,
    avgSpeedMph: row.duration_seconds > 0 ? (row.distance_meters / 1609.344) / (row.duration_seconds / 3600) : 0,
    paceMinPerMile: row.distance_meters > 0 ? (row.duration_seconds / 60) / (row.distance_meters / 1609.344) : null,
    points,
    createdAt: row.created_at,
  };
}

export function saveSession(userId, { points, startTime, endTime }) {
  validatePoints(points);
  const start = Number(startTime);
  const end = Number(endTime);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) throw httpErr(400, 'Invalid session start/end time.');
  const durationSeconds = Math.round((end - start) / 1000);
  if (durationSeconds > 6 * 60 * 60) throw httpErr(400, "A single walking session can't exceed 6 hours.");
  const distanceMeters = computeRouteDistance(points);

  const id = randomUUID();
  const now = Date.now();
  db.prepare(`
    INSERT INTO walking_sessions (id, user_id, start_time, end_time, duration_seconds, distance_meters, points, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, userId, start, end, durationSeconds, distanceMeters, JSON.stringify(points), now);
  return getSession(userId, id);
}

function fetchOwnedRow(userId, id) {
  const row = db.prepare('SELECT * FROM walking_sessions WHERE id = ? AND user_id = ?').get(id, userId);
  if (!row || row.user_id !== userId) throw httpErr(404, 'Walking session not found.');
  return row;
}

export function getSession(userId, id) {
  return rowToSession(fetchOwnedRow(userId, id));
}

export function deleteSession(userId, id) {
  fetchOwnedRow(userId, id);
  db.prepare('DELETE FROM walking_sessions WHERE id = ? AND user_id = ?').run(id, userId);
}

export function listSessions(userId, { fromMs, toMs, limit = 200 } = {}) {
  let rows;
  if (fromMs !== undefined && toMs !== undefined) {
    rows = db.prepare('SELECT * FROM walking_sessions WHERE user_id = ? AND start_time >= ? AND start_time <= ? ORDER BY start_time DESC LIMIT ?').all(userId, fromMs, toMs, limit);
  } else {
    rows = db.prepare('SELECT * FROM walking_sessions WHERE user_id = ? ORDER BY start_time DESC LIMIT ?').all(userId, limit);
  }
  return rows.map(rowToSession);
}

/** Aggregate real recorded sessions for a given local day -- never fabricated, "no data" is a valid and expected answer. */
export function dailySummary(userId, dayStartMs, dayEndMs) {
  const sessions = listSessions(userId, { fromMs: dayStartMs, toMs: dayEndMs, limit: 1000 });
  if (sessions.length === 0) return { hasData: false, sessions: [] };
  const distanceMeters = sessions.reduce((sum, s) => sum + s.distanceMeters, 0);
  const durationSeconds = sessions.reduce((sum, s) => sum + s.durationSeconds, 0);
  return {
    hasData: true,
    sessionCount: sessions.length,
    distanceMeters,
    distanceMiles: distanceMeters / 1609.344,
    durationSeconds,
    sessions,
  };
}

/**
 * Spec section 28/29 -- natural-language-ish activity search. Answers ONLY
 * from real recorded sessions; if nothing matches, says so plainly rather
 * than guessing. This is deliberately simple keyword matching, not an LLM --
 * see README for why a real NLP layer is out of scope here.
 */
export function searchActivity(userId, q) {
  const term = q.trim().toLowerCase();
  if (!/walk|steps?|distance|mile|activity/i.test(term)) return null;

  const now = Date.now();
  const startOfToday = new Date(); startOfToday.setHours(0, 0, 0, 0);
  const startOfYesterday = new Date(startOfToday.getTime() - 86400000);
  const startOfWeek = new Date(startOfToday.getTime() - 6 * 86400000);

  let label, from, to;
  if (/yesterday/.test(term)) { label = 'yesterday'; from = startOfYesterday.getTime(); to = startOfToday.getTime() - 1; }
  else if (/week/.test(term)) { label = 'this week'; from = startOfWeek.getTime(); to = now; }
  else { label = 'today'; from = startOfToday.getTime(); to = now; }

  const summary = dailySummary(userId, from, to);
  const stepsNote = /steps?/i.test(term) ? " Step counts aren't available -- that needs phone sensor access a web browser can't reach; see the Activity screen for why." : '';

  if (!summary.hasData) {
    return { label, hasData: false, answer: `No recorded walking sessions found for ${label}.${stepsNote}` };
  }
  return {
    label, hasData: true, distanceMiles: summary.distanceMiles, durationSeconds: summary.durationSeconds, sessionCount: summary.sessionCount,
    answer: `You've recorded approximately ${summary.distanceMiles.toFixed(1)} miles of walking ${label} (${summary.sessionCount} session${summary.sessionCount === 1 ? '' : 's'}, ${Math.round(summary.durationSeconds / 60)} min).${stepsNote}`,
  };
}


/**
 * Removes the route trail from every walking session older than the retention
 * window. The session row itself stays, with its points set to an empty list,
 * so history, totals, and distance remain. Safe to run repeatedly. Returns the
 * number of sessions whose trail was removed.
 */
export function pruneExpiredRoutes(now = Date.now()) {
  const cutoff = now - ROUTE_RETENTION_MS;
  const result = db.prepare(
    "UPDATE walking_sessions SET points = '[]' WHERE end_time < ? AND points != '[]'"
  ).run(cutoff);
  return result.changes;
}

/** Clears the route trail for one of the caller's own sessions immediately, without deleting the session. */
export function clearRoute(userId, id) {
  fetchOwnedRow(userId, id);
  db.prepare("UPDATE walking_sessions SET points = '[]' WHERE id = ? AND user_id = ?").run(id, userId);
  return getSession(userId, id);
}

// ---------------------------------------------------------------------------
// Personal activity goals (spec section 24, 53)
// ---------------------------------------------------------------------------
const MAX_GOAL_MILES = 100;   // sanity ceiling; a daily goal above this is almost certainly a typo
const MAX_GOAL_MINUTES = 600; // 10 hours of walking per day

export function getGoal(userId) {
  const row = db.prepare('SELECT * FROM activity_goals WHERE user_id = ?').get(userId);
  if (!row) return null;
  return {
    dailyDistanceMiles: row.daily_distance_miles,
    dailyWalkMinutes: row.daily_walk_minutes,
    updatedAt: row.updated_at,
  };
}

export function setGoal(userId, { dailyDistanceMiles, dailyWalkMinutes }) {
  const miles = dailyDistanceMiles === null || dailyDistanceMiles === undefined || dailyDistanceMiles === '' ? null : Number(dailyDistanceMiles);
  const minutes = dailyWalkMinutes === null || dailyWalkMinutes === undefined || dailyWalkMinutes === '' ? null : Math.round(Number(dailyWalkMinutes));
  if (miles === null && minutes === null) {
    db.prepare('DELETE FROM activity_goals WHERE user_id = ?').run(userId);
    return null;
  }
  if (miles !== null && (!Number.isFinite(miles) || miles <= 0 || miles > MAX_GOAL_MILES)) throw httpErr(400, `A distance goal must be between 0 and ${MAX_GOAL_MILES} miles.`);
  if (minutes !== null && (!Number.isFinite(minutes) || minutes <= 0 || minutes > MAX_GOAL_MINUTES)) throw httpErr(400, `A time goal must be between 1 and ${MAX_GOAL_MINUTES} minutes.`);
  db.prepare(`
    INSERT INTO activity_goals (user_id, daily_distance_miles, daily_walk_minutes, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET daily_distance_miles = excluded.daily_distance_miles,
      daily_walk_minutes = excluded.daily_walk_minutes, updated_at = excluded.updated_at
  `).run(userId, miles, minutes, Date.now());
  return getGoal(userId);
}

/**
 * Today's progress against the goal. Computed fresh from real recorded sessions
 * on every call. Returns null for any target that isn't set, so the UI can say
 * "no goal set" instead of showing a fabricated percentage.
 */
export function goalProgress(userId, now = new Date()) {
  const goal = getGoal(userId);
  const startOfToday = new Date(now); startOfToday.setHours(0, 0, 0, 0);
  const summary = dailySummary(userId, startOfToday.getTime(), now.getTime());
  const milesToday = summary.hasData ? summary.distanceMiles : 0;
  const minutesToday = summary.hasData ? summary.durationSeconds / 60 : 0;
  const distancePct = goal?.dailyDistanceMiles ? Math.min(100, Math.round((milesToday / goal.dailyDistanceMiles) * 100)) : null;
  const timePct = goal?.dailyWalkMinutes ? Math.min(100, Math.round((minutesToday / goal.dailyWalkMinutes) * 100)) : null;
  return {
    goal,
    today: { miles: milesToday, minutes: Math.round(minutesToday) },
    distancePct,
    timePct,
    goalMet: (goal?.dailyDistanceMiles ? milesToday >= goal.dailyDistanceMiles : true) && (goal?.dailyWalkMinutes ? minutesToday >= goal.dailyWalkMinutes : true) && !!(goal?.dailyDistanceMiles || goal?.dailyWalkMinutes),
  };
}
