// server/movement.js
//
// Movement engine: GPS (with its reported accuracy) and phone motion (step peaks
// and vibration level) are combined into one of four states:
//   WALKING, STATIONARY, MOVING_OTHER (moved, but not walking), UNCERTAIN.
// Every threshold is a named constant here, and every state change needs a
// confirmation period. Time is credited to a state only once it is confirmed.
//
// Inputs are raw facts sent by the app. The server does the classification,
// so a client cannot choose its own state.

import { MAX_ROUTE_POINTS } from './activity.js';

// --- GPS ------------------------------------------------------------------
export const DEFAULT_ACC_M = 10;     // used when a fix reports no accuracy
export const ACC_REJECT_M = 50;      // fixes worse than this are ignored
export const BASE_RADIUS_M = 10;     // minimum uncertainty radius
export const MAX_RADIUS_M = 60;      // cap, so a bad fix can't hide real movement
export const GPS_STILL_AFTER_MS = 30000; // inside the radius this long = GPS still
export const GPS_FRESH_MS = 60000;   // a fix older than this is "unknown"
export const MAX_GAP_MS = 60000;     // no data for this long earns no time
export const MAX_SPEED_MPS = 10;     // faster than this between fixes = GPS jump

// --- Motion (phone sensors) ----------------------------------------------
export const MOTION_STALE_MS = 20000;  // no motion data for this long = UNCERTAIN
export const WALK_WINDOW_MS = 10000;   // window used to look for steps
export const WALK_MIN_STEPS = 4;       // steps in WALK_WINDOW_MS that count as walking
export const STILL_WINDOW_MS = 8000;   // window with no steps used for "still"
export const RMS_STILL = 0.15;         // m/s^2 vibration below this = still
export const RMS_OTHER = 1.0;          // m/s^2 vibration above this with no steps = moved
const MOTION_KEEP_MS = 30000;

// How long a candidate state must persist before it is adopted.
export const CONFIRM_MS = { WALKING: 6000, STATIONARY: 30000, MOVING_OTHER: 6000, UNCERTAIN: 10000 };

const R = 6371000;
function hav(lat1, lng1, lat2, lng2) {
  const t = (d) => (d * Math.PI) / 180;
  const dLat = t(lat2 - lat1), dLng = t(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(t(lat1)) * Math.cos(t(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}
const mean = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0);

export function initialState() {
  return {
    lastLat: null, lastLng: null, lastT: null,
    anchorLat: null, anchorLng: null, anchorT: null,
    moving: false, movingMs: 0, distanceM: 0, points: [],
    rejectedFixes: 0, accuracy: null, lastGpsT: null,
    state: 'UNCERTAIN', cand: 'UNCERTAIN', candSince: null, pending: 0, lastEvalT: null,
    lastMotionT: null, motion: [],
    walkingMs: 0, stationaryMs: 0, otherMs: 0, uncertainMs: 0,
  };
}

// Saved walks from earlier versions lack the motion fields. Fill them in.
export function normalize(st) {
  return { ...initialState(), ...st };
}

function credit(st, label, ms) {
  if (ms <= 0) return st;
  if (label === 'WALKING') return { ...st, walkingMs: st.walkingMs + ms };
  if (label === 'STATIONARY') return { ...st, stationaryMs: st.stationaryMs + ms };
  if (label === 'MOVING_OTHER') return { ...st, otherMs: st.otherMs + ms };
  return { ...st, uncertainMs: st.uncertainMs + ms };
}

// Moves the clock forward. Time is credited to the confirmed state, or held as
// "pending" while a different candidate is waiting to be confirmed.
function advance(st, t) {
  if (st.lastEvalT === null) return { ...st, lastEvalT: t };
  const dt = t - st.lastEvalT;
  if (dt <= 0) return st;
  const n = { ...st, lastEvalT: t };
  if (dt > MAX_GAP_MS) return { ...n, pending: 0 }; // gap: nothing is credited
  if (n.cand === n.state) return credit(n, n.state, dt);
  return { ...n, pending: n.pending + dt };
}

function gpsEvidence(st, t) {
  if (st.lastGpsT === null || t - st.lastGpsT > GPS_FRESH_MS) return 'unknown';
  return st.moving ? 'moving' : 'still';
}

function evaluate(st, t) {
  const fresh = st.lastMotionT !== null && t - st.lastMotionT <= MOTION_STALE_MS;
  let cand;
  if (!fresh) {
    cand = 'UNCERTAIN';
  } else {
    const w = st.motion.filter((b) => t - b.t < WALK_WINDOW_MS);
    const s = st.motion.filter((b) => t - b.t < STILL_WINDOW_MS);
    const steps10 = w.reduce((a, b) => a + b.steps, 0);
    const steps8 = s.reduce((a, b) => a + b.steps, 0);
    const rmsW = mean(w.map((b) => b.rms));
    const rmsS = mean(s.map((b) => b.rms));
    const gps = gpsEvidence(st, t);
    if (steps10 >= WALK_MIN_STEPS) cand = 'WALKING';
    else if (steps8 === 0 && rmsS < RMS_STILL && gps !== 'moving') cand = 'STATIONARY';
    else if (rmsW >= RMS_OTHER) cand = 'MOVING_OTHER';
    else cand = st.state; // no clear evidence: hold the current state (hysteresis)
  }

  let n = st;
  if (cand !== n.cand) {
    // Time spent waiting on the old candidate belongs to the state we are still in.
    n = credit(n, n.state, n.pending);
    n = { ...n, pending: 0, cand, candSince: t };
  }
  if (n.cand === n.state) {
    n = credit(n, n.state, n.pending);
    return { ...n, pending: 0 };
  }
  if (t - n.candSince >= CONFIRM_MS[n.cand]) {
    n = credit(n, n.cand, n.pending);
    return { ...n, state: n.cand, pending: 0 };
  }
  return n;
}

/** GPS fix: [lat, lng, t, accuracyMetres?]. Fixes worse than ACC_REJECT_M are dropped. */
export function applyGps(st0, sample) {
  const [lat, lng, t] = sample;
  const acc = sample.length >= 4 && Number.isFinite(sample[3]) ? sample[3] : DEFAULT_ACC_M;
  let st = advance(st0, t);
  if (acc > ACC_REJECT_M) return { ...st, rejectedFixes: st.rejectedFixes + 1 };

  const points = st.points.length < MAX_ROUTE_POINTS ? [...st.points, [lat, lng, t, acc]] : st.points;
  const base = { ...st, points, accuracy: acc, lastGpsT: t };

  if (st.lastT === null) {
    return evaluate({ ...base, lastT: t, anchorLat: lat, anchorLng: lng, anchorT: t, moving: false }, t);
  }
  const dt = t - st.lastT;
  if (dt <= 0) return st0; // out of order or duplicate: leave the state exactly as it was
  if (dt > MAX_GAP_MS) {
    return evaluate({ ...base, lastT: t, anchorLat: lat, anchorLng: lng, anchorT: t, moving: false }, t);
  }

  const radius = Math.min(MAX_RADIUS_M, Math.max(BASE_RADIUS_M, acc));
  let anchorLat = st.anchorLat, anchorLng = st.anchorLng, anchorT = st.anchorT, moving = st.moving;
  let movingMs = st.movingMs, distanceM = st.distanceM;
  if (hav(anchorLat, anchorLng, lat, lng) > radius) {
    // Movement begins: credit the distance covered since the last still point, so the
    // first steps of a walk are not lost.
    const startSeg = hav(anchorLat, anchorLng, lat, lng);
    if (!moving && startSeg / (dt / 1000) <= MAX_SPEED_MPS) distanceM += startSeg; // same speed guard as below
    moving = true; anchorLat = lat; anchorLng = lng; anchorT = t;
  } else if (t - anchorT >= GPS_STILL_AFTER_MS) {
    moving = false;
  }
  const seg = hav(st.lastLat, st.lastLng, lat, lng);
  if (st.moving && moving && seg / (dt / 1000) <= MAX_SPEED_MPS) {
    movingMs += dt; distanceM += seg;
  }
  return evaluate({ ...base, lastLat: lat, lastLng: lng, lastT: t, anchorLat, anchorLng, anchorT, moving, movingMs, distanceM }, t);
}

/** Motion bucket: { t, steps, rms } where rms is the vibration level with gravity removed. */
export function applyMotion(st0, b) {
  let st = advance(st0, b.t);
  const motion = [...st.motion, { t: b.t, steps: b.steps, rms: b.rms }].filter((x) => b.t - x.t <= MOTION_KEEP_MS);
  st = { ...st, motion, lastMotionT: st.lastMotionT === null ? b.t : Math.max(st.lastMotionT, b.t) };
  return evaluate(st, b.t);
}

/** What the app shows. Values are as of the last upload, not the second. */
export function movementView(st, now = Date.now()) {
  const motionFresh = st.lastMotionT !== null && now - st.lastMotionT <= MOTION_STALE_MS;
  const gpsFresh = st.lastGpsT !== null && now - st.lastGpsT <= GPS_FRESH_MS;
  let quality;
  if (!motionFresh && !gpsFresh) quality = 'unavailable';
  else if (st.accuracy !== null && st.accuracy > 25) quality = 'poor';
  else if (motionFresh && gpsFresh && (st.accuracy ?? 99) <= 15) quality = 'good';
  else quality = 'limited';
  return {
    state: motionFresh ? st.state : 'UNCERTAIN',
    motionAvailable: motionFresh,
    gpsAvailable: gpsFresh,
    gpsAccuracyM: st.accuracy,
    lastSensorAt: Math.max(st.lastMotionT ?? 0, st.lastGpsT ?? 0) || null,
    walkingSeconds: Math.round(st.walkingMs / 1000),
    stationarySeconds: Math.round(st.stationaryMs / 1000),
    otherSeconds: Math.round(st.otherMs / 1000),
    uncertainSeconds: Math.round(st.uncertainMs / 1000),
    trackingQuality: quality,
    rejectedFixes: st.rejectedFixes,
  };
}
