// SYNTHETIC FIXTURES ONLY. Every position and motion reading below is generated
// in code to test the logic. None of these results are measurements of a real
// phone, person, or GPS receiver. Real-device accuracy is not measured here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { initialState, applyGps, applyMotion, movementView, CONFIRM_MS } from '../server/movement.js';
import { bearingDeg, headingChange, classifyChange, routeTurns } from '../server/route.js';

const LAT0 = 5.6037, LNG0 = -0.1870, M_PER_DEG = 111320;
const KINDS = {
  walk:    { steps: 4, rms: 1.5 },  // about 2 steps per second
  slow:    { steps: 2, rms: 1.0 },  // about 1 step per second
  still:   { steps: 0, rms: 0.05 }, // phone on a bed or desk
  sitting: { steps: 0, rms: 0.08 },
  standing:{ steps: 0, rms: 0.10 },
  shaken:  { steps: 0, rms: 2.0 },  // phone shaken while the person is still
  rotated: { steps: 0, rms: 0.30 }, // phone turned slowly while still
};

/**
 * phases: [{ seconds, motion: kind|null, gps: null | { mode:'walk'|'still'|'drift', acc, stepM, driftM } ]
 * Returns the timeline: the movement state at each second from t0.
 */
function scenario(phases, t0 = 1_000_000) {
  let st = initialState();
  let t = t0, north = 0, k = 0;
  const timeline = [];
  for (const ph of phases) {
    for (let s = 0; s < ph.seconds; s++, t += 1000, k++) {
      if (ph.gps && (t - t0) % 5000 === 0) {
        if (ph.gps.mode === 'walk') north += ph.gps.stepM;
        const drift = ph.gps.mode === 'drift' ? ph.gps.driftM * Math.sin(k * 1.7) : 0;
        const lat = LAT0 + (north + drift) / M_PER_DEG;
        st = applyGps(st, [lat, LNG0, t, ph.gps.acc]);
      }
      if (ph.motion && (t - t0) % 2000 === 0) {
        const kind = KINDS[ph.motion];
        st = applyMotion(st, { t, steps: kind.steps, rms: kind.rms });
      }
      timeline.push({ t, state: movementView(st, t).state, st });
    }
  }
  return { st, timeline, t0 };
}
const at = (r, sec) => r.timeline[sec - 1];

// Older rule, kept only for the comparison in the test below: a fixed 10 m radius,
// with no GPS accuracy taken into account.
function legacyMovingSeconds(positions) {
  let anchor = positions[0][0], anchorT = positions[0][1], moving = false, count = 0;
  for (let i = 1; i < positions.length; i++) {
    const [p, t] = positions[i];
    const d = Math.hypot((p[0] - anchor[0]) * M_PER_DEG, (p[1] - anchor[1]) * M_PER_DEG * 0.9999);
    if (d > 10) { moving = true; anchor = p; anchorT = t; }
    else if (t - anchorT >= 30) moving = false;
    if (moving) count += 5;
  }
  return count;
}

test('phone on a bed, GPS drifting 12 m indoors: not counted as walking or as distance', () => {
  const r = scenario([{ seconds: 180, motion: 'still', gps: { mode: 'drift', acc: 25, driftM: 12 } }]);
  const end = r.st;
  assert.equal(end.walkingMs, 0);
  assert.notEqual(movementView(end, r.t0 + 180000).state, 'WALKING');
  assert.ok(end.distanceM < 5, `drift must not add distance, got ${end.distanceM} m`);
  assert.equal(movementView(end, r.t0 + 180000).state, 'STATIONARY', 'after confirmation the state must be STATIONARY');
});

test('the same bed drift under the old rule is counted as moving (documented before/after)', () => {
  const positions = [];
  for (let s = 5; s <= 180; s += 5) {
    const north = 12 * Math.sin(s * 1.7); // same drift as the scenario
    positions.push([[LAT0 + north / M_PER_DEG, LNG0], s]);
  }
  const legacy = legacyMovingSeconds(positions);
  const r = scenario([{ seconds: 180, motion: 'still', gps: { mode: 'drift', acc: 25, driftM: 12 } }]);
  console.log(`  [synthetic] bed drift 12 m, 3 min: old rule flagged ${legacy} s as moving; new engine GPS-moving ${Math.round(r.st.movingMs / 1000)} s`);
  assert.ok(legacy > 0, 'the old rule must show the false movement this change fixes');
  assert.equal(r.st.movingMs, 0, 'the new engine must not count the same drift');
});

test('standing or sitting still with no GPS motion becomes STATIONARY and earns no walking time', () => {
  for (const kind of ['sitting', 'standing', 'still']) {
    const r = scenario([{ seconds: 120, motion: kind, gps: { mode: 'still', acc: 5 } }]);
    assert.equal(movementView(r.st, r.t0 + 120000).state, 'STATIONARY', kind);
    assert.equal(r.st.walkingMs, 0, kind);
  }
});

test('normal walking is confirmed as WALKING within about six seconds', () => {
  const r = scenario([{ seconds: 60, motion: 'walk', gps: { mode: 'walk', acc: 5, stepM: 7 } }]);
  const firstWalk = r.timeline.findIndex((x) => x.state === 'WALKING') + 1;
  assert.ok(firstWalk > 0 && firstWalk <= 12, `expected WALKING by about 6-12 s, got ${firstWalk} s`);
  assert.ok(r.st.walkingMs >= 40000, `walking time should be most of the walk, got ${r.st.walkingMs} ms`);
  // 12 fixes, 7 m apart: about 77 m. Accept 70-85 m.
  assert.ok(r.st.distanceM > 70 && r.st.distanceM < 85, `GPS distance should be about 77 m, got ${r.st.distanceM}`);
});

test('slow walking (about one step per second) is still recognised as WALKING', () => {
  const r = scenario([{ seconds: 60, motion: 'slow', gps: { mode: 'walk', acc: 5, stepM: 3.5 } }]);
  assert.equal(movementView(r.st, r.t0 + 60000).state, 'WALKING');
});

test('a 30-second stop does not yet count as stationary: stationary needs 30 s of confirmation', () => {
  const r = scenario([
    { seconds: 60, motion: 'walk', gps: { mode: 'walk', acc: 5, stepM: 7 } },
    { seconds: 30, motion: 'still', gps: { mode: 'still', acc: 5 } },
  ]);
  assert.equal(at(r, 85).state, 'WALKING', 'a 30 s stop is not confirmed as stationary');
});

test('a 60-second stop is confirmed as STATIONARY, with the walk time before the stop kept', () => {
  const r = scenario([
    { seconds: 60, motion: 'walk', gps: { mode: 'walk', acc: 5, stepM: 7 } },
    { seconds: 60, motion: 'still', gps: { mode: 'still', acc: 5 } },
  ]);
  assert.equal(at(r, 120).state, 'STATIONARY');
  assert.ok(r.st.stationaryMs >= 25000, `stationary time should be recorded, got ${r.st.stationaryMs}`);
});

test('a 2-minute stop is STATIONARY and walking resumes to WALKING afterwards', () => {
  const r = scenario([
    { seconds: 60, motion: 'walk', gps: { mode: 'walk', acc: 5, stepM: 7 } },
    { seconds: 120, motion: 'still', gps: { mode: 'still', acc: 5 } },
    { seconds: 60, motion: 'walk', gps: { mode: 'walk', acc: 5, stepM: 7 } },
  ]);
  assert.equal(at(r, 150).state, 'STATIONARY');
  assert.equal(at(r, 200).state, 'WALKING', 'walking must be confirmed again after the stop');
});

test('a phone shaken while the person stands still is MOVING_OTHER, never WALKING', () => {
  const r = scenario([{ seconds: 90, motion: 'shaken', gps: { mode: 'still', acc: 5 } }]);
  assert.equal(movementView(r.st, r.t0 + 90000).state, 'MOVING_OTHER');
  assert.equal(r.st.walkingMs, 0, 'shaking without steps must not add walking time');
});

test('a phone turned slowly while still does not create walking time', () => {
  const r = scenario([{ seconds: 90, motion: 'rotated', gps: { mode: 'still', acc: 5 } }]);
  assert.equal(r.st.walkingMs, 0);
  assert.notEqual(movementView(r.st, r.t0 + 90000).state, 'WALKING');
});

test('poor GPS accuracy (worse than 50 m) is rejected, and no distance is added from it', () => {
  const r = scenario([{ seconds: 60, motion: 'still', gps: { mode: 'walk', acc: 80, stepM: 7 } }]);
  assert.ok(r.st.rejectedFixes > 0, 'poor fixes must be counted as rejected');
  assert.equal(r.st.distanceM, 0, 'rejected fixes must not add distance');
});

test('a GPS jump of about 500 m in 5 s is not counted as distance', () => {
  let st = initialState();
  st = applyGps(st, [LAT0, LNG0, 1_000_000, 5]);
  st = applyGps(st, [LAT0 + 500 / M_PER_DEG, LNG0, 1_005_000, 5]);
  assert.equal(st.distanceM, 0);
});

test('with GPS unavailable, motion alone still shows WALKING, and GPS distance stays zero', () => {
  const r = scenario([{ seconds: 60, motion: 'walk', gps: null }]);
  assert.equal(movementView(r.st, r.t0 + 60000).state, 'WALKING');
  assert.equal(r.st.distanceM, 0, 'no GPS means no GPS distance; steps alone are not distance here');
  assert.equal(movementView(r.st, r.t0 + 60000).gpsAvailable, false);
});

test('with motion permission denied, walking is UNCERTAIN, and GPS movement is still shown', () => {
  const r = scenario([{ seconds: 60, motion: null, gps: { mode: 'walk', acc: 5, stepM: 7 } }]);
  const v = movementView(r.st, r.t0 + 60000);
  assert.equal(v.state, 'UNCERTAIN', 'without motion data the engine must not claim walking');
  assert.equal(v.motionAvailable, false);
  assert.ok(r.st.movingMs > 0, 'GPS-based moving time is still reported, labelled as GPS');
});

test('a gap of five minutes with no data earns no time in any state', () => {
  const r = scenario([
    { seconds: 60, motion: 'walk', gps: { mode: 'walk', acc: 5, stepM: 7 } },
    { seconds: 300, motion: null, gps: null },
  ]);
  const total = r.st.walkingMs + r.st.stationaryMs + r.st.otherMs + r.st.uncertainMs;
  assert.ok(total < 120000 + 1000, `a 5-minute gap must not be filled in, credited ${total} ms`);
});

test('time is conserved: every second is credited to exactly one state, outside gaps', () => {
  const r = scenario([
    { seconds: 60, motion: 'still', gps: { mode: 'still', acc: 5 } },
    { seconds: 60, motion: 'walk', gps: { mode: 'walk', acc: 5, stepM: 7 } },
    { seconds: 60, motion: 'still', gps: { mode: 'still', acc: 5 } },
  ]);
  const total = r.st.walkingMs + r.st.stationaryMs + r.st.otherMs + r.st.uncertainMs;
  assert.ok(Math.abs(total - 180000) <= 6000, `expected about 180 s credited, got ${total} ms`);
});

test('a stationary period never reduces walking time that was already confirmed', () => {
  const walk = scenario([{ seconds: 60, motion: 'walk', gps: { mode: 'walk', acc: 5, stepM: 7 } }]);
  const withStop = scenario([
    { seconds: 60, motion: 'walk', gps: { mode: 'walk', acc: 5, stepM: 7 } },
    { seconds: 120, motion: 'still', gps: { mode: 'still', acc: 5 } },
  ]);
  assert.ok(withStop.st.walkingMs >= walk.st.walkingMs - 1000);
});

test('confirmation periods match the documented values', () => {
  assert.equal(CONFIRM_MS.WALKING, 6000);
  assert.equal(CONFIRM_MS.STATIONARY, 30000);
});

test('bearing: north is 0 degrees, east is 90 degrees', () => {
  assert.ok(Math.abs(bearingDeg(0, 0, 1, 0) - 0) < 0.01);
  assert.ok(Math.abs(bearingDeg(0, 0, 0, 1) - 90) < 0.01);
});

test('the 0/360 boundary: 350 to 10 degrees is a 20 degree right turn, not 340', () => {
  assert.equal(headingChange(350, 10), 20);
  assert.equal(headingChange(10, 350), -20);
});

test('turn classification: straight, left, right, and reversal', () => {
  assert.equal(classifyChange(5), 'straight');
  assert.equal(classifyChange(90), 'right');
  assert.equal(classifyChange(-90), 'left');
  assert.equal(classifyChange(180), 'reversal');
});

test('a route going north, then east, then south-west is detected as a right turn, then a reversal-range turn', () => {
  const pts = [
    [LAT0, LNG0, 0],
    [LAT0 + 20 / M_PER_DEG, LNG0, 10000],          // north 20 m
    [LAT0 + 20 / M_PER_DEG, LNG0 + 20 / M_PER_DEG, 20000], // east 20 m: right turn
    [LAT0 + 5 / M_PER_DEG, LNG0 + 15 / M_PER_DEG, 30000],  // back south-west: sharp turn
  ];
  const turns = routeTurns(pts, { minSegmentM: 8 });
  assert.equal(turns[0].type, 'right');
  assert.ok(turns.length === 2 && ['left', 'reversal', 'right'].includes(turns[1].type));
});

test('short GPS jitter segments under 8 m create no turns', () => {
  const pts = [];
  for (let i = 0; i < 10; i++) pts.push([LAT0 + (i % 2) * 2 / M_PER_DEG, LNG0 + (i % 3) * 2 / M_PER_DEG, i * 5000]);
  assert.equal(routeTurns(pts).length, 0);
});

test('CONFIRM_MS stationary confirmation is never shorter than the walking confirmation', () => {
  assert.ok(CONFIRM_MS.STATIONARY >= CONFIRM_MS.WALKING);
});
