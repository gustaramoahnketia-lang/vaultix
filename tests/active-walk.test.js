import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';
import { applySample, initialState, STILL_RADIUS_M, MAX_GAP_MS } from '../server/active-walk.js';
import { db } from '../server/db.js';

// Builds a sample sequence. Each step is { seconds, metersNorth, jitterM }.
// jitter is a deterministic wobble that imitates GPS noise when standing.
const LAT0 = 5.6037, LNG0 = -0.1870;
function run(steps, t0 = 1_000_000) {
  let st = initialState(), t = t0, lat = LAT0, north = 0;
  let i = 0;
  for (const step of steps) {
    for (let k = 0; k < step.count; k++) {
      const jitter = step.jitterM ? Math.sin(i * 1.7) * step.jitterM : 0;
      const wobbleLat = (north + jitter) / 111320;
      const wobbleLng = (jitter * 0.6) / (111320 * Math.cos(LAT0 * Math.PI / 180));
      st = applySample(st, [lat + wobbleLat, LNG0 + wobbleLng, t]);
      t += step.intervalMs; i++;
      north += step.metersPerSample || 0;
    }
  }
  return st;
}

test('standing still for minutes with GPS noise earns no moving time and no distance', () => {
  const st = run([{ count: 60, intervalMs: 5000, metersPerSample: 0, jitterM: 3 }]); // 5 minutes
  assert.equal(st.movingMs, 0, 'standing still must not count as moving');
  assert.ok(st.distanceM < 1, 'jitter must not add distance');
});

test('walking at a steady pace counts as moving, with about the right distance', () => {
  // 1.4 m/s, sampled every 5 seconds, for 2 minutes: 7 m per sample, 24 samples.
  const st = run([{ count: 24, intervalMs: 5000, metersPerSample: 7 }]);
  assert.ok(st.movingMs >= 100_000, `expected close to 115 s of moving time, got ${st.movingMs}`);
  assert.ok(st.distanceM > 140 && st.distanceM < 180, `expected about 161 m, got ${st.distanceM}`);
});

test('standing, then walking, then standing counts only the walking', () => {
  const st = run([
    { count: 36, intervalMs: 5000, metersPerSample: 0, jitterM: 3 },   // 3 min still
    { count: 12, intervalMs: 5000, metersPerSample: 7 },               // 1 min walking
    { count: 36, intervalMs: 5000, metersPerSample: 0, jitterM: 3 },   // 3 min still
  ]);
  assert.ok(st.movingMs >= 40_000 && st.movingMs <= 75_000, `expected about one minute of moving, got ${st.movingMs}`);
});

test('a gap with no samples (app closed) earns no moving time, even if the person was walking before it', () => {
  const beforeGap = run([{ count: 12, intervalMs: 5000, metersPerSample: 7 }]);
  const afterGapTime = 1_000_000 + 12 * 5000 + 10 * 60_000; // ten minutes later
  let st = beforeGap;
  st = applySample(st, [LAT0 + 0.01, LNG0, afterGapTime]);
  st = applySample(st, [LAT0 + 0.0101, LNG0, afterGapTime + 5000]);
  assert.ok(st.movingMs < 10 * 60_000, 'the ten-minute gap must not be counted as moving');
  assert.ok(MAX_GAP_MS < 10 * 60_000);
});

test('a GPS jump faster than walking is not counted as distance or moving time', () => {
  let st = initialState();
  st = applySample(st, [LAT0, LNG0, 1_000_000]);
  st = applySample(st, [LAT0, LNG0, 1_000_000 + 5000]);
  st = applySample(st, [LAT0 + 0.5, LNG0, 1_000_000 + 10_000]); // about 55 km in 5 s
  assert.ok(st.distanceM < 1000, 'an impossible jump must not add distance');
});

test('an out-of-order or duplicate sample never counts backwards', () => {
  let st = initialState();
  st = applySample(st, [LAT0, LNG0, 2_000_000]);
  st = applySample(st, [LAT0 + 0.0001, LNG0, 2_000_000 + 5000]);
  const before = st.movingMs;
  const dup = applySample(st, [LAT0 + 0.0002, LNG0, 2_000_000 + 3000]); // earlier than the last sample
  assert.equal(dup.movingMs, before, 'an earlier timestamp must be ignored');
  assert.equal(dup, st, 'the state must be unchanged');
});

test('standing radius is a real constant, so tests and code agree on what "still" means', () => {
  assert.equal(STILL_RADIUS_M, 10);
});

// ---------------------------------------------------------------------------
// API behaviour: start, resume, samples, stop, ownership, and limits.
// ---------------------------------------------------------------------------
let ctx, a, b;
before(async () => {
  ctx = await startTestServer();
  a = makeClient(ctx.baseUrl);
  b = makeClient(ctx.baseUrl);
  await a.post('/api/auth/register', { name: 'Walk A', email: 'aw-a@example.com', password: 'WalkAlice9!', recoveryEmail: 'aw-a@example.com' });
  await b.post('/api/auth/register', { name: 'Walk B', email: 'aw-b@example.com', password: 'WalkBob9!', recoveryEmail: 'aw-b@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('starting a walk creates one active session and returns it', async () => {
  const res = await a.post('/api/activity/active/start', {});
  assert.equal(res.status, 201);
  assert.equal(res.body.resumed, false);
  assert.ok(res.body.active.startedAt <= Date.now());
});

test('starting again while a walk is running resumes it instead of creating a second one', async () => {
  const first = await a.get('/api/activity/active');
  const again = await a.post('/api/activity/active/start', {});
  assert.equal(again.status, 200);
  assert.equal(again.body.resumed, true);
  assert.equal(again.body.active.id, first.body.active.id, 'the same session must come back');
  const count = db.prepare("SELECT COUNT(*) AS n FROM active_walks WHERE user_id = (SELECT id FROM users WHERE email = 'aw-a@example.com')").get().n;
  assert.equal(count, 1, 'an account may have only one active walk');
});

test('the active walk is still there after a fresh client connects, which is what reopening the app does', async () => {
  const reopened = makeClient(ctx.baseUrl);
  await reopened.post('/api/auth/login', { email: 'aw-a@example.com', password: 'WalkAlice9!' });
  const res = await reopened.get('/api/activity/active');
  assert.ok(res.body.active, 'the walk must still be running after the app is reopened');
  assert.ok(res.body.active.elapsedSeconds >= 0);
});

test('samples are applied and the server reports moving or still', async () => {
  const now = Date.now();
  const samples = [[LAT0, LNG0, now - 4000], [LAT0 + 0.00006, LNG0, now - 2000], [LAT0 + 0.00012, LNG0, now - 500]];
  const res = await a.post('/api/activity/active/samples', { samples });
  assert.equal(res.status, 200);
  assert.equal(res.body.active.pointCount, 3);
  assert.ok(['moving', 'still'].includes(res.body.active.status));
});

test('invalid or too-large sample batches are refused as a whole', async () => {
  const now = Date.now();
  assert.equal((await a.post('/api/activity/active/samples', { samples: [[999, LNG0, now]] })).status, 400);
  assert.equal((await a.post('/api/activity/active/samples', { samples: [[LAT0, LNG0, now + 3_600_000]] })).status, 400, 'a sample in the future is refused');
  assert.equal((await a.post('/api/activity/active/samples', { samples: [] })).status, 400);
  const many = Array.from({ length: 201 }, () => [LAT0, LNG0, now]);
  assert.equal((await a.post('/api/activity/active/samples', { samples: many })).status, 400);
});

test('another account cannot send samples to, or stop, someone else\'s walk', async () => {
  assert.equal((await b.post('/api/activity/active/samples', { samples: [[LAT0, LNG0, Date.now()]] })).status, 404);
  assert.equal((await b.post('/api/activity/active/stop', {})).status, 404);
  const mine = await a.get('/api/activity/active');
  assert.ok(mine.body.active, 'user A\'s walk must be untouched');
});

test('stopping saves the walk to history with session time and walking time kept apart', async () => {
  const res = await a.post('/api/activity/active/stop', {});
  assert.equal(res.status, 200);
  assert.ok(res.body.session.sessionSeconds !== null, 'session time must be recorded');
  assert.ok(res.body.session.durationSeconds <= res.body.session.sessionSeconds, 'walking time can never exceed session time');
  const gone = await a.get('/api/activity/active');
  assert.equal(gone.body.active, null, 'nothing is active after stopping');
  const history = await a.get('/api/activity/sessions');
  assert.ok(history.body.sessions.some((s) => s.id === res.body.session.id));
});

test('a walk that runs past the 12-hour limit is saved automatically', async () => {
  const start = await a.post('/api/activity/active/start', {});
  db.prepare('UPDATE active_walks SET started_at = ? WHERE id = ?').run(Date.now() - 13 * 3600_000, start.body.active.id);
  const res = await a.get('/api/activity/active');
  assert.equal(res.body.active, null, 'an over-long walk must end on its own');
  const history = await a.get('/api/activity/sessions');
  assert.ok(history.body.sessions.some((s) => s.sessionSeconds >= 12 * 3600 - 5), 'the auto-saved walk must keep its capped session time');
});

test('starting or stopping a walk without a CSRF token is refused', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'Walk C', email: 'aw-c@example.com', password: 'WalkCarol9!', recoveryEmail: 'aw-c@example.com' });
  c.setCsrf('');
  assert.equal((await c.post('/api/activity/active/start', {})).status, 403);
});
