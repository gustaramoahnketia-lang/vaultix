// Tests for the API path (synthetic inputs). Real-device accuracy is not tested here.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';
import { db } from '../server/db.js';

let ctx, u, other;
const LAT0 = 5.6037, LNG0 = -0.1870;
before(async () => {
  ctx = await startTestServer();
  u = makeClient(ctx.baseUrl);
  other = makeClient(ctx.baseUrl);
  await u.post('/api/auth/register', { name: 'Mov U', email: 'mov-u@example.com', password: 'MovUser9!', recoveryEmail: 'mov-u@example.com' });
  await other.post('/api/auth/register', { name: 'Mov O', email: 'mov-o@example.com', password: 'MovOther9!', recoveryEmail: 'mov-o@example.com' });
  await u.post('/api/activity/active/start', {});
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('motion readings are accepted with GPS samples, and the walking state is reported', async () => {
  const now = Date.now();
  const motion = [];
  for (let i = 0; i < 10; i++) motion.push({ t: now - 20000 + i * 2000, steps: 4, rms: 1.5 });
  const res = await u.post('/api/activity/active/samples', { samples: [[LAT0, LNG0, now - 20000, 5]], motion });
  assert.equal(res.status, 200);
  assert.equal(res.body.active.movement.state, 'WALKING');
  assert.equal(res.body.active.movement.motionAvailable, true);
  assert.equal(res.body.active.movement.trackingQuality, 'good', 'a fix 20 s old with 5 m accuracy plus fresh motion is good quality');
});

test('a batch of motion readings alone is accepted (no GPS fix in that batch)', async () => {
  const now = Date.now();
  const res = await u.post('/api/activity/active/samples', { samples: [], motion: [{ t: now - 2000, steps: 0, rms: 0.05 }] });
  assert.equal(res.status, 200);
});

test('an empty batch with no motion and no samples is refused', async () => {
  assert.equal((await u.post('/api/activity/active/samples', { samples: [], motion: [] })).status, 400);
});

test('a motion reading with an impossible step count is refused, and nothing in that batch is saved', async () => {
  const now = Date.now();
  const before = (await u.get('/api/activity/active')).body.active.movement.walkingSeconds;
  const res = await u.post('/api/activity/active/samples', { samples: [], motion: [{ t: now - 2000, steps: 500, rms: 1 }] });
  assert.equal(res.status, 400);
  const after = (await u.get('/api/activity/active')).body.active.movement.walkingSeconds;
  assert.equal(after, before, 'a refused batch must not change the walk');
});

test('a motion reading with a non-number level, or a timestamp far in the future, is refused', async () => {
  const now = Date.now();
  assert.equal((await u.post('/api/activity/active/samples', { samples: [], motion: [{ t: now, steps: 1, rms: 'loud' }] })).status, 400);
  assert.equal((await u.post('/api/activity/active/samples', { samples: [], motion: [{ t: now + 3_600_000, steps: 1, rms: 1 }] })).status, 400);
});

test('a GPS fix with an accuracy outside a sane range is refused', async () => {
  assert.equal((await u.post('/api/activity/active/samples', { samples: [[LAT0, LNG0, Date.now(), -5]], motion: [] })).status, 400);
});

test('another account cannot send motion readings to this walk', async () => {
  assert.equal((await other.post('/api/activity/active/samples', { samples: [], motion: [{ t: Date.now(), steps: 1, rms: 1 }] })).status, 404);
});

test('a walk saved by the earlier version, with no motion fields, still loads and gets the new fields', async () => {
  const old = makeClient(ctx.baseUrl);
  await old.post('/api/auth/register', { name: 'Old Walk', email: 'old-walk@example.com', password: 'OldWalk9!', recoveryEmail: 'old-walk@example.com' });
  const started = await old.post('/api/activity/active/start', {});
  const legacyState = JSON.stringify({ lastLat: LAT0, lastLng: LNG0, lastT: Date.now() - 1000, anchorLat: LAT0, anchorLng: LNG0, anchorT: Date.now() - 1000, moving: false, movingMs: 5000, distanceM: 12, points: [] });
  db.prepare('UPDATE active_walks SET state = ? WHERE id = ?').run(legacyState, started.body.active.id);
  const res = await old.get('/api/activity/active');
  assert.equal(res.status, 200);
  assert.equal(res.body.active.movement.state, 'UNCERTAIN', 'with no motion data yet, the state is honest: UNCERTAIN');
  assert.equal(res.body.active.movingSeconds, 5, 'the old moving time is preserved');
});

test('stopping a walk saves walking time separately from GPS moving time', async () => {
  const stopped = await u.post('/api/activity/active/stop', {});
  assert.equal(stopped.status, 200);
  assert.ok('walkingSeconds' in stopped.body.session, 'history must include walkingSeconds');
});
