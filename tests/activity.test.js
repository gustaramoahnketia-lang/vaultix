import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, user;
before(async () => {
  ctx = await startTestServer();
  user = makeClient(ctx.baseUrl);
  await user.post('/api/auth/register', { name: 'Activity Tester', email: 'activitytester@example.com', password: 'ActivityTest9!', recoveryEmail: 'activitytester@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

// Two points roughly 1km apart (central Accra area), 10 minutes apart —
// a plausible walking session.
function samplePoints() {
  const start = Date.now() - 10 * 60000;
  return [
    [5.6037, -0.1870, start],
    [5.6046, -0.1870, start + 5 * 60000], // ~0.1 degree-ish shift north, roughly 1km
    [5.6055, -0.1870, start + 10 * 60000],
  ];
}

test('saving a walking session computes real distance server-side from the points, not from a client-supplied number', async () => {
  const points = samplePoints();
  const res = await user.post('/api/activity/sessions', {
    points, startTime: points[0][2], endTime: points[points.length - 1][2],
  });
  assert.equal(res.status, 201);
  assert.ok(res.body.session.distanceMeters > 0, 'distance should be computed from the actual points');
  assert.ok(res.body.session.durationSeconds > 0);
  assert.equal(res.body.session.points.length, 3);
});

test('a client-supplied distance is ignored entirely — only the points matter', async () => {
  const points = samplePoints();
  const res = await user.post('/api/activity/sessions', {
    points, startTime: points[0][2], endTime: points[points.length - 1][2],
    distanceMeters: 999999999, // an absurd claimed distance — must be ignored
  });
  assert.ok(res.body.session.distanceMeters < 100000, 'server must compute distance itself, never trust a client-supplied value');
});

test('session validation rejects malformed or implausible data', async () => {
  const tooFewPoints = await user.post('/api/activity/sessions', { points: [[5.6, -0.18, Date.now()]], startTime: Date.now() - 1000, endTime: Date.now() });
  assert.equal(tooFewPoints.status, 400);

  const badLat = await user.post('/api/activity/sessions', {
    points: [[999, -0.18, Date.now() - 1000], [5.6, -0.18, Date.now()]], startTime: Date.now() - 1000, endTime: Date.now(),
  });
  assert.equal(badLat.status, 400);

  const now = Date.now();
  const tooLong = await user.post('/api/activity/sessions', {
    points: [[5.6, -0.18, now], [5.61, -0.18, now + 7 * 60 * 60 * 1000]],
    startTime: now, endTime: now + 7 * 60 * 60 * 1000,
  });
  assert.equal(tooLong.status, 400, 'a session over 6 hours should be rejected');
});

test('list, get, and delete sessions — all ownership-scoped', async () => {
  const points = samplePoints();
  const created = await user.post('/api/activity/sessions', { points, startTime: points[0][2], endTime: points[2][2] });
  const id = created.body.session.id;

  const list = await user.get('/api/activity/sessions');
  assert.ok(list.body.sessions.some((s) => s.id === id));

  const fetched = await user.get(`/api/activity/sessions/${id}`);
  assert.equal(fetched.status, 200);

  const attacker = makeClient(ctx.baseUrl);
  await attacker.post('/api/auth/register', { name: 'ActivityAttacker', email: 'activityattacker@example.com', password: 'ActivityAttacker9!', recoveryEmail: 'activityattacker@example.com' });
  const stolen = await attacker.get(`/api/activity/sessions/${id}`);
  assert.equal(stolen.status, 404);
  const badDelete = await attacker.delete(`/api/activity/sessions/${id}`);
  assert.equal(badDelete.status, 404);

  const deleted = await user.delete(`/api/activity/sessions/${id}`);
  assert.equal(deleted.status, 200);
  const goneCheck = await user.get(`/api/activity/sessions/${id}`);
  assert.equal(goneCheck.status, 404);
});

test('activity sessions are isolated per user', async () => {
  const owner = makeClient(ctx.baseUrl);
  await owner.post('/api/auth/register', { name: 'WalkOwner', email: 'walkowner@example.com', password: 'WalkOwner9!', recoveryEmail: 'walkowner@example.com' });
  const points = samplePoints();
  await owner.post('/api/activity/sessions', { points, startTime: points[0][2], endTime: points[2][2] });

  const attacker = makeClient(ctx.baseUrl);
  await attacker.post('/api/auth/register', { name: 'WalkAttacker', email: 'walkattacker@example.com', password: 'WalkAttacker9!', recoveryEmail: 'walkattacker@example.com' });
  const attackerList = await attacker.get('/api/activity/sessions');
  assert.equal(attackerList.body.sessions.length, 0, "an attacker's session list must never include another user's walks");
});

test('activity query never fabricates step counts, and reports "no data" honestly when nothing is recorded', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'NoDataUser', email: 'nodatauser@example.com', password: 'NoDataUser9!', recoveryEmail: 'nodatauser@example.com' });

  const noData = await c.get('/api/activity/query?q=' + encodeURIComponent('How many steps did I take today?'));
  assert.equal(noData.body.hasData, false);
  assert.match(noData.body.answer, /steps.*aren't available|No recorded walking sessions/i);
  assert.doesNotMatch(noData.body.answer, /\d+ steps/, 'must never report a fabricated step count');

  const points = samplePoints();
  await c.post('/api/activity/sessions', { points, startTime: points[0][2], endTime: points[2][2] });
  const withData = await c.get('/api/activity/query?q=' + encodeURIComponent('How far did I walk today?'));
  assert.equal(withData.body.hasData, true);
  assert.match(withData.body.answer, /miles of walking today/);
});

test('activity results are integrated into the main search endpoint', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'SearchWalkUser', email: 'searchwalkuser@example.com', password: 'SearchWalkUser9!', recoveryEmail: 'searchwalkuser@example.com' });
  const points = samplePoints();
  await c.post('/api/activity/sessions', { points, startTime: points[0][2], endTime: points[2][2] });

  const res = await c.get('/api/search?q=walking');
  assert.ok(res.body.activity, 'a "walking" search should include an activity answer');
  assert.equal(res.body.activity.hasData, true);
});
