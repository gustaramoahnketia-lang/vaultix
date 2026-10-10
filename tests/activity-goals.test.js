import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, a, b;
before(async () => {
  ctx = await startTestServer();
  a = makeClient(ctx.baseUrl);
  b = makeClient(ctx.baseUrl);
  await a.post('/api/auth/register', { name: 'Goal A', email: 'goal-a@example.com', password: 'GoalAlice9!', recoveryEmail: 'goal-a@example.com' });
  await b.post('/api/auth/register', { name: 'Goal B', email: 'goal-b@example.com', password: 'GoalBob9!', recoveryEmail: 'goal-b@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

// A walk of roughly `miles` that started `minutesAgo` minutes ago and lasted
// `durationMin` minutes. Points are spaced to produce about the requested
// distance at a plausible walking pace.
function walkOf(miles, durationMin, minutesAgo = 5) {
  const meters = miles * 1609.344;
  const steps = 20;
  const start = Date.now() - minutesAgo * 60000;
  const dLat = (meters / 111320) / steps;
  const pts = [];
  for (let i = 0; i <= steps; i++) {
    pts.push([5.6 + i * dLat, -0.18, start + Math.round(i * (durationMin * 60000) / steps)]);
  }
  return { points: pts, startTime: start, endTime: start + durationMin * 60000 };
}

test('a new user has no goal, and progress shows no percentage rather than an invented one', async () => {
  const res = await a.get('/api/activity/goal');
  assert.equal(res.status, 200);
  assert.equal(res.body.goal, null);
  assert.equal(res.body.distancePct, null, 'no goal must mean no percentage');
  assert.equal(res.body.timePct, null);
  assert.equal(res.body.goalMet, false);
});

test('setting a goal stores it, and progress is 0% before any walk today', async () => {
  const set = await a.put('/api/activity/goal', { dailyDistanceMiles: 2, dailyWalkMinutes: 30 });
  assert.equal(set.status, 200);
  assert.equal(set.body.goal.dailyDistanceMiles, 2);
  assert.equal(set.body.goal.dailyWalkMinutes, 30);
  assert.equal(set.body.distancePct, 0);
});

test('progress is computed from real recorded walks, not stored, and moves with them', async () => {
  // Use a walk that ends now so it counts as today.
  const w = walkOf(1, 15, 10);
  const created = await a.post('/api/activity/sessions', w);
  assert.equal(created.status, 201);
  const res = await a.get('/api/activity/goal');
  assert.ok(res.body.today.miles > 0.5, 'today\'s miles must reflect the recorded walk');
  assert.ok(res.body.distancePct >= 40 && res.body.distancePct <= 60, `expected about 50% of a 2-mile goal, got ${res.body.distancePct}`);
  assert.equal(res.body.timePct, Math.min(100, Math.round((res.body.today.minutes / 30) * 100)));
});

test('goal met is true only when every target that is set has been reached', async () => {
  await a.put('/api/activity/goal', { dailyDistanceMiles: 0.5, dailyWalkMinutes: null });
  const res = await a.get('/api/activity/goal');
  assert.equal(res.body.goalMet, true, 'a 0.5 mile goal is met by a 1 mile walk today');
  await a.put('/api/activity/goal', { dailyDistanceMiles: 50, dailyWalkMinutes: null });
  const big = await a.get('/api/activity/goal');
  assert.equal(big.body.goalMet, false, 'a 50 mile goal is not met');
  assert.equal(big.body.distancePct < 100, true);
});

test('clearing a goal removes it and progress returns to "no goal"', async () => {
  const cleared = await a.put('/api/activity/goal', { dailyDistanceMiles: null, dailyWalkMinutes: null });
  assert.equal(cleared.status, 200);
  const res = await a.get('/api/activity/goal');
  assert.equal(res.body.goal, null);
  assert.equal(res.body.distancePct, null);
});

test('out-of-range goals are refused, so a typo cannot create an absurd target', async () => {
  assert.equal((await a.put('/api/activity/goal', { dailyDistanceMiles: 0 })).status, 400);
  assert.equal((await a.put('/api/activity/goal', { dailyDistanceMiles: -3 })).status, 400);
  assert.equal((await a.put('/api/activity/goal', { dailyDistanceMiles: 100000 })).status, 400);
  assert.equal((await a.put('/api/activity/goal', { dailyWalkMinutes: 99999 })).status, 400);
  assert.equal((await a.put('/api/activity/goal', { dailyDistanceMiles: 'banana' })).status, 400);
});

test('goals and progress are isolated per user', async () => {
  await a.put('/api/activity/goal', { dailyDistanceMiles: 3, dailyWalkMinutes: null });
  const bRes = await b.get('/api/activity/goal');
  assert.equal(bRes.body.goal, null, 'user B must not see user A\'s goal');
  assert.equal(bRes.body.today.miles, 0, 'user B must not see user A\'s walks in progress');
});

test('a goal write without a CSRF token is refused', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'Goal C', email: 'goal-c@example.com', password: 'GoalCarol9!', recoveryEmail: 'goal-c@example.com' });
  c.setCsrf('');
  assert.equal((await c.put('/api/activity/goal', { dailyDistanceMiles: 2 })).status, 403);
});
