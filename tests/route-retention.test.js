import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';
import { db } from '../server/db.js';
import { pruneExpiredRoutes, ROUTE_RETENTION_MS, MAX_ROUTE_POINTS } from '../server/activity.js';

let ctx, a, b;
before(async () => {
  ctx = await startTestServer();
  a = makeClient(ctx.baseUrl);
  b = makeClient(ctx.baseUrl);
  await a.post('/api/auth/register', { name: 'Ret A', email: 'ret-a@example.com', password: 'RetAlice9!', recoveryEmail: 'ret-a@example.com' });
  await b.post('/api/auth/register', { name: 'Ret B', email: 'ret-b@example.com', password: 'RetBob9!', recoveryEmail: 'ret-b@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

function twoPoints(start = Date.now() - 600000) {
  return [[5.6, -0.18, start], [5.601, -0.18, start + 600000]];
}

// Helper: force a session's end_time into the past, simulating age, without
// waiting 30 days. This is the only way to test the window deterministically.
function ageSession(id, msAgo) {
  db.prepare('UPDATE walking_sessions SET end_time = ?, start_time = ? WHERE id = ?')
    .run(Date.now() - msAgo, Date.now() - msAgo - 600000, id);
}

test('the retention window is 30 days and the point cap is 2000 (documented values)', () => {
  assert.equal(ROUTE_RETENTION_MS, 30 * 24 * 60 * 60 * 1000);
  assert.equal(MAX_ROUTE_POINTS, 2000);
});

test('a route trail older than the window is removed, but the session summary survives', async () => {
  const pts = twoPoints();
  const created = await a.post('/api/activity/sessions', { points: pts, startTime: pts[0][2], endTime: pts[1][2] });
  const id = created.body.session.id;
  const distanceBefore = created.body.session.distanceMeters;

  ageSession(id, ROUTE_RETENTION_MS + 60000); // just past the window
  const cleared = pruneExpiredRoutes();
  assert.ok(cleared >= 1, 'the sweep should report at least one cleared trail');

  const after1 = await a.get(`/api/activity/sessions/${id}`);
  assert.equal(after1.status, 200, 'the session row itself must still exist');
  assert.equal(after1.body.session.points.length, 0, 'the location trail must be gone');
  assert.equal(Math.round(after1.body.session.distanceMeters), Math.round(distanceBefore), 'the distance summary must be kept');
});

test('a trail inside the window is NOT removed', async () => {
  const pts = twoPoints();
  const created = await a.post('/api/activity/sessions', { points: pts, startTime: pts[0][2], endTime: pts[1][2] });
  const id = created.body.session.id;
  pruneExpiredRoutes();
  const fresh = await a.get(`/api/activity/sessions/${id}`);
  assert.equal(fresh.body.session.points.length, 2, 'a recent trail must survive the sweep');
});

test('the sweep never touches another user\'s trail and only reports real changes', async () => {
  const pts = twoPoints();
  const bSession = await b.post('/api/activity/sessions', { points: pts, startTime: pts[0][2], endTime: pts[1][2] });
  const bid = bSession.body.session.id;
  ageSession(bid, ROUTE_RETENTION_MS + 60000);

  pruneExpiredRoutes(); // B's trail is expired and gets cleared here
  const second = pruneExpiredRoutes(); // running again finds nothing new to clear
  assert.equal(second, 0, 'a second sweep must not report changes already made');

  const bAfter = await b.get(`/api/activity/sessions/${bid}`);
  assert.equal(bAfter.body.session.points.length, 0);
  // A's still-fresh session from the previous test must be untouched:
  const aList = await a.get('/api/activity/sessions');
  assert.ok(aList.body.sessions.some((s) => s.points.length === 2), 'the sweep must not clear other users\' fresh trails');
});

test('the caller can clear one session\'s trail on demand, and it is ownership-scoped', async () => {
  const pts = twoPoints();
  const created = await a.post('/api/activity/sessions', { points: pts, startTime: pts[0][2], endTime: pts[1][2] });
  const id = created.body.session.id;

  const cleared = await a.post(`/api/activity/sessions/${id}/clear-route`, {});
  assert.equal(cleared.status, 200);
  assert.equal(cleared.body.session.points.length, 0);
  assert.ok(cleared.body.session.distanceMeters > 0, 'clearing the trail must keep the distance');

  const attackerClear = await b.post(`/api/activity/sessions/${id}/clear-route`, {});
  assert.equal(attackerClear.status, 404, 'another user must not clear this trail');
});

test('a session with too many route points is rejected by the server, not just the client', async () => {
  const many = [];
  const t0 = Date.now() - 3600000;
  for (let i = 0; i <= MAX_ROUTE_POINTS; i++) many.push([5.6 + i * 1e-7, -0.18, t0 + i * 1000]);
  const res = await a.post('/api/activity/sessions', { points: many, startTime: t0, endTime: t0 + MAX_ROUTE_POINTS * 1000 });
  assert.equal(res.status, 400, 'a request over the server cap must be refused');
});
