import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

// Committed regression tests for the security review of the calendar and
// activity modules. Each test runs against the real HTTP server with two
// real, separately-authenticated accounts. These are the cross-user checks
// the spec calls out explicitly: User A cannot access User B's calendar,
// activity, or walking sessions.

let ctx, a, b, eventId, sessionId;
const day = new Date().toISOString().slice(0, 10);

before(async () => {
  ctx = await startTestServer();
  a = makeClient(ctx.baseUrl);
  b = makeClient(ctx.baseUrl);
  await a.post('/api/auth/register', { name: 'Iso A', email: 'iso-a@example.com', password: 'IsoAlice9!', recoveryEmail: 'iso-a@example.com' });
  await b.post('/api/auth/register', { name: 'Iso B', email: 'iso-b@example.com', password: 'IsoBob9!', recoveryEmail: 'iso-b@example.com' });

  const ev = await a.post('/api/events', { title: 'PRIVATE_A_EVENT', startDate: day, eventType: 'appointment' });
  eventId = ev.body.event.id;

  const pts = [[5.6, -0.18, Date.now() - 600000], [5.601, -0.18, Date.now()]];
  const walk = await a.post('/api/activity/sessions', { points: pts, startTime: pts[0][2], endTime: pts[1][2] });
  sessionId = walk.body.session.id;
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('User B cannot list User A calendar events', async () => {
  const res = await b.get(`/api/events?from=${day}&to=${day}`);
  assert.equal(res.status, 200);
  assert.ok(!res.body.events.some((e) => e.title === 'PRIVATE_A_EVENT'));
});

test('User B cannot read, complete, duplicate, or delete User A event by id', async () => {
  assert.equal((await b.get(`/api/events/${eventId}`)).status, 404);
  assert.equal((await b.post(`/api/events/${eventId}/complete`, { completed: true })).status, 404);
  assert.equal((await b.post(`/api/events/${eventId}/duplicate`, {})).status, 404);
  assert.equal((await b.delete(`/api/events/${eventId}`)).status, 404);
});

test('User B search never returns User A calendar events', async () => {
  const res = await b.get('/api/search?q=PRIVATE_A_EVENT');
  assert.equal(res.body.events.length, 0);
});

test('User B cannot list, read, or delete User A walking sessions', async () => {
  const list = await b.get('/api/activity/sessions');
  assert.equal(list.body.sessions.length, 0);
  assert.equal((await b.get(`/api/activity/sessions/${sessionId}`)).status, 404);
  assert.equal((await b.delete(`/api/activity/sessions/${sessionId}`)).status, 404);
});

test('User B activity summary and natural-language query never reflect User A walks', async () => {
  const summary = await b.get(`/api/activity/summary?from=0&to=${Date.now() + 1e9}`);
  assert.equal(summary.body.hasData, false);
  const query = await b.get('/api/activity/query?q=' + encodeURIComponent('how far did I walk today'));
  assert.equal(query.body.hasData, false);
});

test('User A still sees their own calendar event and walking session', async () => {
  assert.equal((await a.get(`/api/events/${eventId}`)).status, 200);
  assert.equal((await a.get(`/api/activity/sessions/${sessionId}`)).status, 200);
});

test('state-changing calendar and activity routes reject a request without a CSRF token', async () => {
  const noCsrf = makeClient(ctx.baseUrl);
  // Log in as A but send no CSRF header on writes.
  await noCsrf.post('/api/auth/login', { email: 'iso-a@example.com', password: 'IsoAlice9!' });
  noCsrf.setCsrf('');
  assert.equal((await noCsrf.post('/api/events', { title: 'x', startDate: day })).status, 403);
  assert.equal((await noCsrf.post('/api/activity/sessions', { points: [[5.6, -0.18, 1], [5.601, -0.18, 2]], startTime: 1, endTime: 2 })).status, 403);
});
