import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, a, b;
before(async () => {
  ctx = await startTestServer();
  a = makeClient(ctx.baseUrl);
  b = makeClient(ctx.baseUrl);
  await a.post('/api/auth/register', { name: 'Pref A', email: 'pref-a@example.com', password: 'PrefAlice9!', recoveryEmail: 'pref-a@example.com' });
  await b.post('/api/auth/register', { name: 'Pref B', email: 'pref-b@example.com', password: 'PrefBob9!', recoveryEmail: 'pref-b@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('a new account defaults to a 60-day upcoming window', async () => {
  const res = await a.get('/api/preferences');
  assert.equal(res.status, 200);
  assert.equal(res.body.upcomingWindowDays, 60);
});

test('saving 1 year persists on the account and is returned on the next read', async () => {
  const save = await a.put('/api/preferences/upcoming-window', { days: 365 });
  assert.equal(save.status, 200);
  assert.equal(save.body.upcomingWindowDays, 365);
  const again = await a.get('/api/preferences');
  assert.equal(again.body.upcomingWindowDays, 365, 'the saved value must be read back from the server');
});

test('the preference follows the account to a new session (another device)', async () => {
  await a.put('/api/preferences/upcoming-window', { days: 180 });
  const otherDevice = makeClient(ctx.baseUrl);
  await otherDevice.post('/api/auth/login', { email: 'pref-a@example.com', password: 'PrefAlice9!' });
  const res = await otherDevice.get('/api/preferences');
  assert.equal(res.body.upcomingWindowDays, 180, 'a fresh login on another device must see the account value');
});

test('values outside the allowlist are rejected, so the server cannot store arbitrary windows', async () => {
  for (const bad of [0, 7, 500, -30, 'banana', 60.5, null]) {
    const res = await a.put('/api/preferences/upcoming-window', { days: bad });
    assert.equal(res.status, 400, `value ${JSON.stringify(bad)} must be refused`);
  }
  const still = await a.get('/api/preferences');
  assert.equal(still.body.upcomingWindowDays, 180, 'a refused value must not change the stored preference');
});

test('user B cannot read or change user A\'s preference', async () => {
  await a.put('/api/preferences/upcoming-window', { days: 90 });
  const bRead = await b.get('/api/preferences');
  assert.equal(bRead.body.upcomingWindowDays, 60, 'user B must see only their own default');
  await b.put('/api/preferences/upcoming-window', { days: 30 });
  const aRead = await a.get('/api/preferences');
  assert.equal(aRead.body.upcomingWindowDays, 90, 'user B\'s write must not change user A');
});

test('the owner is taken from the session: a user_id in the body is ignored', async () => {
  const res = await b.put('/api/preferences/upcoming-window', { days: 365, userId: 'USER_A_ID_GUESS', user_id: 'x' });
  assert.equal(res.status, 200);
  const aRead = await a.get('/api/preferences');
  assert.equal(aRead.body.upcomingWindowDays, 90, 'a forged user id in the body must not reach user A');
});

test('a preference write without a CSRF token is refused', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'Pref C', email: 'pref-c@example.com', password: 'PrefCarol9!', recoveryEmail: 'pref-c@example.com' });
  c.setCsrf('');
  assert.equal((await c.put('/api/preferences/upcoming-window', { days: 365 })).status, 403);
});

test('an unauthenticated request cannot read preferences', async () => {
  const anon = makeClient(ctx.baseUrl);
  assert.equal((await anon.get('/api/preferences')).status, 401);
});
