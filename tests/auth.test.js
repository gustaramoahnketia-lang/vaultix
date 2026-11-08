import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx;
before(async () => { ctx = await startTestServer(); });
after(async () => { await ctx.close(); ctx.cleanup(); });

test('registration creates an account and immediately unlocks a session', async () => {
  const c = makeClient(ctx.baseUrl);
  const res = await c.post('/api/auth/register', {
    name: 'Gustar', email: 'gustar@example.com', password: 'CorrectHorseBattery9!', recoveryEmail: 'gustar@example.com',
  });
  assert.equal(res.status, 201);
  assert.equal(res.body.user.email, 'gustar@example.com');
  assert.match(res.body.recoveryKey, /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  assert.ok(c.getCookie().includes('vx_session='));

  const me = await c.get('/api/auth/me');
  assert.equal(me.status, 200);
  assert.equal(me.body.unlocked, true);
});

test('registering the same email twice is rejected', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'Dup', email: 'dup@example.com', password: 'CorrectHorseBattery9!', recoveryEmail: 'dup@example.com' });
  const res2 = await c.post('/api/auth/register', { name: 'Dup2', email: 'dup@example.com', password: 'AnotherPassw0rd!', recoveryEmail: 'dup@example.com' });
  assert.equal(res2.status, 409);
});

test('login succeeds with correct password and fails with wrong password', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'LoginUser', email: 'login@example.com', password: 'CorrectHorseBattery9!', recoveryEmail: 'login@example.com' });
  await c.post('/api/auth/logout', {});

  const fresh = makeClient(ctx.baseUrl);
  const bad = await fresh.post('/api/auth/login', { email: 'login@example.com', password: 'WrongPassword!' });
  assert.equal(bad.status, 401);
  assert.equal(bad.body.error, 'Invalid email or password.'); // generic message, no account-enumeration detail

  const good = await fresh.post('/api/auth/login', { email: 'login@example.com', password: 'CorrectHorseBattery9!' });
  assert.equal(good.status, 200);
  assert.equal(good.body.user.email, 'login@example.com');
});

test('unknown email at login returns the same generic error as a wrong password', async () => {
  const c = makeClient(ctx.baseUrl);
  const res = await c.post('/api/auth/login', { email: 'nobody-here@example.com', password: 'whatever123' });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'Invalid email or password.');
});

test('the stored password hash is never the plaintext password, and is a real scrypt verifier', async () => {
  const c = makeClient(ctx.baseUrl);
  const plaintext = 'CorrectHorseBattery9!';
  await c.post('/api/auth/register', { name: 'HashCheck', email: 'hashcheck@example.com', password: plaintext, recoveryEmail: 'hashcheck@example.com' });

  const { db } = await import('../server/db.js');
  const row = db.prepare('SELECT password_hash FROM users WHERE email = ?').get('hashcheck@example.com');
  assert.notEqual(row.password_hash, plaintext);
  assert.ok(!row.password_hash.includes(plaintext));
  assert.match(row.password_hash, /^scrypt\$\d+\$\d+\$\d+\$[0-9a-f]+\$[0-9a-f]+$/);
});

test('logout clears the session so protected routes reject it afterwards', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'LogoutUser', email: 'logout@example.com', password: 'CorrectHorseBattery9!', recoveryEmail: 'logout@example.com' });
  const out = await c.post('/api/auth/logout', {});
  assert.equal(out.status, 200);
  const me = await c.get('/api/auth/me');
  assert.equal(me.status, 401);
});

test('mutating requests without a valid CSRF token are rejected', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'CsrfUser', email: 'csrf@example.com', password: 'CorrectHorseBattery9!', recoveryEmail: 'csrf@example.com' });
  c.setCsrf('not-the-real-token');
  const res = await c.post('/api/auth/lock', {});
  assert.equal(res.status, 403);
});
