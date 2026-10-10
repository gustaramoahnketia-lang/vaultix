import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, a, other;
before(async () => {
  ctx = await startTestServer();
  a = makeClient(ctx.baseUrl);
  other = makeClient(ctx.baseUrl);
  await a.post('/api/auth/register', { name: 'Old Name', email: 'acct-old@example.com', password: 'AcctPass9!', recoveryEmail: 'acct-old@example.com' });
  await other.post('/api/auth/register', { name: 'Other', email: 'acct-taken@example.com', password: 'OtherPass9!', recoveryEmail: 'acct-taken@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('the name can be changed with the master password', async () => {
  const res = await a.put('/api/auth/account-details', { name: 'New Name', email: 'acct-old@example.com', currentPassword: 'AcctPass9!' });
  assert.equal(res.status, 200);
  assert.equal(res.body.user.name, 'New Name');
});

test('a name change without the password is refused and changes nothing', async () => {
  const res = await a.put('/api/auth/account-details', { name: 'Hacked', email: 'acct-old@example.com', currentPassword: 'WrongPass9!' });
  assert.equal(res.status, 401);
  const me = await a.get('/api/auth/me');
  assert.equal(me.body.user.name, 'New Name', 'a refused change must not take effect');
});

test('the login email can be changed, and the new address signs in to the same data', async () => {
  const change = await a.put('/api/auth/account-details', { name: 'New Name', email: 'acct-new@example.com', currentPassword: 'AcctPass9!' });
  assert.equal(change.status, 200);
  const fresh = makeClient(ctx.baseUrl);
  assert.equal((await fresh.post('/api/auth/login', { email: 'acct-new@example.com', password: 'AcctPass9!' })).status, 200, 'the new email must sign in');
  assert.equal((await fresh.post('/api/auth/unlock/password', { password: 'AcctPass9!' })).status, 200);
});

test('the old login email stops working after the change', async () => {
  const fresh = makeClient(ctx.baseUrl);
  assert.equal((await fresh.post('/api/auth/login', { email: 'acct-old@example.com', password: 'AcctPass9!' })).status, 401);
});

test('an email already used by another account is refused', async () => {
  const res = await a.put('/api/auth/account-details', { name: 'New Name', email: 'acct-taken@example.com', currentPassword: 'AcctPass9!' });
  assert.equal(res.status, 409);
  const other2 = makeClient(ctx.baseUrl);
  assert.equal((await other2.post('/api/auth/login', { email: 'acct-taken@example.com', password: 'OtherPass9!' })).status, 200, 'the other account must be untouched');
});

test('an invalid email or empty name is refused', async () => {
  assert.equal((await a.put('/api/auth/account-details', { name: 'X', email: 'not-an-email', currentPassword: 'AcctPass9!' })).status, 400);
  assert.equal((await a.put('/api/auth/account-details', { name: '   ', email: 'acct-new@example.com', currentPassword: 'AcctPass9!' })).status, 400);
});

test('an account-details change without a CSRF token is refused', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'Csrf', email: 'acct-csrf@example.com', password: 'CsrfPass9!', recoveryEmail: 'acct-csrf@example.com' });
  c.setCsrf('');
  assert.equal((await c.put('/api/auth/account-details', { name: 'X', email: 'acct-csrf@example.com', currentPassword: 'CsrfPass9!' })).status, 403);
});
