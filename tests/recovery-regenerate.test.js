import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, c, oldKey;
const EMAIL = 'regen@example.com';
const PASSWORD = 'RegenPass9!';
const day = new Date().toISOString().slice(0, 10);

// The recovery flow needs a one-time code. The server prints it to the console
// in this build, so the test reads it from the in-memory store.
import { issueRecoveryCode } from '../server/store.js';
import { db } from '../server/db.js';

before(async () => {
  ctx = await startTestServer();
  c = makeClient(ctx.baseUrl);
  const reg = await c.post('/api/auth/register', { name: 'Regen', email: EMAIL, password: PASSWORD, recoveryEmail: EMAIL });
  oldKey = reg.body.recoveryKey;
  await c.post('/api/vault/items', { type: 'note', title: 'Keep me', payload: { content: 'my private note' } });
  await c.post('/api/events', { title: 'Keep this event', startDate: day });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

// Runs the real recovery reset with a given key. Returns the HTTP status.
async function tryRecovery(key, newPassword) {
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(EMAIL);
  const code = issueRecoveryCode(user.id);
  const r = makeClient(ctx.baseUrl);
  return (await r.post('/api/recovery/reset', { email: EMAIL, code, recoveryKey: key, newPassword })).status;
}

test('regenerating requires the master password, and a wrong one changes nothing', async () => {
  await c.post('/api/auth/unlock/password', { password: PASSWORD });
  const res = await c.post('/api/auth/recovery-key/regenerate', { currentPassword: 'WrongPass9!' });
  assert.equal(res.status, 401);
});

test('regenerating returns a new key that differs from the old one', async () => {
  const res = await c.post('/api/auth/recovery-key/regenerate', { currentPassword: PASSWORD });
  assert.equal(res.status, 200);
  assert.match(res.body.recoveryKey, /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  assert.notEqual(res.body.recoveryKey, oldKey);
  oldKey = oldKey; // keep the old key available for the test below
  c.newKey = res.body.recoveryKey;
});

test('the OLD recovery key no longer works after regeneration', async () => {
  const status = await tryRecovery(oldKey, 'AfterOld9!');
  assert.equal(status, 401, 'the superseded key must be refused');
});

test('the NEW recovery key works and recovers the same vault data', async () => {
  const status = await tryRecovery(c.newKey, 'RecoveredPass9!');
  assert.equal(status, 200, 'the new key must open recovery');
  const login = makeClient(ctx.baseUrl);
  assert.equal((await login.post('/api/auth/login', { email: EMAIL, password: 'RecoveredPass9!' })).status, 200);
  assert.equal((await login.post('/api/auth/unlock/password', { password: 'RecoveredPass9!' })).status, 200);
  const items = await login.get('/api/vault/items?type=note');
  assert.ok(items.body.items.some((i) => i.title === 'Keep me'), 'the vault must still hold its data after recovery');
  const events = await login.get(`/api/events?from=${day}&to=${day}`);
  assert.ok(events.body.events.some((e) => e.title === 'Keep this event'), 'events must survive recovery');
});

test('regenerating without an unlocked vault is refused', async () => {
  const locked = makeClient(ctx.baseUrl);
  await locked.post('/api/auth/login', { email: EMAIL, password: 'RecoveredPass9!' });
  // A password login leaves the vault unlocked. Lock it explicitly, so this
  // test exercises a genuinely locked session.
  await locked.post('/api/auth/lock', {});
  const res = await locked.post('/api/auth/recovery-key/regenerate', { currentPassword: 'RecoveredPass9!' });
  assert.equal(res.status, 423, 'regeneration must need the vault to be unlocked');
});

test('regenerating without a CSRF token is refused', async () => {
  await c.post('/api/auth/unlock/password', { password: 'RecoveredPass9!' });
  c.setCsrf('');
  assert.equal((await c.post('/api/auth/recovery-key/regenerate', { currentPassword: 'RecoveredPass9!' })).status, 403);
});
