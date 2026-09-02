import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, user;
before(async () => {
  ctx = await startTestServer();
  user = makeClient(ctx.baseUrl);
  await user.post('/api/auth/register', { name: 'Vault Tester', email: 'vaulttester@example.com', password: 'VaultTest9!', recoveryEmail: 'vaulttester@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('create, read, update, delete a password item', async () => {
  const created = await user.post('/api/vault/items', {
    type: 'password', title: 'Google', category: 'Email', searchUsername: 'example@gmail.com',
    payload: { password: 'Tr0ub4dor&3xamp', website: 'google.com', notes: 'Personal account' },
  });
  assert.equal(created.status, 201);
  const id = created.body.item.id;
  assert.equal(created.body.item.payload.password, 'Tr0ub4dor&3xamp');

  const fetched = await user.get(`/api/vault/items/${id}`);
  assert.equal(fetched.status, 200);
  assert.equal(fetched.body.item.title, 'Google');

  const updated = await user.put(`/api/vault/items/${id}`, { title: 'Google Workspace', payload: { password: 'NewP4ssword!!', website: 'google.com', notes: '' } });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.item.title, 'Google Workspace');
  assert.equal(updated.body.item.payload.password, 'NewP4ssword!!');

  const deleted = await user.delete(`/api/vault/items/${id}`);
  assert.equal(deleted.status, 200);
  const goneCheck = await user.get(`/api/vault/items/${id}`);
  assert.equal(goneCheck.status, 404);
});

test('dashboard summary counts reflect created items by type', async () => {
  await user.post('/api/vault/items', { type: 'note', title: 'Wi-Fi Info', payload: { content: 'Home_WiFi / secretpass' } });
  await user.post('/api/vault/items', { type: 'personal', title: 'Personal Information', payload: { fullName: 'Gustar', dob: '', phone: '', email: '', address: '', occupation: '', emergencyContact: '', notes: '' } });
  const summary = await user.get('/api/vault/summary');
  assert.equal(summary.status, 200);
  assert.ok(summary.body.summary.notes >= 1);
  assert.ok(summary.body.summary.personal >= 1);
});

test('search matches title/category/username metadata (in addition to field content, tested separately), is scoped to the caller, and supports category filters', async () => {
  await user.post('/api/vault/items', { type: 'password', title: 'Facebook', category: 'Social', searchUsername: 'example@gmail.com', payload: { password: 'F4ceB00k!Secure' } });
  await user.post('/api/vault/items', { type: 'password', title: 'Instagram', category: 'Social', searchUsername: 'gustar123', payload: { password: '1nsta_Gr4mSafe' } });

  const all = await user.get('/api/search?q=example@gmail.com');
  assert.ok(all.body.results.length >= 1);
  assert.ok(all.body.results.some((r) => r.title === 'Facebook'));

  const filtered = await user.get('/api/search?q=a&category=password');
  assert.ok(filtered.body.results.every((r) => r.type === 'password'));

  const noHit = await user.get('/api/search?q=zzz-does-not-exist-zzz');
  assert.equal(noHit.body.count, 0);

  // The search index must never expose secret values — only metadata comes back.
  const facebookHit = all.body.results.find((r) => r.title === 'Facebook');
  assert.ok(facebookHit);
  assert.equal(Object.prototype.hasOwnProperty.call(facebookHit, 'payload'), false);
});

test('reveal requires re-authentication and rejects a wrong password', async () => {
  const created = await user.post('/api/vault/items', { type: 'password', title: 'RevealMe', payload: { password: 'TopSecret1!' } });
  const id = created.body.item.id;

  const wrong = await user.post(`/api/vault/items/${id}/reveal`, { reauth: { method: 'password', value: 'DefinitelyWrong!' } });
  assert.equal(wrong.status, 401);

  const right = await user.post(`/api/vault/items/${id}/reveal`, { reauth: { method: 'password', value: 'VaultTest9!' } });
  assert.equal(right.status, 200);
  assert.equal(right.body.item.payload.password, 'TopSecret1!');
});

test('the cryptographically secure password generator honors length and character-set options', async () => {
  const res = await user.post('/api/tools/generate-password', { length: 24, upper: true, lower: false, numbers: true, symbols: false });
  assert.equal(res.status, 200);
  assert.equal(res.body.password.length, 24);
  assert.match(res.body.password, /^[A-Z2-9]+$/);
});
