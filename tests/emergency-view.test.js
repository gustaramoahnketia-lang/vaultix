import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';
import { db } from '../server/db.js';
import { releaseDue } from '../server/emergency.js';

let ctx, owner, other, id, secret;
before(async () => {
  ctx = await startTestServer();
  owner = makeClient(ctx.baseUrl);
  other = makeClient(ctx.baseUrl);
  await owner.post('/api/auth/register', { name: 'Own', email: 'view-own@example.com', password: 'ViewOwn9!', recoveryEmail: 'view-own@example.com' });
  await other.post('/api/auth/register', { name: 'Oth', email: 'view-oth@example.com', password: 'ViewOth9!', recoveryEmail: 'view-oth@example.com' });
  await owner.post('/api/vault/items', { type: 'password', title: 'Owner Bank', payload: { password: 'OwnerBankPw9!' } });
  await other.post('/api/vault/items', { type: 'password', title: 'Other Secret', payload: { password: 'OtherPw9!' } });
  const inv = await owner.post('/api/emergency', { contactName: 'Ama', contactEmail: 'ama-view@example.com', waitDays: 7 });
  id = inv.body.contact.id; secret = inv.body.secret;
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('the contact cannot view anything before release', async () => {
  await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/request`, { secret });
  const res = await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/view`, { secret });
  assert.equal(res.status, 403);
});

test('after release, the contact sees the owner\'s items and not another owner\'s', async () => {
  db.prepare('UPDATE emergency_access SET release_at = ? WHERE id = ?').run(Date.now() - 1000, id);
  releaseDue();
  const res = await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/view`, { secret });
  assert.equal(res.status, 200);
  assert.ok(res.body.items.some((i) => i.title === 'Owner Bank' && i.payload.password === 'OwnerBankPw9!'), 'the owner\'s real item must be readable');
  assert.ok(!res.body.items.some((i) => i.title === 'Other Secret'), 'another owner\'s item must never be returned');
});

test('a wrong secret cannot view the vault even after release', async () => {
  const res = await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/view`, { secret: 'not-the-secret' });
  assert.equal(res.status, 401);
});

test('a revoked contact cannot view the vault', async () => {
  const inv = await owner.post('/api/emergency', { contactName: 'Kofi', contactEmail: 'kofi-view@example.com', waitDays: 7 });
  const rid = inv.body.contact.id, rsec = inv.body.secret;
  db.prepare("UPDATE emergency_access SET status = 'released', released_at = ? WHERE id = ?").run(Date.now(), rid);
  await owner.post(`/api/emergency/${rid}/revoke`, {});
  const res = await makeClient(ctx.baseUrl).post(`/api/emergency/${rid}/view`, { secret: rsec });
  assert.equal(res.status, 403, 'a revoked contact must lose access even if the status was once released');
});
