import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, owner, id, secret;
before(async () => {
  ctx = await startTestServer();
  owner = makeClient(ctx.baseUrl);
  await owner.post('/api/auth/register', { name: 'St', email: 'st-own@example.com', password: 'StatusOwn9!', recoveryEmail: 'st-own@example.com' });
  await owner.post('/api/vault/items', { type: 'password', title: 'Status Secret Item', payload: { password: 'StatusSecretPw9!' } });
  const inv = await owner.post('/api/emergency', { contactName: 'Efua', contactEmail: 'efua@example.com', waitDays: 14 });
  id = inv.body.contact.id; secret = inv.body.secret;
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('status reports invited before any request, so the contact is offered the request button', async () => {
  const res = await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/status`, { secret });
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'invited');
});

test('status reports requested with a release time after a request', async () => {
  await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/request`, { secret });
  const res = await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/status`, { secret });
  assert.equal(res.body.status, 'requested');
  assert.ok(res.body.releaseAt > Date.now(), 'the release time must be in the future during the wait');
});

test('status never includes vault content', async () => {
  const res = await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/status`, { secret });
  assert.ok(!JSON.stringify(res.body).includes('StatusSecretPw9!'), 'status must not expose any vault data');
  assert.ok(!JSON.stringify(res.body).includes('Status Secret Item'), 'status must not expose item titles');
});

test('status with a wrong secret is refused', async () => {
  assert.equal((await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/status`, { secret: 'wrong' })).status, 401);
});
