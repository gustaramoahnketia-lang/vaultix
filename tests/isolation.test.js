import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx;
before(async () => { ctx = await startTestServer(); });
after(async () => { await ctx.close(); ctx.cleanup(); });

test('User A cannot access, edit, delete, or search up User B\'s vault items', async () => {
  const alice = makeClient(ctx.baseUrl);
  const bob = makeClient(ctx.baseUrl);

  await alice.post('/api/auth/register', { name: 'Alice', email: 'alice@example.com', password: 'AlicePassw0rd!', recoveryEmail: 'alice@example.com' });
  await bob.post('/api/auth/register', { name: 'Bob', email: 'bob@example.com', password: 'BobPassword0!', recoveryEmail: 'bob@example.com' });

  const bobItem = await bob.post('/api/vault/items', {
    type: 'password', title: 'BobsBank', category: 'Banking', searchUsername: 'bob@bank.com',
    payload: { password: 'BobsSecretPw1!', website: 'bobsbank.com', notes: 'private' },
  });
  assert.equal(bobItem.status, 201);
  const bobItemId = bobItem.body.item.id;

  // Direct GET by guessed/known id
  const stolenGet = await alice.get(`/api/vault/items/${bobItemId}`);
  assert.equal(stolenGet.status, 404); // not 403 — existence is not confirmed either

  // Reveal endpoint (even with a "correct-looking" re-auth payload of Alice's own password)
  const stolenReveal = await alice.post(`/api/vault/items/${bobItemId}/reveal`, { reauth: { method: 'password', value: 'AlicePassw0rd!' } });
  assert.equal(stolenReveal.status, 404);

  // Edit
  const stolenEdit = await alice.put(`/api/vault/items/${bobItemId}`, { title: 'Hacked' });
  assert.equal(stolenEdit.status, 404);

  // Delete
  const stolenDelete = await alice.delete(`/api/vault/items/${bobItemId}`);
  assert.equal(stolenDelete.status, 404);

  // Alice's own list/search must never surface Bob's item
  const aliceList = await alice.get('/api/vault/items');
  assert.ok(!aliceList.body.items.some((i) => i.id === bobItemId));

  const aliceSearch = await alice.get('/api/search?q=BobsBank');
  assert.equal(aliceSearch.body.count, 0);

  // Bob can still reach his own item normally
  const bobGet = await bob.get(`/api/vault/items/${bobItemId}`);
  assert.equal(bobGet.status, 200);
  assert.equal(bobGet.body.item.title, 'BobsBank');
});

test('sessions are bound to one account — Alice\'s cookie never authenticates as Bob', async () => {
  const alice = makeClient(ctx.baseUrl);
  await alice.post('/api/auth/register', { name: 'Alice2', email: 'alice2@example.com', password: 'AlicePassw0rd!', recoveryEmail: 'alice2@example.com' });
  const me = await alice.get('/api/auth/me');
  assert.equal(me.body.user.email, 'alice2@example.com');
});
