import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';
import { db } from '../server/db.js';
import { releaseDue } from '../server/emergency.js';
import { deriveKey, unwrapKey } from '../server/crypto.js';

let ctx, owner, contactId, contactSecret;
const OWNER = 'ea-owner@example.com';
const PASS = 'EmergencyOwner9!';

before(async () => {
  ctx = await startTestServer();
  owner = makeClient(ctx.baseUrl);
  await owner.post('/api/auth/register', { name: 'Owner', email: OWNER, password: PASS, recoveryEmail: OWNER });
  await owner.post('/api/vault/items', { type: 'password', title: 'Bank', payload: { password: 'BankSecret9!' } });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

// Makes a request's waiting period already expired, without waiting 7 days.
function expireWait(id) {
  db.prepare("UPDATE emergency_access SET release_at = ? WHERE id = ?").run(Date.now() - 1000, id);
}

test('inviting a contact returns a one-time secret and stores only its hash', async () => {
  const res = await owner.post('/api/emergency', { contactName: 'Ama', contactEmail: 'ama@example.com', waitDays: 7 });
  assert.equal(res.status, 201);
  contactId = res.body.contact.id;
  contactSecret = res.body.secret;
  assert.ok(contactSecret && contactSecret.length >= 24, 'the contact gets a secret to hand over');
  const row = db.prepare('SELECT secret_hash FROM emergency_access WHERE id = ?').get(contactId);
  assert.ok(!row.secret_hash.includes(contactSecret), 'the secret itself must never be stored');
});

test('a waiting period other than 7, 14, or 30 days is refused', async () => {
  assert.equal((await owner.post('/api/emergency', { contactName: 'X', contactEmail: 'x@example.com', waitDays: 3 })).status, 400);
});

test('a request with the wrong secret is refused', async () => {
  const contact = makeClient(ctx.baseUrl);
  assert.equal((await contact.post(`/api/emergency/${contactId}/request`, { secret: 'wrong-secret' })).status, 401);
});

test('a request starts the waiting period and nothing is released yet', async () => {
  const res = await makeClient(ctx.baseUrl).post(`/api/emergency/${contactId}/request`, { secret: contactSecret });
  assert.equal(res.status, 200);
  assert.equal(res.body.contact.status, 'requested');
  const fetchEarly = await makeClient(ctx.baseUrl).post(`/api/emergency/${contactId}/fetch`, { secret: contactSecret });
  assert.equal(fetchEarly.status, 403, 'nothing may be fetched while the waiting period runs');
});

test('the owner can veto during the waiting period, and release then does not happen', async () => {
  const veto = await owner.post(`/api/emergency/${contactId}/veto`, {});
  assert.equal(veto.status, 200);
  assert.equal(veto.body.contact.status, 'invited');
  expireWait(contactId);
  releaseDue();
  const still = await makeClient(ctx.baseUrl).post(`/api/emergency/${contactId}/fetch`, { secret: contactSecret });
  assert.equal(still.status, 403, 'a vetoed request must not be released even after the deadline');
});

test('a request that is not vetoed is released at the deadline', async () => {
  await makeClient(ctx.baseUrl).post(`/api/emergency/${contactId}/request`, { secret: contactSecret });
  expireWait(contactId);
  const changed = releaseDue();
  assert.ok(changed >= 1, 'an un-vetoed request past its deadline must be released');
  const row = db.prepare('SELECT status FROM emergency_access WHERE id = ?').get(contactId);
  assert.equal(row.status, 'released');
});

test('the released key lets the contact unwrap the vault key, which opens the owner\'s data', async () => {
  const material = await makeClient(ctx.baseUrl).post(`/api/emergency/${contactId}/fetch`, { secret: contactSecret });
  assert.equal(material.status, 200);
  const { kekSalt, wrappedVek, iv, tag } = material.body;
  const vek = unwrapKey(
    { ciphertext: Buffer.from(wrappedVek, 'base64'), iv: Buffer.from(iv, 'base64'), tag: Buffer.from(tag, 'base64') },
    deriveKey(contactSecret, Buffer.from(kekSalt, 'base64')),
  );
  const row = db.prepare("SELECT payload_ciphertext, payload_iv, payload_tag FROM vault_items WHERE user_id = (SELECT id FROM users WHERE email = ?) AND title = 'Bank'").get(OWNER);
  const { decryptJSON } = await import('../server/crypto.js');
  const payload = decryptJSON({ ciphertext: row.payload_ciphertext, iv: row.payload_iv, tag: row.payload_tag }, vek);
  assert.equal(payload.password, 'BankSecret9!', 'the contact must recover the owner\'s real data with the released key');
});

test('a revoked contact can no longer request or fetch access', async () => {
  const res = await owner.post('/api/emergency', { contactName: 'Kofi', contactEmail: 'kofi@example.com', waitDays: 14 });
  const id = res.body.contact.id, secret = res.body.secret;
  await owner.post(`/api/emergency/${id}/revoke`, {});
  assert.equal((await makeClient(ctx.baseUrl).post(`/api/emergency/${id}/request`, { secret })).status, 403);
});

test('one owner cannot veto or revoke another owner\'s contact', async () => {
  const other = makeClient(ctx.baseUrl);
  await other.post('/api/auth/register', { name: 'Other', email: 'ea-other@example.com', password: 'OtherEa9!', recoveryEmail: 'ea-other@example.com' });
  assert.equal((await other.post(`/api/emergency/${contactId}/veto`, {})).status, 404);
  assert.equal((await other.post(`/api/emergency/${contactId}/revoke`, {})).status, 404);
  const otherList = await other.get('/api/emergency');
  assert.equal(otherList.body.contacts.length, 0, 'the other owner created no contacts, so they must see none of owner A\'s');
  assert.ok(!otherList.body.contacts.some((c) => c.id === contactId), 'owner A\'s contact must never appear in another owner\'s list');
});

test('inviting a contact requires an unlocked vault', async () => {
  const locked = makeClient(ctx.baseUrl);
  await locked.post('/api/auth/login', { email: OWNER, password: PASS });
  await locked.post('/api/auth/lock', {});
  assert.equal((await locked.post('/api/emergency', { contactName: 'L', contactEmail: 'l@example.com', waitDays: 7 })).status, 423);
});
