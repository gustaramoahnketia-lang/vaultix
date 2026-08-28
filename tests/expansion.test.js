import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, user;
before(async () => {
  ctx = await startTestServer();
  user = makeClient(ctx.baseUrl);
  await user.post('/api/auth/register', { name: 'Expansion Tester', email: 'expansion@example.com', password: 'ExpansionTest9!', recoveryEmail: 'expansion@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('every new item type can be created and round-trips its encrypted payload', async () => {
  const cases = [
    ['apikey', 'AWS Production', { service: 'AWS', keyId: 'AKIA...', secretKey: 'wJalrXUtnFEMI...', environment: 'production' }],
    ['sshkey', 'Prod Web Server', { host: 'web1.example.com', port: '22', username: 'deploy', privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----...' }],
    ['wallet', 'Main ETH Wallet', { network: 'Ethereum', address: '0xABC...', seedPhrase: 'twelve words go right here for the seed phrase example ok' }],
    ['physical', 'Front Door', { location: 'Home', code: '4471' }],
    ['license', 'Windows 11 Pro', { software: 'Windows 11 Pro', licenseKey: 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX' }],
    ['medical', 'Health Profile', { bloodType: 'O+', conditions: 'None', emergencyDoctor: 'Dr. Mensah', doctorPhone: '+233...' }],
    ['inheritance', 'In Case of Emergency', { instructions: 'Contact my brother first, then close the exchange accounts.' }],
  ];
  for (const [type, title, payload] of cases) {
    const res = await user.post('/api/vault/items', { type, title, payload });
    assert.equal(res.status, 201, `${type} should create successfully`);
    assert.equal(res.body.item.type, type);
    const fetched = await user.get(`/api/vault/items/${res.body.item.id}`);
    assert.deepEqual(fetched.body.item.payload, payload, `${type} payload should round-trip exactly`);
  }
});

test('an unknown item type is rejected', async () => {
  const res = await user.post('/api/vault/items', { type: 'not-a-real-type', title: 'x', payload: {} });
  assert.equal(res.status, 400);
});

test('encrypted file attachments: upload, download, and reject oversized/unsupported files', async () => {
  const item = await user.post('/api/vault/items', { type: 'document', title: 'Passport Scan', payload: { description: 'Passport' } });
  const id = item.body.item.id;

  const smallPdfBase64 = Buffer.from('%PDF-1.4 fake pdf content for testing').toString('base64');
  const uploaded = await user.post(`/api/vault/items/${id}/file`, { fileName: 'passport.pdf', mimeType: 'application/pdf', dataBase64: smallPdfBase64 });
  assert.equal(uploaded.status, 201);

  const downloaded = await user.get(`/api/vault/items/${id}/file`);
  assert.equal(downloaded.status, 200);
  assert.equal(Buffer.from(downloaded.body.dataBase64, 'base64').toString(), '%PDF-1.4 fake pdf content for testing');

  const badType = await user.post(`/api/vault/items/${id}/file`, { fileName: 'x.exe', mimeType: 'application/x-msdownload', dataBase64: smallPdfBase64 });
  assert.equal(badType.status, 400);

  const oversized = Buffer.alloc(7 * 1024 * 1024, 'a').toString('base64');
  const tooBig = await user.post(`/api/vault/items/${id}/file`, { fileName: 'huge.pdf', mimeType: 'application/pdf', dataBase64: oversized });
  assert.equal(tooBig.status, 413);
});

test('a file cannot be attached to another user\'s item (ownership enforced)', async () => {
  const other = makeClient(ctx.baseUrl);
  await other.post('/api/auth/register', { name: 'Other', email: 'fileother@example.com', password: 'OtherPass9!', recoveryEmail: 'fileother@example.com' });
  const otherItem = await other.post('/api/vault/items', { type: 'document', title: 'Other Doc', payload: {} });
  const res = await user.post(`/api/vault/items/${otherItem.body.item.id}/file`, { fileName: 'x.pdf', mimeType: 'application/pdf', dataBase64: Buffer.from('x').toString('base64') });
  assert.equal(res.status, 404);
});

test('profile picture upload, retrieval, and removal', async () => {
  const tinyPng = Buffer.from('89504e470d0a1a0a', 'hex').toString('base64');
  const upload = await user.post('/api/profile/avatar', { mimeType: 'image/png', dataBase64: tinyPng });
  assert.equal(upload.status, 200);

  const fetched = await user.get('/api/profile/avatar');
  assert.equal(fetched.status, 200);
  assert.equal(fetched.body.dataBase64, tinyPng);

  const removed = await user.delete('/api/profile/avatar', {});
  assert.equal(removed.status, 200);
  const goneCheck = await user.get('/api/profile/avatar');
  assert.equal(goneCheck.status, 404);
});

test('avatar retrieval requires an unlocked vault', async () => {
  await user.post('/api/auth/lock', {});
  const res = await user.get('/api/profile/avatar');
  assert.equal(res.status, 423);
  await user.post('/api/auth/unlock/password', { password: 'ExpansionTest9!' });
});

test('duress PIN: succeeds without ever unlocking the real vault, must differ from the real PIN, and never counts against the real PIN\'s lockout', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'Duress', email: 'duress@example.com', password: 'DuressTest9!', recoveryEmail: 'duress@example.com' });
  await c.post('/api/auth/pin', { pin: '1357' });

  const sameAsPinRejected = await c.post('/api/auth/duress-pin', { pin: '1357' });
  assert.equal(sameAsPinRejected.status, 400);

  const setDuress = await c.post('/api/auth/duress-pin', { pin: '9999' });
  assert.equal(setDuress.status, 200);

  await c.post('/api/auth/lock', {});

  // Same endpoint as a normal PIN unlock — the server distinguishes duress
  // from real internally; there is no separate client-visible endpoint.
  const duressUnlock = await c.post('/api/auth/unlock/pin', { pin: '9999' });
  assert.equal(duressUnlock.status, 200);
  assert.equal(duressUnlock.body.duress, true);

  // Critically: the vault must still be LOCKED from the server's point of
  // view — duress unlock never caches a real VEK.
  const stillLocked = await c.post('/api/vault/items', { type: 'note', title: 'should fail', payload: { content: 'x' } });
  assert.equal(stillLocked.status, 423);

  // Using the duress PIN repeatedly must never move the real PIN toward
  // its own lockout threshold (3 failed attempts) — it's a completely
  // separate code path server-side.
  await c.post('/api/auth/unlock/pin', { pin: '9999' });
  await c.post('/api/auth/unlock/pin', { pin: '9999' });
  const realPinStillWorks = await c.post('/api/auth/unlock/pin', { pin: '1357' });
  assert.equal(realPinStillWorks.status, 200);
  assert.equal(realPinStillWorks.body.duress, undefined);
});

test('the security activity hash chain detects tampering with a past entry', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'ChainUser', email: 'chainuser@example.com', password: 'ChainUser9!', recoveryEmail: 'chainuser@example.com' });
  await c.post('/api/vault/items', { type: 'note', title: 'Note A', payload: { content: 'a' } });
  await c.post('/api/vault/items', { type: 'note', title: 'Note B', payload: { content: 'b' } });

  const before2 = await c.get('/api/security/activity/verify');
  assert.equal(before2.body.valid, true);

  const { db } = await import('../server/db.js');
  const me = await c.get('/api/auth/me');
  const row = db.prepare("SELECT id FROM security_events WHERE user_id = ? AND text LIKE 'Secure note added:%' ORDER BY created_at ASC LIMIT 1").get(me.body.user.id);
  db.prepare("UPDATE security_events SET text = 'Secure note added: TAMPERED' WHERE id = ?").run(row.id);

  const after2 = await c.get('/api/security/activity/verify');
  assert.equal(after2.body.valid, false);
  assert.equal(after2.body.brokenAt, row.id);
});

test('vault health report flags weak, reused, and default-looking Wi-Fi passwords, and leaves strong ones alone', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'HealthUser', email: 'healthuser@example.com', password: 'HealthUser9!', recoveryEmail: 'healthuser@example.com' });

  await c.post('/api/vault/items', { type: 'password', title: 'WeakSite', payload: { password: 'abc123' } });
  await c.post('/api/vault/items', { type: 'password', title: 'ReusedA', payload: { password: 'SameStrongPassw0rd!' } });
  await c.post('/api/vault/items', { type: 'password', title: 'ReusedB', payload: { password: 'SameStrongPassw0rd!' } });
  await c.post('/api/vault/items', { type: 'password', title: 'GreatSite', payload: { password: 'Xk9$mQ2vLpR7#zN4' } });
  await c.post('/api/vault/items', { type: 'wifi', title: 'Home_WiFi', category: 'wifi', payload: { password: '12345678' } });

  const report = await c.get('/api/security/health');
  assert.equal(report.status, 200);
  assert.ok(report.body.weakCount >= 1);
  assert.ok(report.body.reusedCount >= 2);
  assert.ok(report.body.defaultWifiCount >= 1);
  const greatSiteFinding = report.body.findings.find((f) => f.title === 'GreatSite');
  assert.equal(greatSiteFinding, undefined, 'a strong, unique, unused-elsewhere password should have no findings');
});

test('self-destructing share link: consumable exactly maxUses times, then gone', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'ShareUser', email: 'shareuser@example.com', password: 'ShareUser9!', recoveryEmail: 'shareuser@example.com' });
  const item = await c.post('/api/vault/items', { type: 'note', title: 'Shareable', payload: { content: 'secret payload' } });

  const share = await c.post(`/api/vault/items/${item.body.item.id}/share`, {
    ciphertext: Buffer.from('fake-ciphertext').toString('base64'),
    iv: Buffer.from('123456789012').toString('base64'),
    tag: Buffer.from('0123456789012345').toString('base64'),
    maxUses: 1, ttlMs: 60000,
  });
  assert.equal(share.status, 201);

  const anon = makeClient(ctx.baseUrl);
  const first = await anon.get(`/api/share/${share.body.id}`);
  assert.equal(first.status, 200);

  const second = await anon.get(`/api/share/${share.body.id}`);
  assert.equal(second.status, 404); // deleted after single use
});

test('share links from one user cannot be created against another user\'s item', async () => {
  const owner = makeClient(ctx.baseUrl);
  await owner.post('/api/auth/register', { name: 'ShareOwner', email: 'shareowner@example.com', password: 'ShareOwner9!', recoveryEmail: 'shareowner@example.com' });
  const item = await owner.post('/api/vault/items', { type: 'note', title: 'Owned', payload: { content: 'x' } });

  const attacker = makeClient(ctx.baseUrl);
  await attacker.post('/api/auth/register', { name: 'Attacker', email: 'shareattacker@example.com', password: 'Attacker9!', recoveryEmail: 'shareattacker@example.com' });
  const res = await attacker.post(`/api/vault/items/${item.body.item.id}/share`, {
    ciphertext: Buffer.from('x').toString('base64'), iv: Buffer.from('123456789012').toString('base64'), tag: Buffer.from('0123456789012345').toString('base64'),
  });
  assert.equal(res.status, 404);
});

test('encrypted backup export and import round-trips items under a separate export password', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'BackupUser', email: 'backupuser@example.com', password: 'BackupUser9!', recoveryEmail: 'backupuser@example.com' });
  await c.post('/api/vault/items', { type: 'password', title: 'ToBackup', payload: { password: 'BackedUpPassw0rd!' } });

  const exportRes = await c.post('/api/vault/export', { exportPassword: 'MyExportPassword9!' });
  assert.equal(exportRes.status, 200);
  assert.ok(exportRes.body.ciphertext);

  // Wrong export password must fail
  const other = makeClient(ctx.baseUrl);
  await other.post('/api/auth/register', { name: 'ImportUser', email: 'importuser@example.com', password: 'ImportUser9!', recoveryEmail: 'importuser@example.com' });
  const badImport = await other.post('/api/vault/import', { exportPassword: 'WrongPassword!', backup: exportRes.body });
  assert.equal(badImport.status, 401);

  const goodImport = await other.post('/api/vault/import', { exportPassword: 'MyExportPassword9!', backup: exportRes.body });
  assert.equal(goodImport.status, 200);
  assert.equal(goodImport.body.imported, 1);

  const items = await other.get('/api/vault/items?type=password');
  assert.ok(items.body.items.some((i) => i.title.includes('ToBackup')));
});
