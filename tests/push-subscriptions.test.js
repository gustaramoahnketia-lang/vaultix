import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, a, b;
const endpointA = 'https://fcm.googleapis.com/fcm/send/device-A-123';
const goodKeys = { p256dh: 'BNcRdreALRFXTkOOUHK5E', auth: 'tBHItJI5svbpez7KI4CCXg' };

before(async () => {
  ctx = await startTestServer();
  a = makeClient(ctx.baseUrl);
  b = makeClient(ctx.baseUrl);
  await a.post('/api/auth/register', { name: 'Push A', email: 'push-a@example.com', password: 'PushAlice9!', recoveryEmail: 'push-a@example.com' });
  await b.post('/api/auth/register', { name: 'Push B', email: 'push-b@example.com', password: 'PushBob9!', recoveryEmail: 'push-b@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

test('the public key endpoint works without login and reports unavailable when VAPID is not configured', async () => {
  delete process.env.VAPID_PUBLIC_KEY;
  const anon = makeClient(ctx.baseUrl);
  const res = await anon.get('/api/push/public-key');
  assert.equal(res.status, 200);
  assert.equal(res.body.available, false, 'with no key configured, the feature must say so');
  assert.equal(res.body.publicKey, '');
});

test('a valid subscription registers for the signed-in user and is listed', async () => {
  const res = await a.post('/api/push/devices', { subscription: { endpoint: endpointA, keys: goodKeys }, deviceName: 'My Phone' });
  assert.equal(res.status, 201);
  assert.equal(res.body.device.deviceName, 'My Phone');
  assert.equal(res.body.device.active, true);
  const list = await a.get('/api/push/devices');
  assert.ok(list.body.devices.some((d) => d.id === res.body.device.id));
});

test('the device list never exposes the endpoint or the encryption keys', async () => {
  const list = await a.get('/api/push/devices');
  const text = JSON.stringify(list.body);
  assert.ok(!text.includes(endpointA), 'the push endpoint must not be returned to the client');
  assert.ok(!text.includes(goodKeys.p256dh), 'the encryption keys must not be returned to the client');
});

test('user B cannot take over a device that user A has registered', async () => {
  const res = await b.post('/api/push/devices', { subscription: { endpoint: endpointA, keys: goodKeys }, deviceName: 'Stolen' });
  assert.equal(res.status, 409, 'an endpoint owned by another account must be refused, not moved');
  const bList = await b.get('/api/push/devices');
  assert.equal(bList.body.devices.length, 0, 'user B must not gain user A\'s device');
  const aList = await a.get('/api/push/devices');
  assert.equal(aList.body.devices.length, 1, 'user A must keep the device');
});

test('user B cannot remove user A\'s device', async () => {
  const aList = await a.get('/api/push/devices');
  const id = aList.body.devices[0].id;
  assert.equal((await b.delete(`/api/push/devices/${id}`)).status, 404);
  const still = await a.get('/api/push/devices');
  assert.equal(still.body.devices.length, 1);
});

test('re-registering the same endpoint for the same owner updates it rather than duplicating it', async () => {
  await a.post('/api/push/devices', { subscription: { endpoint: endpointA, keys: goodKeys }, deviceName: 'My Phone Renamed' });
  const list = await a.get('/api/push/devices');
  assert.equal(list.body.devices.length, 1, 'no duplicate device row');
  assert.equal(list.body.devices[0].deviceName, 'My Phone Renamed');
});

test('malformed subscriptions are rejected', async () => {
  const bad = [
    { endpoint: 'http://insecure.example.com/x', keys: goodKeys },
    { endpoint: 'not a url', keys: goodKeys },
    { endpoint: 'https://push.example.com/y', keys: { p256dh: '', auth: goodKeys.auth } },
    { endpoint: 'https://push.example.com/y', keys: { p256dh: 'has spaces!', auth: goodKeys.auth } },
    { endpoint: 'https://push.example.com/y' },
    { keys: goodKeys },
    null,
  ];
  for (const sub of bad) {
    const res = await a.post('/api/push/devices', { subscription: sub });
    assert.equal(res.status, 400, `malformed subscription ${JSON.stringify(sub)} must be refused`);
  }
});

test('a device-name field cannot carry markup or unbounded text', async () => {
  const res = await a.post('/api/push/devices', { subscription: { endpoint: 'https://push.example.com/clean-1', keys: goodKeys }, deviceName: '<img src=x onerror=alert(1)>' + 'A'.repeat(500) });
  assert.equal(res.status, 201);
  assert.ok(!/[<>]/.test(res.body.device.deviceName), 'angle brackets must be stripped');
  assert.ok(res.body.device.deviceName.length <= 60, 'device name must be bounded');
});

test('a device write without a CSRF token is refused', async () => {
  const c = makeClient(ctx.baseUrl);
  await c.post('/api/auth/register', { name: 'Push C', email: 'push-c@example.com', password: 'PushCarol9!', recoveryEmail: 'push-c@example.com' });
  c.setCsrf('');
  assert.equal((await c.post('/api/push/devices', { subscription: { endpoint: 'https://push.example.com/c', keys: goodKeys } })).status, 403);
});

test('removing your own device works, and the device is gone afterwards', async () => {
  const list = await a.get('/api/push/devices');
  const id = list.body.devices[0].id;
  assert.equal((await a.delete(`/api/push/devices/${id}`)).status, 200);
  const after = await a.get('/api/push/devices');
  assert.ok(!after.body.devices.some((d) => d.id === id));
});
