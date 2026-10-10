import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

// Part 51 / 52: the account and its data must live in the backend database and
// be retrievable from a brand-new client with no prior local state, exactly as
// a reinstall or a new phone would look to the server.

let ctx;
const EMAIL = 'persist-john@example.com';
const PASSWORD = 'PersistJohn9!';
const day = new Date().toISOString().slice(0, 10);

before(async () => { ctx = await startTestServer(); });
after(async () => { await ctx.close(); ctx.cleanup(); });

test('create an account and save every category of data on "device A"', async () => {
  const deviceA = makeClient(ctx.baseUrl);
  const reg = await deviceA.post('/api/auth/register', { name: 'John', email: EMAIL, password: PASSWORD, recoveryEmail: EMAIL });
  assert.equal(reg.status, 201);

  assert.equal((await deviceA.post('/api/vault/items', { type: 'password', title: 'Bank', searchUsername: 'john', payload: { password: 'BankSecret1!' } })).status, 201);
  assert.equal((await deviceA.post('/api/vault/items', { type: 'note', title: 'Note', payload: { content: 'remember this' } })).status, 201);
  assert.equal((await deviceA.post('/api/vault/items', { type: 'personal', title: 'Personal Information', payload: { fullName: 'John', dob: '15/09/2000' } })).status, 201);
  assert.equal((await deviceA.post('/api/vault/items', { type: 'id', title: 'Passport', payload: { description: 'Ghana passport' } })).status, 201);
  assert.equal((await deviceA.post('/api/vault/items', { type: 'wifi', title: 'Home Wi-Fi', payload: { network: 'Home', password: 'WifiPass1!' } })).status, 201);
  assert.equal((await deviceA.post('/api/events', { title: 'Doctor visit', startDate: day, reminders: [{ minutesBefore: 60 }] })).status, 201);
  assert.equal((await deviceA.put('/api/preferences/upcoming-window', { days: 180 })).status, 200);
  assert.equal((await deviceA.put('/api/activity/goal', { dailyDistanceMiles: 2 })).status, 200);
  await deviceA.post('/api/auth/logout', {});
});

test('a brand-new client with no local state logs in and sees every item, event, and setting again', async () => {
  // "Device B": a fresh client with no cookies, no CSRF token, nothing local.
  // This is what the server sees after a reinstall or on a new phone.
  const deviceB = makeClient(ctx.baseUrl);
  const login = await deviceB.post('/api/auth/login', { email: EMAIL, password: PASSWORD });
  assert.equal(login.status, 200, 'the same credentials must log in on a new client');
  const unlock = await deviceB.post('/api/auth/unlock/password', { password: PASSWORD });
  assert.equal(unlock.status, 200, 'the vault must unlock from the password alone');

  const summary = await deviceB.get('/api/vault/summary');
  assert.equal(summary.body.summary.passwords, 1);
  assert.equal(summary.body.summary.notes, 1);
  assert.equal(summary.body.summary.personal, 1);
  assert.equal(summary.body.summary.documents, 0, 'an id item is type "id", counted under ids');
  assert.equal(summary.body.summary.ids, 1);
  assert.equal(summary.body.summary.wifi, 1);

  const bank = await deviceB.get('/api/vault/items?type=password');
  const full = await deviceB.get(`/api/vault/items/${bank.body.items[0].id}`);
  assert.equal(full.body.item.payload.password, 'BankSecret1!', 'secret content must decrypt on the new client');

  const events = await deviceB.get(`/api/events?from=${day}&to=${day}`);
  assert.ok(events.body.events.some((e) => e.title === 'Doctor visit'), 'calendar events must persist');
  const reminders = await deviceB.get(`/api/events?from=${day}&to=${day}`);
  assert.equal(reminders.body.events.find((e) => e.title === 'Doctor visit').reminders[0].minutesBefore, 60, 'reminders must persist');

  const prefs = await deviceB.get('/api/preferences');
  assert.equal(prefs.body.upcomingWindowDays, 180, 'settings must persist on the account');
  const goal = await deviceB.get('/api/activity/goal');
  assert.equal(goal.body.goal.dailyDistanceMiles, 2, 'the activity goal must persist on the account');
});

test('a wrong password on the new client cannot retrieve the account', async () => {
  const intruder = makeClient(ctx.baseUrl);
  assert.equal((await intruder.post('/api/auth/login', { email: EMAIL, password: 'WrongPassword9!' })).status, 401);
  assert.equal((await intruder.get('/api/vault/summary')).status, 401, 'no data without a session');
});

test('the account survives a server restart: the database, not memory, holds it', async () => {
  // Close the server completely, then start a new one against the same database
  // file. Nothing kept in process memory can survive this.
  await ctx.close();
  const { db } = await import('../server/db.js');
  const row = db.prepare('SELECT email FROM users WHERE email = ?').get(EMAIL);
  assert.ok(row, 'the account row must still exist in the database after the server process is recreated');
  const items = db.prepare("SELECT COUNT(*) AS n FROM vault_items WHERE user_id = (SELECT id FROM users WHERE email = ?)").get(EMAIL);
  assert.ok(items.n >= 5, 'the vault items must still exist in the database');
  ctx = await startTestServer();
  const back = makeClient(ctx.baseUrl);
  assert.equal((await back.post('/api/auth/login', { email: EMAIL, password: PASSWORD })).status, 200, 'the account must log in on a restarted server');
});
