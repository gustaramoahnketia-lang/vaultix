import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, user;
before(async () => {
  ctx = await startTestServer();
  user = makeClient(ctx.baseUrl);
  await user.post('/api/auth/register', { name: 'Cal Tester', email: 'caltester@example.com', password: 'CalTest9!', recoveryEmail: 'caltester@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

function isoDaysFromNow(days) {
  const d = new Date(Date.now() + days * 86400000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

test('create, read, update, delete an event', async () => {
  const created = await user.post('/api/events', { title: 'Project Submission', startDate: isoDaysFromNow(5), startTime: '10:00', eventType: 'general', recurrence: 'none' });
  assert.equal(created.status, 201);
  const id = created.body.event.id;

  const fetched = await user.get(`/api/events/${id}`);
  assert.equal(fetched.body.event.title, 'Project Submission');

  const updated = await user.put(`/api/events/${id}`, { title: 'Final Project Submission' });
  assert.equal(updated.body.event.title, 'Final Project Submission');

  const deleted = await user.delete(`/api/events/${id}`);
  assert.equal(deleted.status, 200);
  const goneCheck = await user.get(`/api/events/${id}`);
  assert.equal(goneCheck.status, 404);
});

test('a birthday (annually-recurring event) appears every year, not just the creation year', async () => {
  // Created "in the past" (a birthdate), recurring annually — must still
  // produce an occurrence in the current year's date range.
  const created = await user.post('/api/events', { title: "John's Birthday", startDate: '2000-09-15', eventType: 'birthday', recurrence: 'annually' });
  assert.equal(created.status, 201);

  const now = new Date();
  const from = `${now.getFullYear()}-01-01`;
  const to = `${now.getFullYear()}-12-31`;
  const res = await user.get(`/api/events?from=${from}&to=${to}`);
  const occurrence = res.body.events.find((e) => e.title === "John's Birthday");
  assert.ok(occurrence, 'the annual event should have an occurrence in the current year');
  assert.equal(occurrence.occurrenceDate.slice(5), '09-15');
});

test('upcoming events compute days-remaining dynamically, never hardcoded', async () => {
  await user.post('/api/events', { title: 'Passport Renewal', startDate: isoDaysFromNow(30), eventType: 'expiry', recurrence: 'none' });
  const res = await user.get('/api/events/upcoming?days=60');
  const found = res.body.events.find((e) => e.title === 'Passport Renewal');
  assert.ok(found);
  assert.ok(found.daysRemaining >= 28 && found.daysRemaining <= 31, `expected ~30 days remaining, got ${found.daysRemaining}`);
});

test('today\'s events endpoint only returns events actually occurring today', async () => {
  await user.post('/api/events', { title: 'Todays Meeting', startDate: isoDaysFromNow(0), eventType: 'general', recurrence: 'none' });
  await user.post('/api/events', { title: 'Next Week Meeting', startDate: isoDaysFromNow(7), eventType: 'general', recurrence: 'none' });
  const res = await user.get('/api/events/today');
  assert.ok(res.body.events.some((e) => e.title === 'Todays Meeting'));
  assert.ok(!res.body.events.some((e) => e.title === 'Next Week Meeting'));
});

test('monthly recurrence clamps to the last valid day of shorter months', async () => {
  await user.post('/api/events', { title: 'Monthly Payment', startDate: '2026-01-31', eventType: 'general', recurrence: 'monthly' });
  const res = await user.get('/api/events?from=2026-02-01&to=2026-02-28');
  const feb = res.body.events.find((e) => e.title === 'Monthly Payment');
  assert.ok(feb, 'a monthly event on the 31st should still produce a February occurrence');
  assert.equal(feb.occurrenceDate, '2026-02-28');
});

test('an event can link to a vault entry, and linking respects ownership', async () => {
  const item = await user.post('/api/vault/items', { type: 'personal', title: 'My Brother', payload: { fullName: 'John', dob: '15/09/2000' } });
  const created = await user.post('/api/events', { title: "John's Birthday", startDate: '2000-09-15', eventType: 'birthday', recurrence: 'annually', linkedItemId: item.body.item.id });
  assert.equal(created.status, 201);
  assert.equal(created.body.event.linkedItemId, item.body.item.id);

  const other = makeClient(ctx.baseUrl);
  await other.post('/api/auth/register', { name: 'EventAttacker', email: 'eventattacker@example.com', password: 'EventAttacker9!', recoveryEmail: 'eventattacker@example.com' });
  const otherItem = await other.post('/api/vault/items', { type: 'note', title: 'Not Yours', payload: { content: 'x' } });
  const badLink = await user.post('/api/events', { title: 'Bad Link', startDate: isoDaysFromNow(1), linkedItemId: otherItem.body.item.id });
  assert.equal(badLink.status, 404, 'linking to another user\'s vault item must be rejected');
});

test('events are isolated per user — User A never sees User B\'s events', async () => {
  const owner = makeClient(ctx.baseUrl);
  await owner.post('/api/auth/register', { name: 'EventOwner', email: 'eventowner@example.com', password: 'EventOwner9!', recoveryEmail: 'eventowner@example.com' });
  const created = await owner.post('/api/events', { title: 'Private Event', startDate: isoDaysFromNow(2), eventType: 'general', recurrence: 'none' });

  const attacker = makeClient(ctx.baseUrl);
  await attacker.post('/api/auth/register', { name: 'EventAttacker2', email: 'eventattacker2@example.com', password: 'EventAttacker9!', recoveryEmail: 'eventattacker2@example.com' });
  const stolen = await attacker.get(`/api/events/${created.body.event.id}`);
  assert.equal(stolen.status, 404);

  const range = await attacker.get(`/api/events?from=${isoDaysFromNow(0)}&to=${isoDaysFromNow(10)}`);
  assert.ok(!range.body.events.some((e) => e.title === 'Private Event'));
});

test('search finds events by title, and the main /api/search endpoint includes matching events', async () => {
  await user.post('/api/events', { title: 'Medicine Reminder', startDate: isoDaysFromNow(0), eventType: 'medication', recurrence: 'daily' });
  const res = await user.get('/api/search?q=medicine');
  assert.ok(res.body.events.some((e) => e.title === 'Medicine Reminder'));
});

test('deleting an event is scoped to its owner', async () => {
  const owner = makeClient(ctx.baseUrl);
  await owner.post('/api/auth/register', { name: 'DelOwner', email: 'delowner@example.com', password: 'DelOwner9!', recoveryEmail: 'delowner@example.com' });
  const created = await owner.post('/api/events', { title: 'ToDelete', startDate: isoDaysFromNow(1) });

  const attacker = makeClient(ctx.baseUrl);
  await attacker.post('/api/auth/register', { name: 'DelAttacker', email: 'delattacker@example.com', password: 'DelAttacker9!', recoveryEmail: 'delattacker@example.com' });
  const badDelete = await attacker.delete(`/api/events/${created.body.event.id}`);
  assert.equal(badDelete.status, 404);

  const stillThere = await owner.get(`/api/events/${created.body.event.id}`);
  assert.equal(stillThere.status, 200);
});
