import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';
import { db } from '../server/db.js';
import { runForUser } from '../server/scheduler.js';

let ctx, u;
const keys = { p256dh: 'BNcRdreALRFXTkOOUHK5E', auth: 'tBHItJI5svbpez7KI4CCXg' };

before(async () => {
  ctx = await startTestServer();
  u = makeClient(ctx.baseUrl);
  await u.post('/api/auth/register', { name: 'Sched', email: 'sched@example.com', password: 'SchedUser9!', recoveryEmail: 'sched@example.com' });
  await u.post('/api/push/devices', { subscription: { endpoint: 'https://push.example.com/dev-1', keys }, deviceName: 'Phone' });
  await u.post('/api/push/devices', { subscription: { endpoint: 'https://push.example.com/dev-2', keys }, deviceName: 'Laptop' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

// An event whose reminder is due right now: it starts in 2 minutes and has a
// 2-minute-before reminder, so its trigger moment is now.
async function dueNow(title) {
  const soon = new Date(Date.now() + 2 * 60000);
  const date = `${soon.getFullYear()}-${String(soon.getMonth() + 1).padStart(2, '0')}-${String(soon.getDate()).padStart(2, '0')}`;
  const time = `${String(soon.getHours()).padStart(2, '0')}:${String(soon.getMinutes()).padStart(2, '0')}`;
  await u.post('/api/events', { title, startDate: date, startTime: time, reminders: [{ minutesBefore: 2 }] });
}

test('a due reminder is delivered to every active device and recorded', async () => {
  await dueNow('Meeting A');
  const sent = [];
  const send = async (dev, payload) => { sent.push({ dev: dev.endpoint, title: payload.body }); return { ok: true }; };
  const s = await runForUser(userIdOf(), send);
  assert.equal(s.due >= 1, true);
  const hits = sent.filter((x) => x.title.includes('Meeting A'));
  assert.equal(hits.length, 2, 'both registered devices must receive the reminder');
});

test('the same reminder is never delivered twice, even if the scheduler runs again', async () => {
  let count = 0;
  const send = async () => { count++; return { ok: true }; };
  await runForUser(userIdOf(), send);
  const afterFirst = count;
  await runForUser(userIdOf(), send);
  await runForUser(userIdOf(), send);
  assert.equal(count, afterFirst, 'a second and third pass must not resend anything already delivered');
});

test('a reminder that fails on every device is not marked sent, so it is retried', async () => {
  await dueNow('Retry Me');
  let attempts = 0;
  const failing = async () => { attempts++; return { ok: false, gone: false }; };
  await runForUser(userIdOf(), failing);
  const fails = attempts;
  let retried = 0;
  const ok = async () => { retried++; return { ok: true }; };
  await runForUser(userIdOf(), ok);
  assert.ok(fails >= 1 && retried >= 1, 'a reminder that never reached the device must be attempted again on a later pass');
});

test('a device the push service reports as gone is deactivated and stops receiving reminders', async () => {
  await dueNow('Gone Device Test');
  const gone = async (dev) => dev.endpoint.endsWith('dev-2') ? { ok: false, gone: true } : { ok: true };
  const s = await runForUser(userIdOf(), gone);
  assert.ok(s.deactivated >= 1);
  const row = db.prepare("SELECT active FROM push_subscriptions WHERE endpoint = 'https://push.example.com/dev-2'").get();
  assert.equal(row.active, 0, 'a gone device must be deactivated');
  await dueNow('After Gone');
  const received = [];
  await runForUser(userIdOf(), async (dev) => { received.push(dev.endpoint); return { ok: true }; });
  assert.ok(!received.some((e) => e.endsWith('dev-2')), 'a deactivated device must not receive later reminders');
});

test('a reminder that is long overdue is not sent late', async () => {
  // An event that started an hour ago: its reminder moment is far outside the window.
  const past = new Date(Date.now() - 60 * 60000);
  const date = `${past.getFullYear()}-${String(past.getMonth() + 1).padStart(2, '0')}-${String(past.getDate()).padStart(2, '0')}`;
  const time = `${String(past.getHours()).padStart(2, '0')}:${String(past.getMinutes()).padStart(2, '0')}`;
  await u.post('/api/events', { title: 'Stale Reminder', startDate: date, startTime: time, reminders: [{ minutesBefore: 0 }] });
  const sent = [];
  await runForUser(userIdOf(), async (dev, p) => { sent.push(p.body); return { ok: true }; });
  assert.ok(!sent.some((b) => b.includes('Stale Reminder')), 'an hour-old reminder must be skipped, not sent late');
});

function userIdOf() {
  return db.prepare("SELECT id FROM users WHERE email = 'sched@example.com'").get().id;
}
