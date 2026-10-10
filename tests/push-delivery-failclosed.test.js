import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pushStatus, sendToDevice } from '../server/push-delivery.js';

// The real sender cannot be exercised here (web-push is not installed). These
// tests guarantee it fails closed: it never reports success without a real send.
test('without the web-push library the sender reports not-ready and never claims success', async () => {
  const st = pushStatus();
  assert.equal(st.ready, false);
  assert.ok(st.reason && st.reason.length > 0, 'the reason must be stated, not hidden');
  const res = await sendToDevice({ endpoint: 'https://push.example.com/x', p256dh_key: 'a', auth_key: 'b' }, { body: 'hi' });
  assert.equal(res.ok, false, 'a not-ready sender must never report a delivery');
  assert.equal(res.gone, false, 'a missing library is not a dead subscription and must not deactivate devices');
});
