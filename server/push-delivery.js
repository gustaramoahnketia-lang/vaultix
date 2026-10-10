// server/push-delivery.js
//
// The real Web Push sender. UNTESTED IN THIS ENVIRONMENT: it needs the `web-push`
// npm package (VAPID signing and payload encryption), and this sandbox cannot
// install packages. It is written to the library's documented API and fails
// closed: if the package or the VAPID keys are missing, every send reports
// failure, so nothing is ever marked delivered that wasn't.
//
// To enable it on a real server:
//   npm install web-push
//   set VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT (a mailto: or https: URL)
//   generate keys once with: npx web-push generate-vapid-keys

let webpush = null;
let loadError = null;
try {
  webpush = (await import('web-push')).default;
} catch (err) {
  loadError = err.code === 'ERR_MODULE_NOT_FOUND' ? 'web-push is not installed' : err.message;
}

const PUBLIC = process.env.VAPID_PUBLIC_KEY || '';
const PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
const SUBJECT = process.env.VAPID_SUBJECT || '';

export function pushStatus() {
  if (loadError) return { ready: false, reason: loadError };
  if (!PUBLIC || !PRIVATE || !SUBJECT) return { ready: false, reason: 'VAPID keys or subject are not configured' };
  return { ready: true, reason: null };
}

/**
 * Sends one payload to one subscription. Resolves (never throws) to
 * { ok, gone }, so the scheduler can decide what to do with each device.
 * A 404 or 410 from the push service means the subscription is dead.
 */
export async function sendToDevice(device, payload) {
  const status = pushStatus();
  if (!status.ready) return { ok: false, gone: false, reason: status.reason };
  try {
    webpush.setVapidDetails(SUBJECT, PUBLIC, PRIVATE);
    await webpush.sendNotification(
      { endpoint: device.endpoint, keys: { p256dh: device.p256dh_key, auth: device.auth_key } },
      JSON.stringify(payload),
      { TTL: 60 * 60 }, // 1 hour: a reminder older than that is no longer useful
    );
    return { ok: true, gone: false };
  } catch (err) {
    const code = err?.statusCode;
    return { ok: false, gone: code === 404 || code === 410, reason: err?.message || 'push failed' };
  }
}
