// public/app.js — VAULTIXgusTAR frontend. Plain JS, no build step: every
// call in here hits a real endpoint in server/app.js — nothing here is
// mocked or simulated except where a comment says so explicitly.

const APP_NAME = 'VAULTIXgusTAR';
const root = document.getElementById('root');
const toastHost = document.getElementById('toasts');

const state = {
  screen: 'loading', // loading | login | register | recovery | unlock | biometric | app
  user: null,
  unlocked: false,
  duress: false, // true when the current "unlock" was a duress PIN — see submitPin()
  csrfToken: '',
  active: 'dashboard',
  mobileOpen: false,
  modal: null,
  addInfoOpen: false,
  loginAttempts: 0,
  pinAttempts: 0,
  pinLockedUntil: 0,
  pinBuffer: '',
  searchOpen: false,
  searchQuery: '',
  searchCategory: 'all',
  searchResults: null,
  searchEventResults: null,
  searchLoading: false,
  recentSearches: [],
  summary: {},
  passwordItems: [],
  noteItems: [],
  personalItem: null,
  customItems: [],
  developerItems: [],
  documentItems: [],
  physicalItems: [],
  medicalItems: [],
  developerTab: 'apikey',
  physicalTab: 'physical',
  events: [],
  calendarView: 'month', // 'month' | 'upcoming'
  walkingSession: null, // { startedAt, points, watchId, tick } while a GPS walk is active -- in memory only
  walkingHistory: [],
  walkingServer: null, // the server's view of the active walk: { id, startedAt, elapsedSeconds, movingSeconds, distanceMiles, status, fetchedAt }
  calendarCursor: null, // {year, month} — set on first load
  activity: [],
  chainStatus: null,
  health: null,
  security: null,
  sessions: [],
  avatarDataUrl: null,
  pendingRecoveryKey: null,
  pendingDeviceToken: null,
  pendingAvatarBase64: null,
  pendingAvatarMime: null,
  revealCache: {}, // itemId -> decrypted payload, cleared on nav away
  recovery: { step: 1, email: '', code: '' },
  busy: false,
};

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------
// Duress mode is air-gapped from the real backend at this single choke
// point: every api() call in the whole app funnels through here, so this
// allowlist is the one place that has to be right, not every call site.
const DURESS_ALLOWED_PATHS = new Set(['/api/auth/lock', '/api/auth/logout', '/api/auth/me']);

async function api(method, path, body) {
  if (state.duress && !DURESS_ALLOWED_PATHS.has(path)) {
    // See enterDuressMode() — a duress-unlocked session never touches a
    // real vault/security/profile endpoint, full stop. This throws the
    // same shape of error a normal failed request would, so nothing in the
    // UI behaves visibly differently.
    throw Object.assign(new Error('Something went wrong. Please try again.'), { status: 503 });
  }
  const headers = { 'Content-Type': 'application/json' };
  if (state.csrfToken) headers['x-csrf-token'] = state.csrfToken;
  const res = await fetch(path, {
    method, headers, credentials: 'include',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* no body */ }
  if (json && json.csrfToken) state.csrfToken = json.csrfToken;
  if (res.status === 401 && state.screen === 'app') {
    // Session died server-side (expired, revoked from another device, etc.)
    resetToLogin();
    throw new Error('Session expired. Please sign in again.');
  }
  if (!res.ok) {
    const err = new Error((json && json.error) || 'Something went wrong. Please try again.');
    err.status = res.status;
    throw err;
  }
  return json;
}

function resetToLogin() {
  Object.assign(state, { screen: 'login', user: null, unlocked: false, duress: false, csrfToken: '', active: 'dashboard' });
  render();
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------
function toast(text, type = 'success') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = text;
  toastHost.appendChild(el);
  setTimeout(() => el.remove(), 2800);
}

// ---------------------------------------------------------------------------
// Boot + auto-lock watcher
// ---------------------------------------------------------------------------
async function boot() {
  try {
    const me = await api('GET', '/api/auth/me');
    state.user = me.user;
    state.csrfToken = me.csrfToken;
    state.unlocked = me.unlocked;
    state.screen = me.unlocked ? 'app' : (me.user.hasPin ? 'unlock' : 'unlock');
    if (me.unlocked) { await loadDashboardData(); await loadAvatar(); loadRecentSearches(); }
  } catch {
    state.screen = 'login';
  }
  render();
}
boot();

// ---------------------------------------------------------------------------
// Installability — makes the app launch from a home-screen/desktop icon
// instead of a typed-in URL. Registering the service worker is what lets
// Chrome/Edge offer their native "Install app" prompt; capturing
// beforeinstallprompt lets Settings → About trigger that same prompt from
// an in-app button instead of waiting for the browser's own UI.
// ---------------------------------------------------------------------------
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => { /* non-fatal — app still works without it */ });
  });
}

let deferredInstallPrompt = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  if (state.screen === 'app') render(); // reveal the Install button in Settings if it's open
});
window.addEventListener('appinstalled', () => {
  deferredInstallPrompt = null;
  toast('VAULTIXgusTAR installed');
});

function isIOS() {
  return /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
}
function isStandalone() {
  return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
}

// ---------------------------------------------------------------------------
// In-app reminder notifications (spec section 28) — real, but scoped
// honestly: this uses the browser's Notification API, checked on a client-
// side interval while the app tab is open. It does NOT survive the tab
// being closed or the device restarting — that requires Web Push with
// VAPID keys and a push server, which needs an npm package this offline
// sandbox can't install. See README for that as a documented next step.
// A reminder fires at most once per (event, occurrence, offset) per page
// load — reloading the page can re-fire a reminder still due "now"; that's
// an accepted trade-off of not persisting notification state server-side.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Closed-app push: subscribe this browser and register it with the server.
// The server only ever receives the public subscription; the VAPID private key
// stays on the server. If push is not configured, this reports that plainly.
// ---------------------------------------------------------------------------
function urlBase64ToUint8Array(b64) {
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  const raw = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function enableClosedAppNotifications() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    throw new Error('This browser does not support background notifications.');
  }
  const pub = await api('GET', '/api/push/public-key');
  if (!pub.available) throw new Error('Background notifications are not set up on this server yet.');
  const perm = await Notification.requestPermission();
  if (perm !== 'granted') throw new Error('Notifications were not allowed in this browser.');
  const reg = await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  if (!sub) {
    sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(pub.publicKey) });
  }
  const json = sub.toJSON();
  const deviceName = (navigator.userAgentData?.platform || navigator.platform || 'This device').slice(0, 40);
  await api('POST', '/api/push/devices', { subscription: { endpoint: json.endpoint, keys: json.keys }, deviceName });
  return true;
}

const notifiedReminderKeys = new Set();
let reminderPollTimer = null;

function startReminderPolling() {
  if (reminderPollTimer) clearInterval(reminderPollTimer);
  checkDueReminders();
  reminderPollTimer = setInterval(checkDueReminders, 60_000);
}

// One gentle nudge a day, at most, if a personal goal is still unmet late in
// the day. It is a reminder about the user's own target, never a health
// judgment. It respects the notification privacy setting.
const GOAL_NUDGE_HOUR = 18; // 6 PM local
function goalNudgeKey() { return 'vx_goal_nudge_' + new Date().toDateString(); }
async function maybeGoalNudge() {
  if (new Date().getHours() < GOAL_NUDGE_HOUR) return;
  try { if (localStorage.getItem(goalNudgeKey())) return; } catch { return; }
  let prog;
  try { prog = await api('GET', '/api/activity/goal'); } catch { return; }
  if (!prog.goal || prog.goalMet) return;
  try { localStorage.setItem(goalNudgeKey(), '1'); } catch { /* non-fatal */ }
  const privacy = notifPrivacyLevel();
  const title = 'VAULTIXgusTAR';
  const body = privacy === 'hide' ? 'You have a reminder.' : 'Your personal walking goal for today is not yet reached.';
  try { new Notification(title, { body, icon: '/brand/icon-192.png', tag: 'goal-nudge' }); } catch { /* non-fatal */ }
}

async function checkDueReminders() {
  if (state.duress || !state.unlocked || typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
  try {
    // Server does the recurrence + multi-reminder-offset math
    // (server/events.js dueReminders); the client only asks "what's due now".
    const res = await api('GET', '/api/events/due-reminders?withinMinutes=2');
    maybeGoalNudge();
    for (const ev of res.events) {
      if (notifiedReminderKeys.has(ev.triggerKey)) continue;
      notifiedReminderKeys.add(ev.triggerKey);
      fireReminderNotification(ev);
    }
  } catch { /* non-fatal -- notifications are a convenience, not core function */ }
}

// Notification privacy (spec section 5) -- a per-device preference stored
// locally; it only affects what this browser displays, never the server.
// Upcoming window, in days. A per-device choice. The server accepts 1-365.
const UPCOMING_WINDOW_OPTIONS = [[30, '30 days'], [60, '60 days'], [180, '6 months'], [365, '1 year']];
// The account is the source of truth for this value (server: user_preferences).
// The in-memory copy below is loaded from the server at sign-in and after each
// change. It is never read back from localStorage, so the value follows the
// account to every device.
let upcomingWindowCache = 60;
function upcomingWindowDays() { return upcomingWindowCache; }
async function loadPreferences() {
  try { upcomingWindowCache = (await api('GET', '/api/preferences')).upcomingWindowDays; }
  catch { upcomingWindowCache = 60; }
}
async function setUpcomingWindowDays(days) {
  const prefs = await api('PUT', '/api/preferences/upcoming-window', { days });
  upcomingWindowCache = prefs.upcomingWindowDays;
}

function notifPrivacyLevel() {
  return localStorage.getItem('vx_notif_privacy') || 'full';
}
function setNotifPrivacyLevel(level) {
  try { localStorage.setItem('vx_notif_privacy', level); } catch { /* non-fatal */ }
}

function fireReminderNotification(ev) {
  const privacy = notifPrivacyLevel();
  const m = ev.reminderMinutesBefore;
  const whenPhrase = m === 0 ? 'is now' : m < 60 ? `is in ${m} min` : m < 1440 ? `is in ${Math.round(m / 60)} hr` : 'is coming up';
  let title = 'VAULTIXgusTAR';
  let body;
  if (privacy === 'hide') body = 'You have a security reminder.';
  else if (privacy === 'limited') body = `You have a reminder ${whenPhrase}. Tap to view.`;
  else { title = `VAULTIXgusTAR -- ${ev.title}`; body = `${ev.title} ${whenPhrase}. Tap to view event.`; }
  try {
    const n = new Notification(title, { body, icon: '/brand/icon-192.png', tag: ev.id });
    n.onclick = () => {
      window.focus();
      state.active = 'calendar';
      state.pendingOpenEventId = ev.id;
      render();
    };
  } catch { /* Notification constructor can throw on some platforms -- non-fatal */ }
}

function notifPermission() {
  return typeof Notification === 'undefined' ? 'unsupported' : Notification.permission;
}

let idleTimer = null;
function resetIdleWatch() {
  if (idleTimer) clearInterval(idleTimer);
  idleTimer = setInterval(async () => {
    if (state.screen !== 'app' || !state.unlocked) return;
    // The server is the source of truth for auto-lock (it drops the cached
    // key after user.autoLockMs of inactivity). We just poll /auth/me
    // periodically so the UI notices and returns to the unlock screen.
    try {
      const me = await api('GET', '/api/auth/me');
      if (!me.unlocked) {
        state.unlocked = false;
        state.screen = 'unlock';
        toast('Vault auto-locked due to inactivity', 'warn');
        render();
      }
    } catch { /* handled by api() */ }
  }, 5000);
}
['click', 'keydown', 'mousemove'].forEach((evt) => {
  document.addEventListener(evt, () => { /* server tracks activity per-request; nothing to do client-side */ }, { passive: true });
});

// Global search shortcut — Ctrl/Cmd+K opens search from any screen, Escape
// closes it from anywhere (not just while the input itself has focus).
document.addEventListener('keydown', (e) => {
  const isShortcut = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k';
  if (isShortcut && state.screen === 'app' && state.unlocked && !state.duress && !state.modal) {
    e.preventDefault();
    if (state.searchOpen) closeSearch(); else openSearch();
    return;
  }
  if (e.key === 'Escape' && state.searchOpen) {
    closeSearch();
  }
});

// ---------------------------------------------------------------------------
// Data loaders
// ---------------------------------------------------------------------------
async function loadDashboardData() {
  await loadPreferences();
  const [summaryRes, activityRes, upcomingRes, walkRes] = await Promise.all([
    api('GET', '/api/vault/summary'),
    api('GET', '/api/security/activity'),
    api('GET', `/api/events/upcoming?days=${upcomingWindowDays()}`),
    api('GET', '/api/activity/sessions'),
  ]);
  state.summary = summaryRes.summary;
  state.activity = activityRes.events;
  state.upcomingEvents = upcomingRes.events;
  state.walkingHistory = walkRes.sessions;
}

async function loadPasswords() {
  const res = await api('GET', '/api/vault/items?type=password');
  state.passwordItems = res.items;
}
async function loadNotes() {
  const res = await api('GET', '/api/vault/items?type=note');
  state.noteItems = res.items;
}
async function loadPersonal() {
  const res = await api('GET', '/api/vault/items?type=personal');
  if (res.items[0]) {
    const full = await api('GET', `/api/vault/items/${res.items[0].id}`);
    state.personalItem = full.item;
  } else {
    state.personalItem = null;
  }
}
// These four screens show a non-secret preview field (e.g. "AWS" under an
// API key titled "AWS Production"). That preview comes from the same
// plaintext `searchUsername` metadata column passwords already use for
// their username/email preview — see bindGenericFormEvents() where it's
// populated from each type's designated non-secret field on save. It is
// NOT the decrypted payload: list screens never fetch secret content, so
// nothing sensitive sits in memory until the user explicitly reveals it.
async function loadDeveloper() {
  const [apikeys, sshkeys, wallets] = await Promise.all([
    api('GET', '/api/vault/items?type=apikey'),
    api('GET', '/api/vault/items?type=sshkey'),
    api('GET', '/api/vault/items?type=wallet'),
  ]);
  state.developerItems = { apikey: apikeys.items, sshkey: sshkeys.items, wallet: wallets.items };
}
async function loadDocuments() {
  const res = await api('GET', '/api/vault/items?type=document');
  state.documentItems = res.items;
}
async function loadPhysical() {
  const [physical, license] = await Promise.all([
    api('GET', '/api/vault/items?type=physical'),
    api('GET', '/api/vault/items?type=license'),
  ]);
  state.physicalItems = { physical: physical.items, license: license.items };
}
async function loadMedical() {
  const [medical, inheritance] = await Promise.all([
    api('GET', '/api/vault/items?type=medical'),
    api('GET', '/api/vault/items?type=inheritance'),
  ]);
  state.medicalItems = { medical: medical.items, inheritance: inheritance.items };
}
async function loadCustomItems() {
  const res = await api('GET', '/api/vault/items?type=custom');
  state.customItems = res.items;
}
async function loadCalendar() {
  if (!state.calendarCursor) {
    const now = new Date();
    state.calendarCursor = { year: now.getFullYear(), month: now.getMonth() };
  }
  const { year, month } = state.calendarCursor;
  const from = localDateStr(new Date(year, month, 1));
  const to = localDateStr(new Date(year, month + 1, 0));
  const [rangeRes, upcomingRes, completedRes] = await Promise.all([
    api('GET', `/api/events?from=${from}&to=${to}`),
    api('GET', `/api/events/upcoming?days=${upcomingWindowDays()}`),
    api('GET', '/api/events/completed'),
  ]);
  state.events = rangeRes.events;
  state.upcomingEvents = upcomingRes.events;
  state.completedEvents = completedRes.events;
}
function localDateStr(d) {
  // Deliberately NOT toISOString() — that converts to UTC and can shift the
  // date across midnight depending on the user's timezone offset, which
  // would show events on the wrong day near month boundaries.
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
async function loadSecurity() {
  const [status, sessions] = await Promise.all([
    api('GET', '/api/security/status'),
    api('GET', '/api/auth/sessions'),
  ]);
  state.security = status;
  state.sessions = sessions.sessions;
  state.emergency = (await api('GET', '/api/emergency')).contacts;
}
async function loadActivity() {
  const res = await api('GET', '/api/security/activity');
  state.activity = res.events;
  state.chainStatus = null;
}
async function loadAvatar() {
  try {
    const res = await api('GET', '/api/profile/avatar');
    state.avatarDataUrl = `data:${res.mimeType};base64,${res.dataBase64}`;
  } catch {
    state.avatarDataUrl = null;
  }
}

async function navigate(key) {
  state.active = key; state.modal = null; state.mobileOpen = false;
  if (state.duress) {
    // Decoy session: never fetch anything real. Only Dashboard and Settings
    // (sign out / lock) exist in duress mode — see renderApp().
    render();
    return;
  }
  try {
    if (key === 'dashboard') await loadDashboardData();
    if (key === 'passwords' || key === 'emails') await loadPasswords();
    if (key === 'notes') await loadNotes();
    if (key === 'custom') await loadCustomItems();
    if (key === 'personal') await loadPersonal();
    if (key === 'developer') await loadDeveloper();
    if (key === 'documents') await loadDocuments();
    if (key === 'physical') await loadPhysical();
    if (key === 'medical') await loadMedical();
    if (key === 'calendar') await loadCalendar();
    if (key === 'walking') await loadWalking();
    if (key === 'security') { await loadSecurity(); state.health = null; }
    if (key === 'activity') await loadActivity();
    if (key === 'settings') await loadSecurity();
  } catch (e) { toast(e.message, 'error'); }
  render();
}
window.navigate = navigate;

// ---------------------------------------------------------------------------
// Duress ("panic") decoy data — entirely fabricated, held only in memory,
// never derived from or written back to anything real. See enterDuressMode()
// and the DURESS_ALLOWED_PATHS gate in api() above.
// ---------------------------------------------------------------------------
const DECOY = {
  summary: { passwords: 4, emails: 2, personal: 1, notes: 2 },
  passwordItems: [
    { id: 'decoy-1', title: 'Netflix', searchUsername: 'demo@example.com', payload: { password: 'N3tfl1xW4tch!' } },
    { id: 'decoy-2', title: 'Spotify', searchUsername: 'demo@example.com', payload: { password: 'Mus1cLover2024' } },
    { id: 'decoy-3', title: 'Amazon', searchUsername: 'demo@example.com', payload: { password: 'Sh0pp1ngT1me!' } },
    { id: 'decoy-4', title: 'LinkedIn', searchUsername: 'demo@example.com', payload: { password: 'C4reerN3tw0rk' } },
  ],
  noteItems: [
    { id: 'decoy-n1', title: 'Grocery List', payload: { content: 'Milk, eggs, bread, rice, tomatoes' } },
    { id: 'decoy-n2', title: 'Wi-Fi Guest Code', payload: { content: 'Network: Guest_5G\nPassword: welcome2024' } },
  ],
  activity: [
    { text: 'Successful login', created_at: Date.now() - 3600_000 },
    { text: 'Password added: Amazon', created_at: Date.now() - 86_400_000 },
    { text: 'Vault unlocked using PIN', created_at: Date.now() - 172_800_000 },
  ],
};

// ---------------------------------------------------------------------------
// Icons — a small hand-built line-icon set (inline SVG, currentColor
// stroke). No emoji anywhere in the interface, no icon-font, no network
// font/asset loads — every glyph in the app is one of these paths.
// ---------------------------------------------------------------------------
const ICON_PATHS = {
  home: '<path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V20a1 1 0 0 0 1 1h4v-6h4v6h4a1 1 0 0 0 1-1V9.5"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.8 12.2 19 4l2 2-1.5 1.5L21 9l-2 2-1.7-1.7L15.5 11"/>',
  lock: '<rect x="4.5" y="10.5" width="15" height="9.5" rx="2"/><path d="M7.5 10.5V7.5a4.5 4.5 0 0 1 9 0v3"/>',
  unlock: '<rect x="4.5" y="10.5" width="15" height="9.5" rx="2"/><path d="M7.5 10.5V7.5a4.5 4.5 0 0 1 8-2.8"/>',
  shield: '<path d="M12 3 5 5.5v5.7c0 4.6 3 8 7 9.8 4-1.8 7-5.2 7-9.8V5.5L12 3Z"/>',
  mail: '<rect x="3" y="5.5" width="18" height="13" rx="2"/><path d="m4 7 8 6 8-6"/>',
  user: '<circle cx="12" cy="8.2" r="3.7"/><path d="M4.5 20.5c.5-4 3.6-6.5 7.5-6.5s7 2.5 7.5 6.5"/>',
  idcard: '<rect x="3" y="5.5" width="18" height="13" rx="2"/><circle cx="9" cy="11" r="1.8"/><path d="M6 17c0-1.6 1.3-2.8 3-2.8s3 1.2 3 2.8"/><path d="M14.5 10h4M14.5 13.5h4"/>',
  note: '<path d="M7 3.5h7l4 4V20a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4.5a1 1 0 0 1 1-1Z"/><path d="M14 3.5v4h4"/><path d="M9 13h6M9 16.5h6"/>',
  settings: '<circle cx="12" cy="12" r="2.8"/><path d="M19.4 14.5a1.7 1.7 0 0 0 .3 1.9l.1.1a1.9 1.9 0 1 1-2.7 2.7l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5v.2a1.9 1.9 0 1 1-3.8 0v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1a1.9 1.9 0 1 1-2.7-2.7l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a1.9 1.9 0 1 1 0-3.8h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1A1.9 1.9 0 1 1 7 4.9l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3.5a1.9 1.9 0 1 1 3.8 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a1.9 1.9 0 1 1 2.7 2.7l-.1.1a1.7 1.7 0 0 0-.3 1.9v.1a1.7 1.7 0 0 0 1.5 1h.2a1.9 1.9 0 1 1 0 3.8h-.1a1.7 1.7 0 0 0-1.5 1Z"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.3-4.3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  eye: '<path d="M2.5 12S6 6 12 6s9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.8"/>',
  eyeOff: '<path d="M3 3l18 18"/><path d="M10.6 10.7a2.8 2.8 0 0 0 3.9 3.9"/><path d="M7.8 5.7A9.6 9.6 0 0 1 12 4.8c6 0 9.5 5.7 9.5 5.7a12.7 12.7 0 0 1-3 3.6M5.6 7.4C3.4 9.2 2.5 10.5 2.5 10.5A12.9 12.9 0 0 0 6 14.3"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4.5a1 1 0 0 1-1-1V4.5a1 1 0 0 1 1-1H15a1 1 0 0 1 1 1V6"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4.5 1L4.5 14.5Z"/>',
  trash: '<path d="M4.5 7h15"/><path d="M10 11v6M14 11v6"/><path d="M6.5 7l.8 12a1 1 0 0 0 1 1h7.4a1 1 0 0 0 1-1l.8-12"/><path d="M9 7V4.5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1V7"/>',
  check: '<path d="M5 12.5 10 17.5 19.5 6.5"/>',
  warn: '<path d="M12 3.5 2.5 20h19L12 3.5Z"/><path d="M12 10v3.5M12 17h.01"/>',
  fingerprint: '<path d="M12 3.2a8.8 8.8 0 0 0-8.8 8.8v1.8"/><path d="M12 3.2A8.8 8.8 0 0 1 20.8 12v2.5"/><path d="M7.2 20a13 13 0 0 1-1.8-6"/><path d="M16.8 20a13 13 0 0 0 1.8-6"/><path d="M9 21a17 17 0 0 1-1.3-7.5A4.3 4.3 0 0 1 12 9a4.3 4.3 0 0 1 4.3 4.5c0 1.9.3 3.8.9 5.6"/><path d="M12 17.2a6.6 6.6 0 0 1-.9-3.4 0.9.9 0 0 1 1.8 0"/>',
  menu: '<path d="M4 6.5h16M4 12h16M4 17.5h16"/>',
  arrowLeft: '<path d="M19 12H5M11 18l-6-6 6-6"/>',
  arrowRight: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  chevronDown: '<path d="M6 9.5 12 15l6-5.5"/>',
  chevronRight: '<path d="M9 6l6 6-6 6"/>',
  wifi: '<path d="M2.5 8.8a15 15 0 0 1 19 0"/><path d="M5.8 12.3a10.4 10.4 0 0 1 12.4 0"/><path d="M9 15.7a5.7 5.7 0 0 1 6 0"/><circle cx="12" cy="19" r="1"/>',
  contact: '<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18.2h2"/>',
  account: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5a13 13 0 0 1 0 17"/><path d="M12 3.5a13 13 0 0 0 0 17"/>',
  x: '<path d="m6 6 12 12M18 6 6 18"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.6-5.9"/><path d="M20 3.5v5.4h-5.4"/>',
  droplet: '<path d="M12 3.5s6.5 7.4 6.5 12A6.5 6.5 0 0 1 5.5 15.5C5.5 10.9 12 3.5 12 3.5Z"/>',
  bell: '<path d="M6 9a6 6 0 0 1 12 0v4.5l1.8 3H4.2L6 13.5Z"/><path d="M10 19.5a2 2 0 0 0 4 0"/>',
  backspace: '<path d="M9 6h10a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H9l-6-6Z"/><path d="m11 10 4 4M15 10l-4 4"/>',
  activity: '<path d="M3 12h4l2.5-7L14 19l2.5-7H21"/>',
};

// ---------------------------------------------------------------------------
// Field configs for the newer vault item types — [key, label, sensitive, kind]
// sensitive fields are masked until reveal; kind is 'text' or 'textarea'.
// ---------------------------------------------------------------------------
const FIELD_CONFIGS = {
  wifi: [['network', 'Network Name', false, 'text'], ['password', 'Wi-Fi Password', true, 'text'], ['notes', 'Notes', false, 'textarea']],
  contact: [['phone', 'Phone', false, 'text'], ['email', 'Email', false, 'text'], ['notes', 'Notes', false, 'textarea']],
  account: [['website', 'Website / Service', false, 'text'], ['username', 'Username', false, 'text'], ['notes', 'Notes', false, 'textarea']],
  apikey: [['service', 'Service', false, 'text'], ['keyId', 'Key ID / Access Key', false, 'text'], ['secretKey', 'Secret Key', true, 'text'], ['environment', 'Environment', false, 'text'], ['notes', 'Notes', false, 'textarea']],
  sshkey: [['host', 'Host', false, 'text'], ['port', 'Port', false, 'text'], ['username', 'Username', false, 'text'], ['privateKey', 'Private Key', true, 'textarea'], ['passphrase', 'Passphrase', true, 'text'], ['notes', 'Notes', false, 'textarea']],
  wallet: [['network', 'Network', false, 'text'], ['address', 'Wallet Address', false, 'text'], ['seedPhrase', 'Seed Phrase', true, 'textarea'], ['privateKey', 'Private Key', true, 'text'], ['exchangeApiKey', 'Exchange API Key', true, 'text'], ['notes', 'Notes', false, 'textarea']],
  physical: [['location', 'Location', false, 'text'], ['code', 'Code / PIN', true, 'text'], ['notes', 'Notes', false, 'textarea']],
  license: [['software', 'Software', false, 'text'], ['licenseKey', 'License Key', true, 'text'], ['edition', 'Edition', false, 'text'], ['notes', 'Notes', false, 'textarea']],
  medical: [['bloodType', 'Blood Type', false, 'text'], ['conditions', 'Conditions', false, 'textarea'], ['medications', 'Medications', false, 'textarea'], ['allergies', 'Allergies', false, 'text'], ['emergencyDoctor', 'Emergency Doctor', false, 'text'], ['doctorPhone', 'Doctor Phone', false, 'text'], ['insuranceProvider', 'Insurance Provider', false, 'text'], ['policyNumber', 'Policy Number', true, 'text']],
  inheritance: [['instructions', 'Instructions', false, 'textarea']],
  document: [['description', 'Description', false, 'text'], ['notes', 'Notes', false, 'textarea']],
};
const TYPE_ICON_NAME = {
  password: 'lock', email: 'mail', personal: 'user', id: 'idcard', note: 'note',
  wifi: 'wifi', contact: 'contact', account: 'account', apikey: 'key', sshkey: 'lock',
  wallet: 'key', physical: 'lock', license: 'idcard', medical: 'activity', inheritance: 'note', document: 'idcard',
  custom: 'idcard',
};
const SENSITIVE_KEYS = new Set(Object.values(FIELD_CONFIGS).flat().filter((f) => f[2]).map((f) => f[0]).concat(['password']));
// Which single non-secret field (if any) becomes the plaintext, unencrypted
// `searchUsername` preview shown in list rows — same mechanism passwords
// already use for their username/email preview. Deliberately omits types
// with no safe-to-preview field (physical codes, medical, inheritance).
const PREVIEW_FIELD = { apikey: 'service', sshkey: 'host', wallet: 'network', license: 'software', document: 'description', physical: 'location', medical: 'bloodType' };

function icon(name, size = 16) {
  const paths = ICON_PATHS[name] || '';
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" style="display:block;flex-shrink:0;vertical-align:middle" aria-hidden="true">${paths}</svg>`;
}

// ICON.<name> keeps every existing call site in this file unchanged (they
// were written as `${ICON.eye}` etc.) while switching the underlying glyph
// from an emoji character to a rendered SVG icon at a sensible default size.
const ICON = new Proxy({}, {
  get(_, name) {
    const map = {
      password: 'lock', email: 'mail', personal: 'user', id: 'idcard',
      security: 'shield', settings: 'settings', lock: 'lock', search: 'search',
      plus: 'plus', eyeOff: 'eyeOff', copy: 'copy', edit: 'edit', trash: 'trash',
      check: 'check', warn: 'warn', menu: 'menu', arrowLeft: 'arrowLeft',
      wifi: 'wifi', contact: 'contact', account: 'account', note: 'note',
      home: 'home', activity: 'activity', eye: 'eye', fingerprint: 'fingerprint',
    };
    return icon(map[name] || name, 16);
  },
});

// ---------------------------------------------------------------------------
// Render dispatch
// ---------------------------------------------------------------------------
function render() {
  if (state.screen === 'loading') { root.innerHTML = ''; return; }
  if (state.screen === 'login') return renderAuthShell(loginView());
  if (state.screen === 'register') return renderAuthShell(registerView());
  if (state.screen === 'recovery') return renderAuthShell(recoveryView());
  if (state.screen === 'recovery-key-reveal') return renderAuthShell(recoveryKeyRevealView());
  if (state.screen === 'unlock') return renderAuthShell(unlockView());
  if (state.screen === 'biometric') return renderAuthShell(biometricView());
  if (state.screen === 'app') return renderApp();
}

function renderAuthShell(innerHtml) {
  root.innerHTML = `
    <div class="auth-shell">
      <div class="auth-box">
        <div class="auth-brand">
          <div class="auth-logo"><img src="/brand/icon-256.png" alt="" /></div>
          <h1>${APP_NAME}</h1>
          <p>Your private world, securely stored.</p>
        </div>
        <div class="card auth-card">${innerHtml}</div>
        <div class="auth-foot">Reference implementation — see README for architecture notes.</div>
      </div>
    </div>`;
  bindAuthEvents();
}

// ---------------------------------------------------------------------------
// Login / Register / Recovery views
// ---------------------------------------------------------------------------
function loginView() {
  return `
    <form id="login-form">
      <div class="field"><label>Email / Username</label><input name="email" type="email" required autocomplete="username" placeholder="you@example.com" /></div>
      <div class="field">
        <label>Master Password</label>
        <div class="pw-wrap">
          <input name="password" type="password" required autocomplete="current-password" placeholder="••••••••••••••••" />
          <button type="button" class="pw-toggle" data-toggle="password">${ICON.eye}</button>
        </div>
      </div>
      <div id="login-error"></div>
      ${state.loginAttempts >= 3 ? `<div class="warn-banner">${ICON.warn} Multiple failed attempts detected — further attempts are rate-limited.</div>` : ''}
      <button class="btn btn-primary btn-block" type="submit">Unlock Vault</button>
      <div class="divider-or"><span>OR</span></div>
      <button class="btn btn-subtle btn-block" type="button" id="login-biometric" style="margin-bottom:10px;">${ICON.fingerprint} Use Fingerprint</button>
      <button class="btn btn-ghost btn-block" type="button" id="login-pin">Use PIN</button>
      <div style="display:flex; justify-content:space-between; margin-top:18px;">
        <button class="link-btn" type="button" id="go-recovery">Forgot password?</button>
        <button class="link-btn" type="button" id="go-register">Create a vault</button>
      </div>
    </form>`;
}

function registerView() {
  return `
    <button class="link-btn" id="back-login" style="display:flex;align-items:center;gap:6px;margin-bottom:14px;">${ICON.arrowLeft} Back to sign in</button>
    <form id="register-form">
      <div class="field" style="text-align:center;">
        <label>Profile Picture (optional)</label>
        <div id="avatar-preview" class="avatar-picker">${icon('user', 22)}</div>
        <input type="file" id="avatar-file-input" accept="image/png,image/jpeg,image/webp" style="display:none;" />
        <button type="button" class="link-btn" id="avatar-pick-btn" style="justify-content:center;width:100%;margin-top:8px;">${icon('edit', 13)} Choose photo</button>
      </div>
      <div class="field"><label>Full Name</label><input name="name" required autocomplete="name" placeholder="Your name" /></div>
      <div class="field"><label>Recovery Email</label><input name="email" type="email" required autocomplete="email" placeholder="you@example.com" /></div>
      <div class="field"><label>Create Master Password</label><input name="password" type="password" required minlength="8" autocomplete="new-password" placeholder="••••••••••••••••" /></div>
      <div class="field"><label>Confirm Password</label><input name="confirm" type="password" required autocomplete="new-password" placeholder="••••••••••••••••" /></div>
      <div id="register-error"></div>
      <button class="btn btn-primary btn-block" type="submit">Create Secure Vault</button>
      <div class="field-hint">Your master password is hashed (scrypt) and never stored or transmitted in plain text. See README for the exact key-derivation architecture.</div>
    </form>`;
}

function recoveryKeyRevealView() {
  return `
    <div style="text-align:center;margin-bottom:6px;">
      <div style="color:var(--blue);margin-bottom:8px;">${icon('shield', 30)}</div>
      <div style="font-weight:700;font-size:16px;color:var(--navy);">Save your Recovery Key</div>
      <div style="font-size:12.5px;color:var(--text-muted);margin-top:4px;">If you forget your master password, this key plus your recovery email is the only way back into your vault. VAULTIXgusTAR cannot recover it for you.</div>
    </div>
    <div class="recovery-key-box">${state.pendingRecoveryKey}</div>
    <button class="btn btn-subtle btn-block" id="copy-recovery-key" style="margin-bottom:10px;">${ICON.copy} Copy Recovery Key</button>
    <button class="btn btn-primary btn-block" id="continue-after-recovery-key">I've stored it safely — Continue</button>`;
}

function recoveryView() {
  const { step, email, code } = state.recovery;
  const steps = `<div style="display:flex;gap:6px;margin-bottom:20px;">${[1,2,3,4].map((s) => `<div style="flex:1;height:4px;border-radius:4px;background:${s <= step ? 'var(--blue)' : 'var(--border)'}"></div>`).join('')}</div>`;
  let body = '';
  if (step === 1) {
    body = `
      <div style="font-weight:700;color:var(--navy);margin-bottom:4px;">Verify recovery email</div>
      <div style="font-size:12.5px;color:var(--text-muted);margin-bottom:14px;">Enter the email linked to your vault.</div>
      <div class="field"><label>Recovery Email</label><input id="rec-email" type="email" value="${email}" placeholder="you@example.com" /></div>
      <button class="btn btn-primary btn-block" id="rec-send-code">Send Verification Code</button>`;
  } else if (step === 2) {
    body = `
      <div style="font-weight:700;color:var(--navy);margin-bottom:4px;">Enter one-time code</div>
      <div style="font-size:12.5px;color:var(--text-muted);margin-bottom:14px;">We sent a 6-digit code to ${email}. In this offline sandbox it's printed to the server console instead of emailed — see README.</div>
      <div class="field"><label>Verification Code</label><input id="rec-code" value="${code}" placeholder="••••••" /></div>
      <button class="btn btn-primary btn-block" id="rec-verify-code">Verify Code</button>`;
  } else if (step === 3) {
    body = `
      <div style="font-weight:700;color:var(--navy);margin-bottom:4px;">Enter Recovery Key</div>
      <div class="field"><label>Recovery Key</label><input id="rec-key" placeholder="K7X9-PQ2M-8F4L-2Z6R" style="text-transform:uppercase;" /></div>
      <div class="field"><label>New Master Password</label><input id="rec-newpw" type="password" minlength="8" placeholder="••••••••••••••••" /></div>
      <button class="btn btn-primary btn-block" id="rec-reset">Restore Access to Vault</button>
      <div class="field-hint" style="background:var(--bg);padding:10px;border-radius:8px;margin-top:10px;">
        <b>Trade-off:</b> because your vault key is only ever unwrapped via your password or this recovery key, losing both means the encrypted data genuinely cannot be recovered — a reset alone can't decrypt old data. See README "Recovery trade-offs".
      </div>`;
  }
  return `<button class="link-btn" id="back-login" style="display:flex;align-items:center;gap:6px;margin-bottom:14px;">${ICON.arrowLeft} Back to sign in</button>${steps}<div id="rec-error"></div>${body}`;
}

function unlockView() {
  const name = state.user?.name || '';
  const disabled = Date.now() < state.pinLockedUntil;
  const dots = Array.from({ length: 6 }, (_, i) => `<div class="pin-dot">${state.pinBuffer[i] ? '•' : ''}</div>`).join('');
  const keys = ['1','2','3','4','5','6','7','8','9','⌫','0','OK'];
  return `
    <div style="text-align:center;margin-bottom:20px;">
      <div style="color:var(--blue);margin-bottom:8px;">${icon('lock', 30)}</div>
      <div style="font-weight:700;font-size:16px;color:var(--navy);">Vault Locked</div>
      <div style="font-size:12.5px;color:var(--text-muted);margin-top:2px;">Welcome back, ${name}</div>
    </div>
    <div class="pin-dots">${dots}</div>
    <div id="pin-error" style="text-align:center;color:var(--danger);font-size:12.5px;margin-bottom:10px;"></div>
    <div class="pin-pad">${keys.map((k) => `<button class="pin-key ${k === 'OK' ? 'ok' : ''}" data-key="${k}" ${disabled ? 'disabled' : ''}>${k === '\u232b' ? icon('backspace', 18) : k}</button>`).join('')}</div>
    <button class="btn btn-subtle btn-block" id="unlock-biometric" style="margin-bottom:8px;">${ICON.fingerprint} Use Fingerprint</button>
    <button class="btn btn-ghost btn-block" id="unlock-password-instead">Use Master Password</button>
    <div id="unlock-password-form" class="hidden" style="margin-top:14px;">
      <div class="field"><label>Master Password</label><input id="unlock-password" type="password" placeholder="••••••••••••••••" /></div>
      <button class="btn btn-primary btn-block" id="unlock-password-submit">Unlock Vault</button>
    </div>
    <div style="text-align:center;margin-top:14px;"><button class="link-btn" id="unlock-signout">Sign out</button></div>`;
}

function biometricView() {
  return `
    <div style="text-align:center;padding:20px 0;">
      <div class="biometric-pulse">${icon('fingerprint', 32)}</div>
      <div style="font-weight:700;color:var(--navy);margin-bottom:4px;">Verifying biometrics…</div>
      <div style="font-size:12.5px;color:var(--text-muted);">Handled by your device's secure enclave.</div>
    </div>`;
}

// ---------------------------------------------------------------------------
// App shell (unlocked)
// ---------------------------------------------------------------------------
const NAV = [
  ['dashboard', 'Dashboard', ICON.home],
  ['passwords', 'Passwords', ICON.password],
  ['emails', 'Emails', ICON.email],
  ['personal', 'Personal Details', ICON.personal],
  ['notes', 'Secure Notes', ICON.note],
  ['custom', 'Custom Items', icon('idcard', 16)],
  ['developer', 'Developer & Crypto', icon('key', 16)],
  ['documents', 'Documents', ICON.id],
  ['physical', 'Physical & Licenses', icon('lock', 16)],
  ['medical', 'Medical & Estate', icon('activity', 16)],
  ['calendar', 'Calendar', icon('clock', 16)],
  ['walking', 'Walking', icon('activity', 16)],
  ['security', 'Security Centre', ICON.security],
  ['activity', 'Activity Log', ICON.activity],
  ['settings', 'Settings', ICON.settings],
];
const TITLES = Object.fromEntries(NAV.map(([k, l]) => [k, l]));

function renderApp() {
  const navItems = state.duress ? NAV.filter(([key]) => ['dashboard', 'passwords', 'notes'].includes(key)) : NAV;
  root.innerHTML = `
    <div class="app-shell">
      ${state.mobileOpen ? '<div class="scrim" id="scrim"></div>' : ''}
      <div class="sidebar ${state.mobileOpen ? 'open' : ''}">
        <div class="sidebar-brand"><div class="mark"><img src="/brand/icon-256.png" alt="" /></div><div class="name">${APP_NAME}</div></div>
        <div class="nav-list">
          ${navItems.map(([key, label, ic]) => `<button class="nav-item ${state.active === key ? 'active' : ''}" data-nav="${key}">${ic} ${label}</button>`).join('')}
        </div>
        <div class="sidebar-foot"><button class="lock-btn" id="lock-vault-btn">${ICON.lock} Lock Vault</button></div>
      </div>
      <div class="main">
        <div class="topbar">
          <div class="topbar-left">
            <button class="icon-btn menu-btn" id="menu-btn">${ICON.menu}</button>
            <span class="topbar-title">${TITLES[state.active] || 'Dashboard'}</span>
          </div>
          <div style="display:flex;align-items:center;gap:14px;">
            ${state.duress ? '' : `<button class="icon-btn" id="topbar-search" title="Search (${isMac() ? '⌘K' : 'Ctrl+K'})">${ICON.search}</button>`}
            <button class="icon-btn" id="topbar-lock" title="Lock Vault">${ICON.lock}</button>
            <div class="avatar">${state.avatarDataUrl ? `<img src="${state.avatarDataUrl}" alt="" />` : (state.user.name || '?').slice(0,1).toUpperCase()}</div>
          </div>
        </div>
        <div class="content">${screenHtml()}</div>
      </div>
      ${state.active !== 'dashboard' && !state.duress ? `<button class="fab" id="fab-add">${ICON.plus}</button>` : ''}
    </div>
    ${state.searchOpen ? searchOverlay() : ''}
    ${state.modal ? modalHtml() : ''}
  `;
  bindAppEvents();
  if (state.searchOpen) bindSearchEvents();
}

function screenHtml() {
  if (state.duress && !['dashboard', 'passwords', 'notes'].includes(state.active)) state.active = 'dashboard';
  switch (state.active) {
    case 'dashboard': return dashboardScreen();
    case 'passwords': return passwordsScreen();
    case 'emails': return emailsScreen();
    case 'personal': return personalScreen();
    case 'notes': return notesScreen();
    case 'custom': return customItemsScreen();
    case 'developer': return developerScreen();
    case 'documents': return documentsScreen();
    case 'physical': return physicalScreen();
    case 'medical': return medicalScreen();
    case 'calendar': return calendarScreen();
    case 'walking': return walkingScreen();
    case 'security': return securityScreen();
    case 'activity': return activityScreen();
    case 'settings': return settingsScreen();
    default: return '';
  }
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function timeAgo(ts) {
  const diff = Math.max(0, Date.now() - ts);
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return new Date(ts).toLocaleDateString();
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
function dashboardScreen() {
  const s = state.duress ? DECOY.summary : state.summary;
  const activityList = state.duress ? DECOY.activity : state.activity;
  return `
    <div style="margin-bottom:20px;">
      <div style="font-size:20px;font-weight:800;color:var(--navy);">Welcome back, ${esc((state.user.name || '').split(' ')[0])}</div>
      <div style="font-size:13px;color:var(--text-muted);margin-top:2px;">Last login ${state.user.lastLogin ? timeAgo(state.user.lastLogin) : '—'}</div>
    </div>
    ${state.duress ? '' : `
    <button class="search-trigger" id="open-search">
      <span class="icon">${ICON.search}</span>
      <span class="search-trigger-label">Search your vault…</span>
      <span class="search-trigger-kbd">${isMac() ? '⌘K' : 'Ctrl K'}</span>
    </button>`}
    <div class="stat-grid">
      <div class="card stat-card" data-nav="passwords"><div class="stat-icon">${ICON.password}</div><div class="stat-value">${s.passwords || 0}</div><div class="stat-label">Passwords</div></div>
      <div class="card stat-card" data-nav="${state.duress ? 'passwords' : 'emails'}"><div class="stat-icon">${ICON.email}</div><div class="stat-value">${s.emails || 0}</div><div class="stat-label">Emails</div></div>
      <div class="card stat-card" data-nav="${state.duress ? 'notes' : 'personal'}"><div class="stat-icon">${ICON.personal}</div><div class="stat-value">${s.personal || 0}</div><div class="stat-label">Personal</div></div>
      <div class="card stat-card" data-nav="notes"><div class="stat-icon">${ICON.note}</div><div class="stat-value">${s.notes || 0}</div><div class="stat-label">Secure Notes</div></div>
    </div>
    <div class="two-col">
      <div class="card" style="padding:18px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
          <div style="font-weight:700;color:var(--navy);font-size:14.5px;">Recent Activity</div>
          ${state.duress ? '' : `<button class="link-btn" data-nav="activity">View all</button>`}
        </div>
        ${activityList.slice(0, 4).map((a) => `
          <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);">
            <div style="width:8px;height:8px;border-radius:50%;background:var(--success);"></div>
            <div style="flex:1;font-size:13px;">${esc(a.text)}</div>
            <div style="font-size:11.5px;color:var(--text-muted);">${timeAgo(a.created_at)}</div>
          </div>`).join('') || '<div style="font-size:13px;color:var(--text-muted);">No activity yet.</div>'}
      </div>
      <div class="card" style="padding:18px;">
        <div style="font-weight:700;color:var(--navy);font-size:14.5px;margin-bottom:12px;">Security Status</div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
          <span style="color:var(--success);display:flex;">${icon('shield', 16)}</span><span style="font-size:13.5px;font-weight:600;">Vault Protected</span>
        </div>
        <div style="font-size:12.5px;color:var(--text-muted);line-height:2;">
          <div>Biometric unlock: <b style="color:${state.user.biometricEnabled ? 'var(--success)' : 'inherit'}">${state.user.biometricEnabled ? 'ON' : 'OFF'}</b></div>
          <div>Two-factor authentication: <b style="color:${state.user.twoFactorEnabled ? 'var(--success)' : 'var(--warning)'}">${state.user.twoFactorEnabled ? 'ON' : 'OFF'}</b></div>
          <div>Auto-lock: <b>${autoLockLabel(state.user.autoLockMs)}</b></div>
        </div>
        <button class="btn btn-outline btn-block" style="margin-top:12px;" data-nav="${state.duress ? 'passwords' : 'security'}">${state.duress ? 'View All Passwords' : 'Open Security Centre'}</button>
      </div>
    </div>
    ${state.duress ? '' : upcomingDashboardCard()}
    ${state.duress ? '' : walkingDashboardCard()}
    ${state.duress ? '' : `<button class="btn btn-dark" style="margin-top:18px;" id="fab-add">${ICON.plus} Add Information</button>`}
  `;
}

// Dashboard walking card -- real recorded GPS sessions only. Shows the empty
// state when nothing has been recorded. Never a step count (spec sections 18,
// 30, 32: never fabricate activity measurements).
function walkingDashboardCard() {
  const sessions = state.walkingHistory || [];
  const startOfToday = new Date(); startOfToday.setHours(0, 0, 0, 0);
  const today = sessions.filter((w) => w.startTime >= startOfToday.getTime());
  const todayMiles = today.reduce((sum, w) => sum + w.distanceMiles, 0);
  const todaySeconds = today.reduce((sum, w) => sum + w.durationSeconds, 0);
  return `
    <div class="card" style="padding:18px;margin-top:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
        <div style="font-weight:700;color:var(--navy);font-size:14.5px;">Walking</div>
        <button class="link-btn" data-nav="walking">Open Walking</button>
      </div>
      ${today.length
        ? `<div style="display:flex;gap:24px;">
             <div><div class="stat-label">Today's walking</div><div class="stat-value">${todayMiles.toFixed(2)} mi</div></div>
             <div><div class="stat-label">Time walking</div><div class="stat-value">${fmtDuration(todaySeconds)}</div></div>
           </div>`
        : `<div style="font-size:13px;color:var(--text-muted);">No walking sessions recorded today. Start one from the Walking screen.</div>`}
    </div>`;
}

function upcomingDashboardCard() {
  const events = state.upcomingEvents || [];
  const today = events.filter((e) => e.daysRemaining === 0);
  const birthdays = events.filter((e) => e.eventType === 'birthday').slice(0, 3);
  const expiring = events.filter((e) => e.eventType === 'expiry' && e.daysRemaining <= 30).slice(0, 3);
  const upcoming = events.filter((e) => e.daysRemaining > 0).slice(0, 4);
  if (events.length === 0) return '';
  return `
    <div class="card" style="padding:18px;margin-top:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
        <div style="font-weight:700;color:var(--navy);font-size:14.5px;">Calendar</div>
        <button class="link-btn" data-nav="calendar">Open Calendar</button>
      </div>
      ${today.length ? `<div class="dash-cal-section"><div class="dash-cal-label">Today</div>${today.map(dashEventLine).join('')}</div>` : ''}
      ${upcoming.length ? `<div class="dash-cal-section"><div class="dash-cal-label">Upcoming</div>${upcoming.map(dashEventLine).join('')}</div>` : ''}
      ${birthdays.length ? `<div class="dash-cal-section"><div class="dash-cal-label">Birthdays</div>${birthdays.map(dashEventLine).join('')}</div>` : ''}
      ${expiring.length ? `<div class="dash-cal-section"><div class="dash-cal-label">Expiring Soon</div>${expiring.map(dashEventLine).join('')}</div>` : ''}
    </div>`;
}

function dashEventLine(ev) {
  const meta = EVENT_TYPE_META[ev.eventType] || EVENT_TYPE_META.general;
  const when = ev.daysRemaining === 0 ? 'Today' : ev.daysRemaining === 1 ? 'Tomorrow' : `${ev.daysRemaining} days remaining`;
  return `<div class="dash-cal-item" data-event-id="${ev.id}">${icon(meta.icon, 14)}<span>${esc(ev.title)}</span><span class="dash-cal-when">${when}</span></div>`;
}

function isMac() {
  return /Mac|iPod|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');
}

function autoLockLabel(ms) {
  return { 0: 'Never', 30000: '30 seconds', 60000: '1 minute', 300000: '5 minutes', 900000: '15 minutes' }[ms] || `${ms / 1000}s`;
}

// ---------------------------------------------------------------------------
// Global Search — a command-palette style overlay reachable from any screen
// (topbar icon or Ctrl/Cmd+K), not just the dashboard. Fixes several real
// bugs the old dashboard-embedded search box had: it only worked on one
// screen, its category filter was missing every new item type added since,
// it left stale results behind when you navigated away and back, it never
// showed a loading state, and it interpolated the raw search query into
// HTML unescaped.
// ---------------------------------------------------------------------------
const SEARCH_CATS = ['all', ...Object.keys(TYPE_ICON_NAME)];

function searchOverlay() {
  const q = state.searchQuery;
  const hasQuery = q.trim().length > 0;
  return `
    <div class="search-scrim" id="search-scrim">
      <div class="search-panel" role="dialog" aria-label="Search your vault">
        <div class="search-input-row">
          <span class="icon">${ICON.search}</span>
          <input id="search-input" placeholder="Search your vault…" value="${esc(q)}" autocomplete="off" spellcheck="false" />
          ${hasQuery ? `<button class="icon-btn" id="search-clear" title="Clear">${icon('x', 15)}</button>` : ''}
          <button class="icon-btn search-close-btn" id="search-close" title="Close">${icon('x', 16)}</button>
        </div>
        ${hasQuery ? `<div class="search-cat-row">${SEARCH_CATS.map((c) => `<button class="chip ${state.searchCategory === c ? 'active' : ''}" data-search-cat="${c}">${c === 'all' ? 'All' : labelForType(c)}</button>`).join('')}</div>` : ''}
        <div class="search-results">${searchBody()}</div>
      </div>
    </div>`;
}

function searchBody() {
  const q = state.searchQuery.trim();
  if (!q) {
    if (state.recentSearches.length === 0) {
      return `<div class="search-empty">
        <div class="empty-icon">${ICON.search}</div>
        <div>Search across every category in your vault — passwords, notes, API keys, documents, and more.</div>
      </div>`;
    }
    return `
      <div class="search-recent-head">
        <span>Recent Searches</span>
        <button class="link-btn" id="search-clear-history">Clear</button>
      </div>
      ${state.recentSearches.map((term) => `<button class="search-recent-item" data-recent="${esc(term)}">${ICON.activity}<span>${esc(term)}</span></button>`).join('')}`;
  }
  if (state.searchLoading) {
    return `<div class="search-empty"><div class="search-spinner"></div><div>Searching…</div></div>`;
  }
  const results = state.searchResults || [];
  const events = state.searchEventResults || [];
  if (results.length === 0 && events.length === 0) {
    return `<div class="search-empty"><div class="empty-icon">${ICON.search}</div><div>No matches for "${esc(q)}" in your vault.</div></div>`;
  }
  const total = results.length + events.length;
  return `
    <div class="search-result-count">${total} result${total === 1 ? '' : 's'}</div>
    ${results.map((r) => `
      <button class="search-result-row" data-open-item="${r.id}">
        <div class="item-badge">${icon(TYPE_ICON_NAME[r.type] || 'note', 18)}</div>
        <div class="item-main">
          <div class="item-title">${esc(r.title)}</div>
          <div class="item-sub">${searchMatchSubtitle(r)}</div>
        </div>
        ${icon('chevronRight', 15)}
      </button>`).join('')}
    ${events.map((e) => `
      <button class="search-result-row" data-event-id="${e.id}">
        <div class="item-badge">${icon((EVENT_TYPE_META[e.eventType] || EVENT_TYPE_META.general).icon, 18)}</div>
        <div class="item-main">
          <div class="item-title">${esc(e.title)}</div>
          <div class="item-sub">Calendar · ${new Date(e.startDate).toLocaleDateString(undefined, { month: 'long', day: 'numeric' })}</div>
        </div>
        ${icon('chevronRight', 15)}
      </button>`).join('')}`;
}

/** Explains WHY a result matched (spec section 11) — never the raw value of a sensitive field. */
function searchMatchSubtitle(r) {
  const category = labelForType(r.type);
  if (r.matchedIn === 'heading') return category;
  if (r.matchedIn === 'field' && r.matchedField === 'Username/Email') return `${category} · ${esc(r.matchedExcerpt)}`;
  if (r.matchedIn === 'category') return `${category} · Category: ${esc(r.matchedExcerpt)}`;
  if (r.matchedIn === 'field-name') return `${category} · Matched field: ${esc(r.matchedField)}${r.matchedSensitive ? '' : r.matchedExcerpt ? `: ${esc(r.matchedExcerpt)}` : ''}`;
  if (r.matchedIn === 'field-value') return `${category} · Matched: ${esc(r.matchedField)}${r.matchedSensitive ? ': ••••••••' : `: ${esc(r.matchedExcerpt)}`}`;
  return category;
}

function openSearch() {
  state.searchOpen = true;
  render();
  setTimeout(() => document.getElementById('search-input')?.focus(), 20);
}

function closeSearch() {
  state.searchOpen = false;
  state.searchResults = null;
  state.searchEventResults = null;
  state.searchQuery = '';
  state.searchCategory = 'all';
  render();
}

const RECENT_SEARCHES_KEY = () => `vx_recent_searches_${state.user?.id || 'anon'}`;
function loadRecentSearches() {
  try { state.recentSearches = JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY()) || '[]'); }
  catch { state.recentSearches = []; }
}
function saveRecentSearch(term) {
  const trimmed = term.trim();
  if (!trimmed) return;
  state.recentSearches = [trimmed, ...state.recentSearches.filter((t) => t.toLowerCase() !== trimmed.toLowerCase())].slice(0, 6);
  try { localStorage.setItem(RECENT_SEARCHES_KEY(), JSON.stringify(state.recentSearches)); } catch { /* storage unavailable — non-fatal */ }
}
function clearRecentSearches() {
  state.recentSearches = [];
  try { localStorage.removeItem(RECENT_SEARCHES_KEY()); } catch { /* non-fatal */ }
}

function bindSearchEvents() {
  const scrim = document.getElementById('search-scrim');
  if (scrim) scrim.onclick = (e) => { if (e.target === scrim) closeSearch(); };
  const closeBtn = document.getElementById('search-close');
  if (closeBtn) closeBtn.onclick = closeSearch;
  const clearBtn = document.getElementById('search-clear');
  if (clearBtn) clearBtn.onclick = () => { state.searchQuery = ''; state.searchResults = null; renderPreservingSearchFocus(); };

  const input = document.getElementById('search-input');
  if (input) {
    let t;
    input.oninput = () => {
      clearTimeout(t);
      state.searchQuery = input.value;
      t = setTimeout(runSearch, 250);
    };
    input.onkeydown = (e) => {
      if (e.key === 'Enter') { clearTimeout(t); runSearch(); }
      if (e.key === 'Escape') { closeSearch(); }
    };
  }

  root.querySelectorAll('[data-search-cat]').forEach((btn) => {
    btn.onclick = () => { state.searchCategory = btn.dataset.searchCat; runSearch(); };
  });
  root.querySelectorAll('[data-recent]').forEach((btn) => {
    btn.onclick = () => { state.searchQuery = btn.dataset.recent; runSearch(); };
  });
  const clearHistoryBtn = document.getElementById('search-clear-history');
  if (clearHistoryBtn) clearHistoryBtn.onclick = () => { clearRecentSearches(); render(); };

  bindSearchResultEvents();
}

function bindSearchResultEvents() {
  // Scoped to the search panel only — the overlay sits on top of whatever
  // screen is underneath, and that screen may have its own [data-open-item]
  // elements (e.g. Documents) with their own handlers that must not be
  // overwritten by this one.
  const panel = document.querySelector('.search-panel');
  if (!panel) return;
  panel.querySelectorAll('[data-open-item]').forEach((el) => {
    el.onclick = async () => {
      try {
        const res = await api('GET', `/api/vault/items/${el.dataset.openItem}`);
        closeSearch();
        state.modal = { type: 'item-detail', item: res.item };
        render();
      } catch (err) { toast(err.message, 'error'); }
    };
  });
  panel.querySelectorAll('[data-event-id]').forEach((el) => {
    el.onclick = async () => {
      try {
        const res = await api('GET', `/api/events/${el.dataset.eventId}`);
        closeSearch();
        state.modal = { type: 'edit-event', event: res.event };
        render();
      } catch (err) { toast(err.message, 'error'); }
    };
  });
}

function labelForType(t) {
  return {
    password: 'Password', email: 'Email', personal: 'Personal', note: 'Secure Note', id: 'ID Document',
    wifi: 'Wi-Fi', contact: 'Contact', account: 'Account', apikey: 'API Key', sshkey: 'SSH Key',
    wallet: 'Crypto Wallet', physical: 'Access Code', license: 'Software License',
    medical: 'Medical Profile', inheritance: 'Digital Inheritance', document: 'Document', custom: 'Custom Item',
  }[t] || t;
}

// ---------------------------------------------------------------------------
// Passwords / Emails
// ---------------------------------------------------------------------------
function passwordsScreen() {
  const items = state.duress ? DECOY.passwordItems : state.passwordItems;
  return `
    <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;">
      <div class="search-bar"><span class="icon">${ICON.search}</span><input id="pw-filter" placeholder="Search passwords..." /></div>
      ${state.duress ? '' : `<button class="btn btn-primary" id="open-add-password">${ICON.plus} Add Password</button>`}
    </div>
    <div id="pw-list">${passwordListHtml(items)}</div>`;
}

function passwordListHtml(items) {
  if (items.length === 0) return `<div class="empty-state"><div class="empty-icon">${ICON.password}</div><div>No passwords saved yet.</div>${state.duress ? '' : `<button class="btn btn-primary" id="open-add-password-2">${ICON.plus} Add Password</button>`}</div>`;
  return items.map((item) => `
    <div class="card item-row">
      <div class="item-badge">${item.title.slice(0,1).toUpperCase()}</div>
      <div class="item-main">
        <div class="item-title">${item.title}</div>
        <div class="item-sub">${item.searchUsername || ''}</div>
        <div class="item-secret">${state.revealCache[item.id] ? state.revealCache[item.id].password : '••••••••••••'}</div>
      </div>
      <div class="item-actions">
        <button class="icon-btn" data-reveal="${item.id}" title="Reveal">${state.revealCache[item.id] ? ICON.eyeOff : ICON.eye}</button>
        <button class="icon-btn" data-copy="${item.id}" title="Copy">${ICON.copy}</button>
        ${state.duress ? '' : `<button class="icon-btn" data-edit-password="${item.id}" title="Edit">${ICON.edit}</button>
        <button class="icon-btn" data-delete-item="${item.id}" data-delete-title="${item.title}" title="Delete">${ICON.trash}</button>`}
      </div>
    </div>`).join('');
}

function emailsScreen() {
  const emails = state.passwordItems.filter((i) => i.category === 'Email');
  if (emails.length === 0) return `<div class="empty-state"><div class="empty-icon">${ICON.email}</div><div>No email accounts saved yet.</div></div>`;
  return emails.map((e) => `<div class="card item-row"><div class="item-badge">${ICON.email}</div><div class="item-main"><div class="item-title">${e.title}</div><div class="item-sub">${e.searchUsername || ''}</div></div></div>`).join('');
}

// ---------------------------------------------------------------------------
// Personal Info
// ---------------------------------------------------------------------------
const PERSONAL_FIELDS = [
  ['fullName', 'Full Name'], ['dob', 'Date of Birth'], ['phone', 'Phone Number'], ['email', 'Email'],
  ['address', 'Address'], ['occupation', 'Occupation'], ['emergencyContact', 'Emergency Contact'],
];
function personalScreen() {
  const p = state.personalItem?.payload || {};
  return `
    <div class="card" style="padding:20px;max-width:560px;">
      <form id="personal-form">
        ${PERSONAL_FIELDS.map(([key, label]) => `<div class="field"><label>${label}</label><input name="${key}" value="${(p[key] || '').replace(/"/g,'&quot;')}" /></div>`).join('')}
        <div class="field"><label>Other Notes</label><textarea name="notes" rows="3">${p.notes || ''}</textarea></div>
        <button class="btn btn-primary" type="submit">Save Changes</button>
      </form>
    </div>`;
}

// ---------------------------------------------------------------------------
// Secure Notes
// ---------------------------------------------------------------------------
function notesScreen() {
  const items = state.duress ? DECOY.noteItems : state.noteItems;
  if (items.length === 0) return `<div class="empty-state"><div class="empty-icon">${ICON.note}</div><div>No secure notes yet.</div>${state.duress ? '' : `<button class="btn btn-primary" id="open-add-note">${ICON.plus} New Secure Note</button>`}</div>`;
  return `
    <div style="display:flex;justify-content:flex-end;margin-bottom:16px;">${state.duress ? '' : `<button class="btn btn-primary" id="open-add-note">${ICON.plus} New Secure Note</button>`}</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px;">
      ${items.map((n) => {
        const revealed = !!state.revealCache[n.id];
        const content = revealed ? state.revealCache[n.id].content : (n.payload?.content || '');
        return `
        <div class="card" style="padding:16px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:8px;"><div style="font-weight:700;font-size:14px;color:var(--navy);">${n.title}</div>${ICON.note}</div>
          <div class="blur-until-open ${revealed ? 'revealed' : ''}" style="font-size:12.5px;color:var(--text-muted);white-space:pre-wrap;margin-bottom:12px;min-height:20px;">${content || '—'}</div>
          <div style="display:flex;gap:8px;">
            <button class="link-btn" data-reveal-note="${n.id}">${revealed ? 'Hide' : 'Reveal'}</button>
            ${state.duress ? '' : `<button class="link-btn" data-edit-note="${n.id}" style="color:var(--text-muted);">Edit</button>
            <button class="link-btn" data-delete-item="${n.id}" data-delete-title="${n.title}" style="color:var(--danger);">Delete</button>`}
          </div>
        </div>`;
      }).join('')}
    </div>`;
}

// ---------------------------------------------------------------------------
// Developer & Crypto / Documents / Physical & Licenses / Medical & Estate
// — four tabbed screens sharing one generic-item-row renderer.
// ---------------------------------------------------------------------------
function genericItemRow(item, opts = {}) {
  const revealed = !!state.revealCache[item.id];
  const fields = FIELD_CONFIGS[item.type] || [];
  const secretField = fields.find((f) => f[2]);
  const subtitle = item.searchUsername || '';
  return `
    <div class="card item-row">
      <div class="item-badge">${icon(TYPE_ICON_NAME[item.type] || 'note', 18)}</div>
      <div class="item-main">
        <div class="item-title">${item.title}</div>
        ${subtitle ? `<div class="item-sub">${subtitle}</div>` : ''}
        ${secretField ? `<div class="item-secret">${revealed ? String(state.revealCache[item.id][secretField[0]] || '') : '••••••••••••'}</div>` : ''}
      </div>
      <div class="item-actions">
        ${secretField ? `<button class="icon-btn" data-generic-reveal="${item.id}" title="Reveal">${revealed ? ICON.eyeOff : ICON.eye}</button>` : `<button class="icon-btn" data-open-item="${item.id}" title="View">${ICON.eye}</button>`}
        <button class="icon-btn" data-generic-edit="${item.id}" data-generic-type="${item.type}" title="Edit">${ICON.edit}</button>
        <button class="icon-btn" data-delete-item="${item.id}" data-delete-title="${item.title}" title="Delete">${ICON.trash}</button>
      </div>
    </div>`;
}

function tabbedTypeScreen({ tabs, activeTab, itemsByType, emptyIcon }) {
  const items = itemsByType[activeTab] || [];
  return `
    <div class="tab-row">${tabs.map(([key, label]) => `<button class="tab-btn ${activeTab === key ? 'active' : ''}" data-type-tab="${key}">${label}</button>`).join('')}</div>
    <div style="display:flex;justify-content:flex-end;margin-bottom:14px;">
      <button class="btn btn-primary" data-add-type="${activeTab}">${ICON.plus} Add ${labelForType(activeTab)}</button>
    </div>
    ${items.length === 0
      ? `<div class="empty-state"><div class="empty-icon">${icon(emptyIcon || 'note', 22)}</div><div>No ${labelForType(activeTab).toLowerCase()} entries yet.</div></div>`
      : items.map((item) => genericItemRow(item)).join('')}`;
}

function developerScreen() {
  return tabbedTypeScreen({
    tabs: [['apikey', 'API Keys'], ['sshkey', 'SSH Keys'], ['wallet', 'Crypto Wallets']],
    activeTab: state.developerTab,
    itemsByType: state.developerItems,
    emptyIcon: 'key',
  });
}

function physicalScreen() {
  return tabbedTypeScreen({
    tabs: [['physical', 'Access Codes'], ['license', 'Software Licenses']],
    activeTab: state.physicalTab,
    itemsByType: state.physicalItems,
    emptyIcon: 'lock',
  });
}

function medicalScreen() {
  return tabbedTypeScreen({
    tabs: [['medical', 'Medical Profile'], ['inheritance', 'Digital Inheritance']],
    activeTab: state.medicalTab || 'medical',
    itemsByType: state.medicalItems,
    emptyIcon: 'activity',
  });
}

function documentsScreen() {
  if (state.documentItems.length === 0) {
    return `<div class="empty-state"><div class="empty-icon">${ICON.id}</div><div>No documents saved yet.</div><button class="btn btn-primary" id="open-add-document">${ICON.plus} Add Document</button></div>`;
  }
  return `
    <div style="display:flex;justify-content:flex-end;margin-bottom:16px;"><button class="btn btn-primary" id="open-add-document">${ICON.plus} Add Document</button></div>
    ${state.documentItems.map((item) => `
      <div class="card item-row" data-open-item="${item.id}" style="cursor:pointer;">
        <div class="item-badge">${ICON.id}</div>
        <div class="item-main">
          <div class="item-title">${item.title}</div>
          <div class="item-sub">${item.searchUsername || ''}</div>
        </div>
      </div>`).join('')}`;
}

function customItemsScreen() {
  if (state.customItems.length === 0) {
    return `<div class="empty-state"><div class="empty-icon">${icon('idcard', 22)}</div><div>No custom items yet. Give any information its own heading and fields — memberships, references, whatever doesn't fit elsewhere.</div><button class="btn btn-primary" id="open-add-custom">${ICON.plus} New Custom Item</button></div>`;
  }
  return `
    <div style="display:flex;justify-content:flex-end;margin-bottom:16px;"><button class="btn btn-primary" id="open-add-custom">${ICON.plus} New Custom Item</button></div>
    ${state.customItems.map((item) => `
      <div class="card item-row" data-open-item="${item.id}" style="cursor:pointer;">
        <div class="item-badge">${icon('idcard', 18)}</div>
        <div class="item-main">
          <div class="item-title">${esc(item.title)}</div>
          <div class="item-sub">Updated ${timeAgo(item.updatedAt)}</div>
        </div>
      </div>`).join('')}`;
}


// ---------------------------------------------------------------------------
// Walking (GPS) -- spec section 19. The only "activity" feature a web browser
// can genuinely provide: a user-started session using the real Geolocation
// API. There are NO step counts here -- the browser has no access to a
// pedometer or HealthKit/Health Connect. The UI says so plainly.
// ---------------------------------------------------------------------------
const WALK_SAMPLE_MIN_INTERVAL_MS = 5000; // at most one point every 5s -- battery-conscious (spec section 59)
const WALK_MAX_POINTS = 2000;             // hard cap so a forgotten session can't grow unbounded

function goalPanelHtml() {
  const g = state.goalProgress;
  if (!g || !g.goal) {
    return `
    <div class="card" style="padding:18px;margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">
        <div><div style="font-weight:700;color:var(--navy);font-size:14.5px;">Daily goal</div>
        <div class="field-hint">No goal set. Goals are your own targets, and you can change or remove them any time.</div></div>
        <button class="btn btn-outline btn-sm" id="goal-edit">Set a goal</button>
      </div>
    </div>`;
  }
  const rows = [];
  if (g.goal.dailyDistanceMiles) rows.push(`<div style="font-size:13px;">Distance: <b>${g.today.miles.toFixed(2)}</b> of ${g.goal.dailyDistanceMiles} mi (${g.distancePct}%)</div>`);
  if (g.goal.dailyWalkMinutes) rows.push(`<div style="font-size:13px;">Walking time: <b>${g.today.minutes}</b> of ${g.goal.dailyWalkMinutes} min (${g.timePct}%)</div>`);
  return `
    <div class="card" style="padding:18px;margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px;">
        <div style="font-weight:700;color:var(--navy);font-size:14.5px;">Daily goal ${g.goalMet ? '<span style="color:var(--success);font-size:12px;">· reached</span>' : ''}</div>
        <button class="link-btn" id="goal-edit">Edit</button>
      </div>
      ${rows.join('')}
      <div class="field-hint" style="margin-top:8px;">Based only on walks you recorded today.</div>
    </div>`;
}

function goalEditModal() {
  const g = state.goalProgress?.goal;
  return modalShell('Daily goal', `
    <form id="goal-form">
      <div class="field"><label>Distance (miles, optional)</label><input name="dailyDistanceMiles" type="number" step="0.1" min="0" max="100" value="${g?.dailyDistanceMiles ?? ''}" placeholder="e.g. 2" /></div>
      <div class="field"><label>Walking time (minutes, optional)</label><input name="dailyWalkMinutes" type="number" step="1" min="0" max="600" value="${g?.dailyWalkMinutes ?? ''}" placeholder="e.g. 30" /></div>
      <div class="field-hint" style="margin-bottom:12px;">Leave both blank to remove the goal. These are personal targets, not recommendations.</div>
      <button class="btn btn-primary btn-block" type="submit">Save goal</button>
    </form>`);
}

function walkingScreen() {
  const srv = state.walkingServer;
  const hist = state.walkingHistory || [];
  const geoSupported = 'geolocation' in navigator;
  const tracking = isWalkTracking();
  return `
    ${goalPanelHtml()}
    <div class="card" style="padding:20px;margin-bottom:16px;">
      <div style="font-weight:700;color:var(--navy);font-size:15px;margin-bottom:6px;">Walk</div>
      <div class="field-hint" style="margin-bottom:14px;">
        Your walk keeps going if you close or minimize the app. Movement is recorded only while the app is open or running in the background on this device. If the app is fully closed, the session clock keeps running, but movement isn't recorded until you open the app again.
      </div>
      ${!geoSupported ? `<div class="warn-banner">This browser doesn't support location, so walks can't record movement here.</div>` : ''}
      ${srv ? `
        <div class="rec-tip ${tracking ? 'success' : 'warn'}" style="margin-bottom:12px;">
          ${tracking ? 'Recording movement.' : 'A walk is running, but movement isn\'t being recorded right now. Tap Resume tracking to continue.'}
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;">
          <div><div class="stat-label">Session time</div><div class="stat-value" id="walk-session-time">${fmtDuration(walkLiveSeconds())}</div></div>
          <div><div class="stat-label">Walking time</div><div class="stat-value" id="walk-moving-time">${fmtDuration(srv.movingSeconds)}</div></div>
          <div><div class="stat-label">Distance</div><div class="stat-value" id="walk-distance">${srv.distanceMiles.toFixed(2)} mi</div></div>
          <div><div class="stat-label">Now</div><div class="stat-value" id="walk-status" style="font-size:16px;">${srv.status === 'moving' ? 'Moving' : 'Standing still'}</div></div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          ${tracking ? '' : `<button class="btn btn-outline" id="walk-resume" style="flex:1;" ${geoSupported ? '' : 'disabled'}>Resume tracking</button>`}
          <button class="btn btn-danger" id="walk-stop" style="flex:1;">Finish walk</button>
        </div>
      ` : `
        <button class="btn btn-primary btn-block" id="walk-start" ${geoSupported ? '' : 'disabled'}>${icon('activity', 15)} Start walk</button>
      `}
    </div>
    <div style="font-weight:700;color:var(--navy);font-size:14px;margin:6px 0 10px;">History</div>
    ${hist.length === 0 ? `<div class="empty-state"><div class="empty-icon">${icon('activity', 22)}</div><div>No walks recorded yet.</div></div>`
      : hist.map((w) => `
        <div class="card item-row">
          <div class="item-badge">${icon('activity', 18)}</div>
          <div class="item-main">
            <div class="item-title">${w.distanceMiles.toFixed(2)} mi walked</div>
            <div class="item-sub">${new Date(w.startTime).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })} · walking ${fmtDuration(w.durationSeconds)}${w.sessionSeconds ? ` of ${fmtDuration(w.sessionSeconds)} session` : ''}</div>
          </div>
          <button class="icon-btn" data-walk-delete="${w.id}" title="Delete walk">${ICON.trash}</button>
        </div>`).join('')}
    <div class="field-hint" style="margin-top:14px;">Step counts and daily sensor totals aren't available in a web browser. They need the native iPhone or Android app, which reads the phone's own health data.</div>`;
}

function fmtDuration(sec) {
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = Math.floor(sec % 60);
  return h ? `${h}h ${m}m` : `${m}:${String(s).padStart(2, '0')}`;
}

function haversineMiles(lat1, lng1, lat2, lng2) {
  const R = 3958.8, toRad = (d) => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1), dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

const WALK_FLUSH_MS = 15000;   // send collected samples to the server every 15 seconds
const WALK_MAX_BUFFER = 500;   // keep at most this many unsent samples; the oldest are dropped first

function setWalkServer(view) {
  if (!view) { state.walkingServer = null; return; }
  state.walkingServer = { ...view, fetchedAt: Date.now() };
}
function walkLiveSeconds() {
  const srv = state.walkingServer;
  if (!srv) return 0;
  return srv.elapsedSeconds + (Date.now() - srv.fetchedAt) / 1000;
}
function isWalkTracking() {
  return !!(state.walkingSession && state.walkingSession.watchId !== null);
}

function updateWalkLive() {
  const srv = state.walkingServer;
  if (!srv) return;
  const set = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
  set('walk-session-time', fmtDuration(walkLiveSeconds()));
  set('walk-moving-time', fmtDuration(srv.movingSeconds));
  set('walk-distance', `${srv.distanceMiles.toFixed(2)} mi`);
  set('walk-status', srv.status === 'moving' ? 'Moving' : 'Standing still');
}

let walkWakeLock = null;
async function requestWakeLock() {
  try { if ('wakeLock' in navigator) walkWakeLock = await navigator.wakeLock.request('screen'); } catch { /* not supported or refused: fine */ }
}
function releaseWakeLock() {
  try { walkWakeLock?.release(); } catch { /* already released */ }
  walkWakeLock = null;
}

// Starts recording location on this device. The walk itself is already on the
// server; this only collects samples and sends them.
function beginTracking() {
  if (isWalkTracking() || !('geolocation' in navigator)) return;
  const sess = { buffer: [], lastSampleAt: 0, watchId: null, flushTimer: null, flushing: false };
  state.walkingSession = sess;
  sess.watchId = navigator.geolocation.watchPosition(
    (pos) => {
      const now = Date.now();
      if (now - sess.lastSampleAt < WALK_SAMPLE_MIN_INTERVAL_MS) return;
      sess.lastSampleAt = now;
      if (sess.buffer.length >= WALK_MAX_BUFFER) sess.buffer.shift();
      sess.buffer.push([pos.coords.latitude, pos.coords.longitude, now]);
    },
    (err) => {
      if (err.code === 1) {
        toast('Location permission is off. Allow it in your browser settings to record movement.', 'error');
        endTrackingOnly();
        render();
      }
    },
    { enableHighAccuracy: true, maximumAge: 2000, timeout: 20000 }
  );
  sess.flushTimer = setInterval(flushWalk, WALK_FLUSH_MS);
  requestWakeLock();
}

function endTrackingOnly() {
  const sess = state.walkingSession;
  if (sess) {
    if (sess.watchId !== null) navigator.geolocation.clearWatch(sess.watchId);
    clearInterval(sess.flushTimer);
  }
  state.walkingSession = null;
  releaseWakeLock();
}

async function flushWalk() {
  const sess = state.walkingSession;
  if (!sess || sess.flushing || sess.buffer.length === 0) return;
  sess.flushing = true;
  const batch = sess.buffer.slice(0, 200);
  try {
    const res = await api('POST', '/api/activity/active/samples', { samples: batch });
    sess.buffer.splice(0, batch.length);
    setWalkServer(res.active);
    updateWalkLive();
  } catch (err) {
    if (err.status === 404 || err.status === 409) {
      // The server no longer has this walk (it was finished elsewhere or hit the 12-hour limit).
      endTrackingOnly();
      await loadWalking();
      render();
      toast('This walk was already saved on the server.', 'warn');
    } else if (err.status === 400) {
      // The server refused this batch as invalid. Drop it so it doesn't retry forever.
      sess.buffer.splice(0, batch.length);
    }
    // Any other error (for example, offline): keep the samples and retry on the next flush.
  } finally {
    sess.flushing = false;
  }
}

async function startWalkingSession() {
  if (!('geolocation' in navigator)) { toast('Location is not available on this device.', 'error'); return; }
  try {
    const res = await api('POST', '/api/activity/active/start', {});
    setWalkServer(res.active);
  } catch (err) {
    toast('Could not start the walk. Please try again.', 'error');
    return;
  }
  beginTracking();
  render();
}

async function stopWalkingSession() {
  const sess = state.walkingSession;
  if (sess) {
    while (sess.flushing) await new Promise((r) => setTimeout(r, 100));
    await flushWalk();
  }
  endTrackingOnly();
  try {
    const res = await api('POST', '/api/activity/active/stop', {});
    state.walkingServer = null;
    state.walkingHistory = [res.session, ...(state.walkingHistory || [])];
    toast('Walk saved to your history.');
  } catch (err) {
    toast('Could not finish the walk. Please try again.', 'error');
    await loadWalking();
  }
  render();
}

// Runs on every visit to the Walking screen. The server is the source of truth,
// so a walk started before the app was closed comes back here.
async function loadWalking() {
  const [res, goal, active] = await Promise.all([
    api('GET', '/api/activity/sessions'),
    api('GET', '/api/activity/goal'),
    api('GET', '/api/activity/active'),
  ]);
  state.walkingHistory = res.sessions;
  state.goalProgress = goal;
  if (active.active) {
    setWalkServer(active.active);
    beginTracking();
  } else {
    state.walkingServer = null;
    endTrackingOnly();
  }
}

// Keep the live readout ticking, and recover tracking when the app comes back.
setInterval(() => { if (state.screen === 'app' && state.active === 'walking') updateWalkLive(); }, 1000);
document.addEventListener('visibilitychange', () => {
  if (document.hidden) return;
  if (state.screen === 'app' && state.walkingServer && !isWalkTracking()) { beginTracking(); render(); }
  if (isWalkTracking()) requestWakeLock();
});

function bindWalkingEvents() {
  const goalEdit = document.getElementById('goal-edit');
  if (goalEdit) goalEdit.onclick = () => { state.modal = { type: 'goal-edit' }; render(); };
  const goalForm = document.getElementById('goal-form');
  if (goalForm) goalForm.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(goalForm);
    const val = (k) => { const v = fd.get(k); return v === '' ? null : Number(v); };
    try {
      state.goalProgress = await api('PUT', '/api/activity/goal', {
        dailyDistanceMiles: val('dailyDistanceMiles'), dailyWalkMinutes: val('dailyWalkMinutes'),
      });
      state.modal = null;
      toast('Goal saved.');
      render();
    } catch (err) { toast(err.message || 'Unable to save goal.', 'error'); }
  };
  const start = document.getElementById('walk-start');
  if (start) start.onclick = startWalkingSession;
  const resume = document.getElementById('walk-resume');
  if (resume) resume.onclick = () => { beginTracking(); render(); };
  const stop = document.getElementById('walk-stop');
  if (stop) stop.onclick = stopWalkingSession;
  root.querySelectorAll('[data-walk-delete]').forEach((btn) => {
    btn.onclick = async () => {
      try {
        await api('DELETE', `/api/activity/sessions/${btn.dataset.walkDelete}`);
        state.walkingHistory = state.walkingHistory.filter((w) => w.id !== btn.dataset.walkDelete);
        toast('Walk deleted.');
        render();
      } catch (err) { toast('Unable to delete this walk.', 'error'); }
    };
  });
}

function securityScreen() {
  const sec = state.security;
  if (!sec) return '';
  const pct = Math.round((sec.score.score / sec.score.max) * 100);
  const color = pct >= 80 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)';
  return `
    <div class="two-col">
      <div class="card" style="padding:20px;">
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:18px;">
          <div style="width:64px;height:64px;border-radius:50%;border:5px solid ${color};display:flex;align-items:center;justify-content:center;font-weight:800;font-size:16px;color:${color};flex-shrink:0;">${pct}%</div>
          <div>
            <div style="font-weight:700;font-size:15px;color:var(--navy);">Vault Status: <span style="color:var(--success);display:inline-flex;align-items:center;gap:6px;">${icon('check',14)} Protected</span></div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Score reflects real conditions — 2FA, biometrics, auto-lock timing, password reuse.</div>
          </div>
        </div>
        <div class="sec-row"><div class="sec-row-label">${icon('key',16)} Master Password</div><div class="sec-row-value" style="color:var(--success);">Strong</div></div>
        <div class="sec-row"><div class="sec-row-label">${icon('shield',16)} Two-Factor Authentication</div><div style="display:flex;align-items:center;gap:10px;"><div class="sec-row-value" style="color:${sec.twoFactorEnabled ? 'var(--success)' : 'var(--warning)'};">${sec.twoFactorEnabled ? 'ON' : 'OFF'}</div><button class="link-btn" id="toggle-2fa">${sec.twoFactorEnabled ? 'Disable' : 'Enable'}</button></div></div>
        <div class="sec-row"><div class="sec-row-label">${icon('fingerprint',16)} Biometric Unlock</div><div style="display:flex;align-items:center;gap:10px;"><div class="sec-row-value" style="color:${sec.biometricEnabled ? 'var(--success)' : 'var(--warning)'};">${sec.biometricEnabled ? 'ON' : 'OFF'}</div><button class="link-btn" data-nav="settings">Manage</button></div></div>
        <div class="sec-row"><div class="sec-row-label">${icon('clock',16)} Auto Lock</div><div class="sec-row-value">${autoLockLabel(sec.autoLockMs)}</div></div>
        <div class="sec-row"><div class="sec-row-label">${icon('contact',16)} Active Sessions</div><div class="sec-row-value">${state.sessions.length} Devices</div></div>
        <div class="sec-row" style="border-bottom:none;"><div class="sec-row-label">${icon('clock',16)} Last Login</div><div class="sec-row-value">${sec.lastLogin ? new Date(sec.lastLogin).toLocaleString() : '—'}</div></div>
        <div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap;">
          <button class="btn btn-dark" id="lock-vault-btn-2">${ICON.lock} Lock Vault</button>
          <button class="btn btn-danger" id="signout-all">Sign Out All Devices</button>
        </div>
      </div>
      <div class="card" style="padding:20px;">
        <div style="font-weight:700;color:var(--navy);font-size:14.5px;margin-bottom:10px;">Recommendations</div>
        ${sec.score.checks.filter((c) => !c.pass).map((c) => `<div class="rec-tip warn">${ICON.warn} Recommended: ${c.label[0].toLowerCase()}${c.label.slice(1)}.</div>`).join('') || `<div class="rec-tip success">${ICON.check} No outstanding recommendations.</div>`}
        <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
            <div style="font-weight:700;color:var(--navy);font-size:13.5px;">Vault Health Scan</div>
            <button class="link-btn" id="run-health-scan">${icon('refresh', 13)} ${state.health ? 'Re-scan' : 'Run scan'}</button>
          </div>
          ${healthScanBody()}
        </div>
        <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border);font-size:12px;color:var(--text-muted);line-height:1.9;">
          <b style="color:var(--navy);">How search stays secure:</b> results only ever match non-secret metadata (titles, categories, the username/email field) — encrypted contents like passwords and note bodies are never decrypted to build search results. See README "Search architecture".
        </div>
      </div>
    </div>`;
}

function healthScanBody() {
  const h = state.health;
  if (!h) return `<div style="font-size:12px;color:var(--text-muted);">Checks your saved passwords locally for reuse, weak entropy, age, and default-looking Wi-Fi keys — nothing leaves your vault.</div>`;
  if (h.itemsChecked === 0) return `<div style="font-size:12px;color:var(--text-muted);">No passwords or Wi-Fi credentials saved yet.</div>`;
  const rows = [
    ['Weak passwords', h.weakCount], ['Reused passwords', h.reusedCount],
    ['Passwords older than 6 months', h.oldCount], ['Default-looking Wi-Fi keys', h.defaultWifiCount],
  ];
  return `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;">
      ${rows.map(([label, n]) => `<div style="font-size:12px;color:${n > 0 ? 'var(--warning)' : 'var(--text-muted)'};">${label}: <b>${n}</b></div>`).join('')}
    </div>
    ${h.findings.length ? h.findings.map((f) => `<div class="rec-tip warn" style="margin-bottom:6px;">${ICON.warn} <b>${f.title}</b> — ${f.issues.join(', ')}</div>`).join('') : `<div class="rec-tip success">${ICON.check} No issues found across ${h.itemsChecked} checked item(s).</div>`}
  `;
}

// ---------------------------------------------------------------------------
// Activity Log
// ---------------------------------------------------------------------------
function activityScreen() {
  const groups = {};
  state.activity.forEach((a) => {
    const d = new Date(a.created_at);
    const today = new Date(); const yesterday = new Date(Date.now() - 86400000);
    let key = d.toDateString() === today.toDateString() ? 'Today' : d.toDateString() === yesterday.toDateString() ? 'Yesterday' : d.toLocaleDateString(undefined, { month: 'long', day: 'numeric' });
    (groups[key] = groups[key] || []).push(a);
  });
  const chainBanner = state.chainStatus
    ? state.chainStatus.valid
      ? `<div class="rec-tip success" style="margin-bottom:16px;">${ICON.check} Log integrity verified — ${state.chainStatus.checked} entries checked, hash chain intact.</div>`
      : `<div class="rec-tip warn" style="margin-bottom:16px;background:#FEF2F2;color:var(--danger);">${ICON.warn} Tampering detected — the hash chain breaks at entry ${state.chainStatus.brokenAt}.</div>`
    : '';
  return `
    <div style="display:flex;justify-content:flex-end;margin-bottom:12px;">
      <button class="link-btn" id="verify-chain-btn">${icon('shield', 13)} Verify log integrity</button>
    </div>
    ${chainBanner}
    ${Object.entries(groups).map(([day, items]) => `
    <div style="margin-bottom:20px;">
      <div style="font-weight:700;color:var(--navy);font-size:13.5px;margin-bottom:8px;">${day}</div>
      <div class="card" style="padding:4px 16px;">
        ${items.map((a, i) => `
          <div style="display:flex;align-items:center;gap:12px;padding:12px 0;${i < items.length - 1 ? 'border-bottom:1px solid var(--border);' : ''}">
            <div style="width:8px;height:8px;border-radius:50%;background:var(--success);flex-shrink:0;"></div>
            <span style="flex:1;font-size:13.5px;">${a.text}</span>
            <span style="font-size:12px;color:var(--text-muted);">${new Date(a.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          </div>`).join('')}
      </div>
    </div>`).join('') || `<div class="empty-state"><div class="empty-icon">${ICON.activity}</div><div>No activity yet.</div></div>`}`;
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
function settingsScreen() {
  const tab = state.settingsTab || 'security';
  const tabs = ['account', 'security', 'recovery', 'sessions', 'backup', 'about'];
  const sec = state.security || {};
  let body = '';
  if (tab === 'account') {
    body = `<div class="card" style="padding:20px;max-width:480px;">
      <div class="field" style="text-align:center;">
        <label>Profile Picture</label>
        <div class="avatar-picker" id="settings-avatar-preview">${state.avatarDataUrl ? `<img src="${state.avatarDataUrl}" alt="" />` : icon('user', 24)}</div>
        <input type="file" id="settings-avatar-input" accept="image/png,image/jpeg,image/webp" style="display:none;" />
        <div style="display:flex;gap:14px;justify-content:center;margin-top:8px;">
          <button type="button" class="link-btn" id="settings-avatar-pick">${icon('edit', 13)} Change</button>
          ${state.avatarDataUrl ? `<button type="button" class="link-btn" id="settings-avatar-remove" style="color:var(--danger);">Remove</button>` : ''}
        </div>
      </div>
      <form id="account-details-form">
        <div class="field"><label>Full Name</label><input name="name" required maxlength="80" value="${esc(state.user.name)}" /></div>
        <div class="field"><label>Login Email</label><input name="email" type="email" required maxlength="254" value="${esc(state.user.email)}" /></div>
        <div class="field"><label>Current Master Password</label><input name="currentPassword" type="password" required autocomplete="current-password" /></div>
        <div class="field-hint" style="margin-bottom:12px;">Your master password is required to change these, so a stolen session can't change how you sign in.</div>
        <div id="account-details-error"></div>
        <button class="btn btn-primary" type="submit">Save changes</button>
      </form>
    </div>`;
  } else if (tab === 'security') {
    body = `
      <div class="card" style="padding:20px;max-width:520px;">
        <div class="sec-row"><div class="sec-row-label">${icon('key',16)} Master Password</div><button class="link-btn" id="open-change-password">Change</button></div>
        <div class="sec-row"><div class="sec-row-label">${icon('idcard',16)} PIN</div><button class="link-btn" id="open-change-pin">${state.user.hasPin ? 'Change' : 'Set PIN'}</button></div>
        <div class="sec-row"><div class="sec-row-label">${icon('fingerprint',16)} Biometric Unlock</div><button class="toggle ${state.user.biometricEnabled ? 'on' : ''}" id="toggle-biometric"><span class="knob"></span></button></div>
        <div class="sec-row"><div class="sec-row-label">${icon('shield',16)} Two-Factor Authentication</div><button class="toggle ${sec.twoFactorEnabled ? 'on' : ''}" id="toggle-2fa-settings"><span class="knob"></span></button></div>
        <div class="sec-row"><div class="sec-row-label">${icon('warn',16)} Duress PIN</div><button class="link-btn" id="open-duress-pin">Set up</button></div>
        <div class="sec-row"><div class="sec-row-label">${icon('bell',16)} Reminder Notifications</div><button class="toggle ${notifPermission() === 'granted' ? 'on' : ''}" id="toggle-notifications"><span class="knob"></span></button></div>
        <div class="sec-row" style="flex-wrap:wrap;"><div class="sec-row-label">${icon('lock',16)} Notification privacy</div>
          <select id="notif-privacy" style="padding:6px 8px;border-radius:8px;border:1px solid var(--border);font-size:13px;">
            <option value="full" ${notifPrivacyLevel() === 'full' ? 'selected' : ''}>Show full details</option>
            <option value="limited" ${notifPrivacyLevel() === 'limited' ? 'selected' : ''}>Limited (timing only)</option>
            <option value="hide" ${notifPrivacyLevel() === 'hide' ? 'selected' : ''}>Hide details</option>
          </select>
        </div>
        <div style="padding:13px 0;">
          <div style="font-size:13.5px;font-weight:600;margin-bottom:8px;">Auto-Lock After</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            ${[[0,'Never'],[30000,'30 seconds'],[60000,'1 minute'],[300000,'5 minutes'],[900000,'15 minutes']].map(([ms,label]) => `<button class="tab-btn ${state.user.autoLockMs === ms ? 'active' : ''}" data-autolock="${ms}">${label}</button>`).join('')}
          </div>
        </div>
        <div class="field-hint" style="margin-top:8px;">A duress PIN unlocks a harmless decoy screen instead of your real vault — useful if you're ever pressured to unlock it. It's indistinguishable from a normal unlock to anyone watching.</div>
        <div class="field-hint">Reminder notifications only fire while this tab is open — closed-app delivery needs Web Push, noted as a next step in the README.</div>
      </div>`;
  } else if (tab === 'recovery') {
    body = `<div class="card" style="padding:20px;max-width:480px;margin-bottom:16px;">
      <div style="font-size:14px;font-weight:700;color:var(--navy);margin-bottom:4px;">Emergency contacts</div>
      <div class="field-hint" style="margin-bottom:12px;">Choose someone who can request access to your vault if something happens to you. You can cancel a request at any time before the waiting period ends.</div>
      <button class="btn btn-outline btn-block" id="open-emergency-invite" style="margin-bottom:12px;">${icon('plus', 14)} Add an emergency contact</button>
      <div id="emergency-list">${(state.emergency || []).map((c) => `
        <div class="sec-row" style="flex-wrap:wrap;">
          <div><div style="font-size:13.5px;font-weight:600;">${esc(c.contactName)}</div>
          <div class="field-hint">${esc(c.contactEmail)} · ${c.waitDays}-day wait · ${({invited:'Waiting for a request',requested:'Access requested, waiting period running',released:'Access released',revoked:'Removed'})[c.status] || c.status}</div></div>
          <div style="display:flex;gap:8px;">
            ${c.status === 'requested' ? `<button class="link-btn" data-em-veto="${c.id}">Cancel request</button>` : ''}
            ${c.status !== 'revoked' ? `<button class="link-btn" style="color:var(--danger);" data-em-revoke="${c.id}">Remove</button>` : ''}
          </div>
        </div>`).join('') || '<div class="field-hint">No emergency contacts yet.</div>'}</div>
    </div>`;
    body += `<div class="card" style="padding:20px;max-width:480px;">
      <div style="font-size:13.5px;font-weight:600;margin-bottom:4px;">Recovery Email</div>
      <div style="font-size:13.5px;color:var(--text-muted);margin-bottom:16px;">${esc(state.user.email)}</div>
      <div style="font-size:13.5px;font-weight:600;margin-bottom:4px;">Recovery Key</div>
      <div class="field-hint" style="margin-bottom:12px;">Your recovery key lets you get back into your vault if you forget your master password. Creating a new key makes the old one stop working.</div>
      <form id="regen-recovery-form">
        <div class="field"><label>Current Master Password</label><input name="currentPassword" type="password" required autocomplete="current-password" /></div>
        <div id="regen-recovery-error"></div>
        <button class="btn btn-outline btn-block" type="submit">Create a new recovery key</button>
      </form>
    </div>`;
  } else if (tab === 'sessions') {
    body = `<div class="card" style="padding:20px;max-width:520px;">
      ${state.sessions.map((s) => `
        <div class="sec-row">
          <div class="sec-row-label">${icon('contact',16)} ${s.device || 'Unknown device'} ${s.current ? '<span style="color:var(--success);font-size:11px;">· This device</span>' : ''}</div>
          ${!s.current ? `<button class="link-btn" style="color:var(--danger);" data-revoke-session="${s.id}">Revoke</button>` : ''}
        </div>`).join('')}
      <button class="btn btn-danger" style="margin-top:14px;" id="signout-all-2">Sign Out All Other Devices</button>
    </div>`;
  } else if (tab === 'backup') {
    body = `<div class="card" style="padding:20px;max-width:480px;">
      <div style="font-weight:700;color:var(--navy);font-size:14px;margin-bottom:6px;">Export Encrypted Backup</div>
      <div class="field-hint" style="margin-bottom:12px;">Downloads every item in your vault as a single AES-256-GCM encrypted file, protected by a password you choose here — separate from your master password.</div>
      <button class="btn btn-outline btn-block" id="open-export-backup" style="margin-bottom:20px;">${icon('copy', 15)} Export Backup (.vaultx)</button>
      <div style="border-top:1px solid var(--border);padding-top:16px;">
        <div style="font-weight:700;color:var(--navy);font-size:14px;margin-bottom:6px;">Import Backup</div>
        <div class="field-hint" style="margin-bottom:12px;">Items are added alongside what's already in your vault — nothing is overwritten.</div>
        <button class="btn btn-outline btn-block" id="open-import-backup">${icon('plus', 15)} Import Backup (.vaultx)</button>
      </div>
    </div>`;
  } else if (tab === 'about') {
    body = `<div class="card" style="padding:20px;max-width:480px;">
      <div style="font-weight:800;color:var(--navy);margin-bottom:6px;">${APP_NAME}</div>
      <div style="font-size:13px;color:var(--text-muted);line-height:1.7;margin-bottom:16px;">A secure personal information vault: password manager, encrypted notes, universal search, and a Security Centre — backed by a real Node.js API, SQLite database, scrypt-hashed authentication, and AES-256-GCM encrypted storage.</div>
      ${installSectionHtml()}
      <div style="border-top:1px solid var(--border);padding-top:14px;margin-top:16px;">
        <button class="link-btn" id="logout-btn" style="display:block;margin-bottom:12px;color:var(--text);">Sign Out</button>
        <button class="link-btn" id="open-delete-account" style="color:var(--danger);font-weight:700;">Delete Account</button>
      </div>
    </div>`;
  }
  return `<div class="tab-row">${tabs.map((t) => `<button class="tab-btn ${tab === t ? 'active' : ''}" data-settings-tab="${t}">${t[0].toUpperCase()}${t.slice(1)}</button>`).join('')}</div>${body}`;
}

function installSectionHtml() {
  if (isStandalone()) {
    return `<div class="rec-tip success" style="margin-bottom:0;">${ICON.check} Already installed — you're running the installed app.</div>`;
  }
  if (deferredInstallPrompt) {
    return `
      <div style="border-top:1px solid var(--border);padding-top:16px;">
        <div style="font-weight:700;color:var(--navy);font-size:14px;margin-bottom:6px;">Install App</div>
        <div class="field-hint" style="margin-bottom:12px;">Add ${APP_NAME} to your home screen or desktop so it opens straight to the vault — no address bar, no typing a link.</div>
        <button class="btn btn-outline btn-block" id="install-app-btn">${icon('plus', 15)} Install ${APP_NAME}</button>
      </div>`;
  }
  if (isIOS()) {
    return `
      <div style="border-top:1px solid var(--border);padding-top:16px;">
        <div style="font-weight:700;color:var(--navy);font-size:14px;margin-bottom:6px;">Install App</div>
        <div class="field-hint">iOS doesn't allow apps to trigger this automatically. In Safari, tap the Share icon, then "Add to Home Screen".</div>
      </div>`;
  }
  return `
    <div style="border-top:1px solid var(--border);padding-top:16px;">
      <div style="font-weight:700;color:var(--navy);font-size:14px;margin-bottom:6px;">Install App</div>
      <div class="field-hint">Look for an install icon in your browser's address bar, or check its menu for "Install ${APP_NAME}" / "Add to Home Screen".</div>
    </div>`;
}

// ---------------------------------------------------------------------------
// Modals
// ---------------------------------------------------------------------------
function modalHtml() {
  const m = state.modal;
  if (m.type === 'add-info') return modalShell('Add Information', `
    <div class="add-grid">
      ${[
        ['password', 'Password', ICON.password], ['note', 'Secure Note', ICON.note],
        ['personal', 'Personal Information', ICON.personal], ['custom-new', 'Custom Item', icon('idcard', 18)],
        ['apikey', 'API Key / Secret', icon('key', 18)],
        ['sshkey', 'SSH Key', icon('lock', 18)], ['wallet', 'Crypto Wallet', icon('key', 18)],
        ['document', 'Document', ICON.id], ['physical', 'Physical Access Code', icon('lock', 18)],
        ['license', 'Software License', icon('idcard', 18)], ['medical', 'Medical Profile', icon('activity', 18)],
        ['inheritance', 'Digital Inheritance', ICON.note], ['wifi', 'Wi-Fi Credentials', ICON.wifi],
        ['contact', 'Contact', ICON.contact], ['account', 'Account', ICON.account],
        ['event-new', 'Calendar Event', icon('clock', 18)],
      ].map(([type, label, ic]) => `<button class="add-opt" data-pick-type="${type}"><div class="icon">${ic}</div>${label}</button>`).join('')}
    </div>`);
  if (m.type === 'add-password' || m.type === 'edit-password') return passwordModal(m);
  if (m.type === 'add-note' || m.type === 'edit-note') return noteModal(m);
  if (m.type === 'add-generic' || m.type === 'edit-generic') return genericModal(m);
  if (m.type === 'add-custom' || m.type === 'edit-custom') return customFieldsModal(m);
  if (m.type === 'add-event' || m.type === 'edit-event') return eventModal(m);
  if (m.type === 'reminder-suggestion') return reminderSuggestionModal(m);
  if (m.type === 'item-detail') return itemDetailModal(m);
  if (m.type === 'file-upload') return fileUploadModal(m);
  if (m.type === 'goal-edit') return goalEditModal();
  if (m.type === 'emergency-invite') return modalShell('Add an emergency contact', `
    <form id="emergency-invite-form">
      <div class="field"><label>Contact name</label><input name="contactName" required maxlength="80" /></div>
      <div class="field"><label>Contact email</label><input name="contactEmail" type="email" required maxlength="254" /></div>
      <div class="field"><label>Waiting period before access is released</label>
        <select name="waitDays"><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option></select>
      </div>
      <div class="field-hint" style="margin-bottom:12px;">You'll get a one-time code to give your contact. They need it to request access. It can't be shown again, so keep a note of it until you've passed it on.</div>
      <div id="emergency-invite-error"></div>
      <button class="btn btn-primary btn-block" type="submit">Create contact</button>
    </form>`);
  if (m.type === 'emergency-secret') return modalShell('Give this code to your contact', `
    <div class="field-hint" style="margin-bottom:12px;">Share this link with ${esc(m.name)} in person or in a private message. It contains the access code and is shown only once.</div>
    <div class="recovery-key-box" style="font-size:12px;word-break:break-all;">${esc(location.origin + '/contact.html#id=' + m.id + '&code=' + m.secret)}</div>
    <button class="btn btn-subtle btn-block" id="emergency-copy" style="margin-bottom:8px;">${ICON.copy} Copy code</button>
    <button class="btn btn-primary btn-block" id="emergency-done">I have passed it on</button>`);
  if (m.type === 'recovery-key-shown') return modalShell('Your new recovery key', `
    <div class="field-hint" style="margin-bottom:12px;">Write this down and keep it somewhere safe. It is shown only once. The old recovery key no longer works.</div>
    <div class="recovery-key-box">${esc(state.pendingRecoveryKey)}</div>
    <button class="btn btn-subtle btn-block" id="recovery-copy" style="margin-bottom:8px;">${ICON.copy} Copy key</button>
    <button class="btn btn-primary btn-block" id="recovery-done">I have saved it</button>`);
  if (m.type === 'share-link') return shareLinkModal(m);
  if (m.type === 'breach-result') return breachResultModal(m);
  if (m.type === 'export-backup') return exportBackupModal();
  if (m.type === 'import-backup') return importBackupModal();
  if (m.type === 'duress-pin') return duressPinModal();
  if (m.type === 'confirm-delete') return confirmModal({
    title: 'Delete item?', body: `This permanently removes "${m.title}". This can't be undone.`, confirmLabel: 'Delete', danger: true, action: 'confirm-delete-item', id: m.id,
  });
  if (m.type === 'change-password') return changePasswordModal();
  if (m.type === 'change-pin') return changePinModal();
  if (m.type === 'delete-account') return deleteAccountModal();
  if (m.type === 'reauth') return reauthModal(m);
  return '';
}

function modalShell(title, body) {
  return `<div class="modal-scrim" id="modal-scrim"><div class="modal"><div class="modal-head"><div class="modal-title">${title}</div><button class="icon-btn" id="modal-close">${icon('x', 16)}</button></div><div class="modal-body">${body}</div></div></div>`;
}

function passwordModal(m) {
  const item = m.item;
  return modalShell(m.type === 'edit-password' ? 'Edit Password' : 'Add Password', `
    <form id="password-form">
      <div class="field"><label>Website</label><input name="title" required value="${item?.title || ''}" placeholder="e.g. Google" /></div>
      <div class="field"><label>Username / Email</label><input name="searchUsername" value="${item?.searchUsername || ''}" placeholder="you@example.com" /></div>
      <div class="field"><label>Password</label>
        <div class="pw-wrap"><input name="password" id="pw-field" required value="${item?.payload?.password || ''}" placeholder="••••••••••••••••" /><button type="button" class="pw-toggle" data-toggle="pw-field">${ICON.eye}</button></div>
      </div>
      <button type="button" class="link-btn" id="toggle-generator" style="margin-bottom:12px;display:inline-flex;align-items:center;gap:6px;">${icon('refresh', 14)} Generate Strong Password</button>
      <div id="generator-slot"></div>
      <div class="field"><label>Category</label>
        <select name="category">${['General','Email','Social','Banking','Work','Shopping'].map((c) => `<option ${item?.category === c ? 'selected' : ''}>${c}</option>`).join('')}</select>
      </div>
      <div class="field"><label>Notes</label><textarea name="notes" rows="3">${item?.payload?.notes || ''}</textarea></div>
      <input type="hidden" name="website" value="${item?.payload?.website || ''}" />
      <button class="btn btn-primary btn-block" type="submit">Save Securely</button>
    </form>`);
}

function noteModal(m) {
  const item = m.item;
  return modalShell(m.type === 'edit-note' ? 'Edit Secure Note' : 'New Secure Note', `
    <form id="note-form">
      <div class="field"><label>Title</label><input name="title" required value="${item?.title || ''}" placeholder="e.g. Wi-Fi Information" /></div>
      <div class="field"><label>Content</label><textarea name="content" rows="6">${item?.payload?.content || ''}</textarea></div>
      <button class="btn btn-primary btn-block" type="submit">Save Note (Encrypted)</button>
    </form>`);
}

function genericModal(m) {
  const t = m.itemType;
  const item = m.item;
  const fields = FIELD_CONFIGS[t] || [['notes', 'Notes', false, 'textarea']];
  return modalShell(`${item ? 'Edit' : 'Add'} ${labelForType(t)}`, `
    <form id="generic-form">
      <input type="hidden" name="_type" value="${t}" />
      <div class="field"><label>Title</label><input name="title" required value="${item?.title || ''}" placeholder="e.g. ${titlePlaceholder(t)}" /></div>
      ${fields.map(([key, label, sensitive, kind]) => {
        const val = (item?.payload?.[key] || '').toString().replace(/"/g, '&quot;');
        if (kind === 'textarea') return `<div class="field"><label>${label}</label><textarea name="${key}" rows="${sensitive ? 4 : 3}" style="${sensitive ? 'font-family:monospace;font-size:12.5px;' : ''}">${item?.payload?.[key] || ''}</textarea></div>`;
        return `<div class="field"><label>${label}</label><input name="${key}" value="${val}" ${sensitive ? 'style="font-family:monospace;"' : ''} /></div>`;
      }).join('')}
      <button class="btn btn-primary btn-block" type="submit">Save Securely</button>
    </form>`);
}

function titlePlaceholder(t) {
  return { wifi: 'Home_WiFi', contact: 'Mom', account: 'Netflix', apikey: 'AWS Production', sshkey: 'Prod Web Server', wallet: 'Main ETH Wallet', physical: 'Front Door', license: 'Windows 11 Pro', medical: 'Health Profile', inheritance: 'In Case of Emergency', document: 'Passport Scan' }[t] || 'Title';
}

// ---------------------------------------------------------------------------
// Flexible custom fields — spec section 4: users are not limited to
// predefined field sets. Every row is a free-form name/value pair the user
// types themselves, with an optional "sensitive" flag (masked like a
// password until revealed). Stored as payload: { fields: [...], notes }.
// ---------------------------------------------------------------------------
function customFieldsModal(m) {
  const fields = m.fields || [];
  return modalShell(m.item ? 'Edit Custom Item' : 'New Custom Item', `
    <form id="custom-fields-form">
      <div class="field"><label>Heading</label><input name="title" required value="${esc(m.title !== undefined ? m.title : (m.item?.title || ''))}" placeholder="e.g. My Important Information" autofocus /></div>
      <div id="login-hint-container">${loginHintHtml(fields)}</div>
      <div id="custom-field-rows">${customFieldRowsHtml(fields)}</div>
      <button type="button" class="link-btn" id="add-custom-field-row" style="margin:4px 0 16px;">${icon('plus', 13)} Add Field</button>
      <div class="field"><label>Notes (optional)</label><textarea name="notes" rows="2">${esc(m.item?.payload?.notes || '')}</textarea></div>
      <button class="btn btn-primary btn-block" type="submit">Save Securely</button>
    </form>`);
}

function customFieldRowsHtml(fields) {
  return fields.map((f, i) => {
    const sensitive = !!f.sensitive || isAutoSensitive(f.name);
    return `
    <div class="custom-field-row" data-row="${i}">
      <input class="cf-name" value="${esc(f.name)}" placeholder="Field name (e.g. Membership Number)" />
      <input class="cf-value" type="${sensitive ? 'password' : 'text'}" value="${esc(f.value)}" placeholder="Value" />
      <label class="cf-sensitive" title="Mask this value like a password"><input type="checkbox" ${sensitive ? 'checked' : ''} />${icon('lock', 13)}</label>
      <button type="button" class="icon-btn cf-remove" title="Remove field">${icon('x', 14)}</button>
    </div>`;
  }).join('');
}

/** Heuristic-only, spec section 5/10: an email/username field plus a password field suggests a login. Never auto-saves anything — just a suggestion the user can ignore. */
// Mirrors server/vault.js AUTO_SENSITIVE_NAME_RE — a custom field named
// "Password"/"PIN"/etc. is treated as sensitive even if the user forgot to
// check the box. This is a floor applied at SAVE time (so the stored data
// itself is correct downstream, not just this session's display) and again
// at DISPLAY time as a safety net for anything saved before this existed.
const AUTO_SENSITIVE_NAME_RE = /password|passphrase|\bpin\b|\bcvv\b|\bssn\b|secret|private\s*key|seed\s*phrase|license\s*key/i;
function isAutoSensitive(name) {
  return AUTO_SENSITIVE_NAME_RE.test(name || '');
}

function detectLoginPattern(fields) {
  const hasCredential = fields.some((f) => /email|username|login\s*id/i.test(f.name));
  const hasPassword = fields.some((f) => /password/i.test(f.name));
  return hasCredential && hasPassword;
}

function loginHintHtml(fields) {
  if (!detectLoginPattern(fields)) return '';
  return `
    <div class="rec-tip warn" style="margin-bottom:14px;">
      ${ICON.warn} This looks like a login (an email/username and a password field). Consider using
      <button type="button" class="link-btn" id="switch-to-password-entry" style="display:inline;padding:0;">Add Password</button>
      instead — it keeps related credentials together and supports the password generator and breach checking.
    </div>`;
}

function readCustomFieldRows() {
  return Array.from(document.querySelectorAll('.custom-field-row')).map((row) => {
    const name = row.querySelector('.cf-name').value.trim();
    return {
      name, value: row.querySelector('.cf-value').value,
      sensitive: row.querySelector('.cf-sensitive input').checked || isAutoSensitive(name),
    };
  }).filter((f) => f.name || f.value);
}

function bindCustomFieldsFormEvents() {
  const form = document.getElementById('custom-fields-form');
  if (!form) return;

  const addRowBtn = document.getElementById('add-custom-field-row');
  if (addRowBtn) addRowBtn.onclick = () => {
    state.modal.title = form.querySelector('[name="title"]').value;
    state.modal.fields = readCustomFieldRows();
    state.modal.fields.push({ name: '', value: '', sensitive: false });
    render();
    const rows = document.querySelectorAll('.custom-field-row .cf-name');
    rows[rows.length - 1]?.focus();
  };
  document.querySelectorAll('.cf-remove').forEach((btn) => {
    btn.onclick = () => {
      state.modal.title = form.querySelector('[name="title"]').value;
      const rows = readCustomFieldRows();
      const idx = Number(btn.closest('.custom-field-row').dataset.row);
      state.modal.fields = rows.filter((_, i) => i !== idx);
      if (state.modal.fields.length === 0) state.modal.fields.push({ name: '', value: '', sensitive: false });
      render();
    };
  });
  document.querySelectorAll('.cf-sensitive input').forEach((checkbox) => {
    checkbox.onchange = () => {
      // Mask the value field the instant "sensitive" is checked, without a
      // full re-render — a full render would lose focus/cursor position in
      // whichever field the user is actively typing in.
      const valueInput = checkbox.closest('.custom-field-row').querySelector('.cf-value');
      valueInput.type = checkbox.checked ? 'password' : 'text';
    };
  });

  // Live credential-detection (spec section 5/10) — recomputed on every
  // keystroke in a field NAME, without a full re-render, so typing "Email"
  // then "Password" as field names shows the hint immediately rather than
  // only after the next Add/Remove Field click.
  form.querySelectorAll('.cf-name').forEach((input) => {
    input.oninput = () => {
      document.getElementById('login-hint-container').innerHTML = loginHintHtml(readCustomFieldRows());
      // Auto-mask the value the instant the field name looks sensitive
      // (e.g. typing "Password") — same live-update approach as the
      // sensitivity checkbox itself, so nothing sensitive is ever shown
      // in the clear just because the user didn't think to check the box.
      const row = input.closest('.custom-field-row');
      const checkbox = row.querySelector('.cf-sensitive input');
      if (isAutoSensitive(input.value) && !checkbox.checked) {
        checkbox.checked = true;
        row.querySelector('.cf-value').type = 'password';
      }
    };
  });
  // Event delegation for the hint's own button, since its DOM node gets
  // replaced by the innerHTML swap above and a directly-bound handler
  // would otherwise go stale after the first field-name keystroke.
  form.onclick = (e) => {
    if (e.target.id !== 'switch-to-password-entry') return;
    const rows = readCustomFieldRows();
    const emailField = rows.find((f) => /email|username|login\s*id/i.test(f.name));
    const pwField = rows.find((f) => /password/i.test(f.name));
    state.modal = {
      type: 'add-password',
      item: { title: form.querySelector('[name="title"]').value, searchUsername: emailField?.value || '', payload: { password: pwField?.value || '' } },
    };
    render();
  };

  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const fields = readCustomFieldRows();
    if (fields.length === 0) { toast('Add at least one field.', 'warn'); return; }
    const payload = { fields, notes: fd.get('notes') || '' };
    try {
      const editing = state.modal.item;
      let saved;
      if (editing) saved = await api('PUT', `/api/vault/items/${editing.id}`, { title: fd.get('title'), payload });
      else saved = await api('POST', '/api/vault/items', { type: 'custom', title: fd.get('title'), payload });
      toast(editing ? 'Updated' : 'Saved securely — your information has been encrypted and stored.');
      state.modal = null;
      await maybeSuggestReminders(fields, fd.get('title'), saved.item.id);
      await navigate(state.active === 'custom' || state.active === 'dashboard' ? 'custom' : state.active);
    } catch (err) { toast(err.message, 'error'); }
  };
}

// ---------------------------------------------------------------------------
// Smart date detection (spec sections 20, 25) — purely client-side, purely
// a suggestion. Never creates a reminder without the user explicitly
// clicking "Add Reminder"; a rejected/dismissed suggestion does nothing.
// ---------------------------------------------------------------------------
const DATE_FIELD_PATTERNS = [
  { re: /\b(dob|date\s*of\s*birth|birth\s*date|birthday)\b/i, eventType: 'birthday', recurrence: 'annually', label: 'birthday' },
  { re: /\b(expir\w*|renewal|valid\s*until)\b/i, eventType: 'expiry', recurrence: 'none', label: 'expiration/renewal' },
  { re: /\banniversary\b/i, eventType: 'general', recurrence: 'annually', label: 'anniversary' },
];

function parseHumanDate(value) {
  if (!value) return null;
  const v = String(value).trim();
  let m = v.match(/^(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})$/); // DD/MM/YYYY
  if (m) { const [, d, mo, y] = m; if (+mo <= 12 && +d <= 31) return `${y}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`; }
  m = v.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/); // YYYY-MM-DD
  if (m) { const [, y, mo, d] = m; return `${y}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`; }
  const parsed = new Date(v); // "15 September 2000" and similar — trust the browser's date parser
  if (!isNaN(parsed) && v.length > 5) return `${parsed.getFullYear()}-${String(parsed.getMonth() + 1).padStart(2, '0')}-${String(parsed.getDate()).padStart(2, '0')}`;
  return null;
}

function detectDateFields(fields) {
  const found = [];
  for (const f of fields) {
    const isoDate = parseHumanDate(f.value);
    if (!isoDate) continue;
    const pattern = DATE_FIELD_PATTERNS.find((p) => p.re.test(f.name));
    if (pattern) found.push({ fieldName: f.name, isoDate, ...pattern });
  }
  return found;
}

async function maybeSuggestReminders(fields, itemTitle, itemId) {
  const detected = detectDateFields(fields);
  if (detected.length === 0) return;
  // One suggestion at a time — the user can add more manually from the
  // Calendar screen if a second date field also looked meaningful.
  const d = detected[0];
  state.modal = { type: 'reminder-suggestion', detected: d, itemTitle, itemId };
  render();
}

function reminderSuggestionModal(m) {
  const d = m.detected;
  const dateLabel = new Date(d.isoDate).toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: d.eventType === 'birthday' ? undefined : 'numeric' });
  const question = d.eventType === 'birthday'
    ? `This looks like a birthday (${d.fieldName}: ${dateLabel}). Would you like an annual reminder?`
    : d.label === 'anniversary'
      ? `This looks like an anniversary (${d.fieldName}: ${dateLabel}). Would you like an annual reminder?`
      : `This looks like an expiration or renewal date (${d.fieldName}: ${dateLabel}). Would you like a reminder before it's due?`;
  const offsetOptions = d.eventType === 'birthday' || d.label === 'anniversary'
    ? [[7, '7 days before'], [1, '1 day before'], [0, 'On the day']]
    : [[365, '1 year before'], [180, '6 months before'], [90, '3 months before'], [30, '1 month before'], [7, '1 week before']];
  return modalShell('Create a Reminder?', `
    <div style="font-size:13.5px;color:var(--text);line-height:1.6;margin-bottom:16px;">${esc(question)}</div>
    <div class="field"><label>Remind me</label>
      <select id="reminder-offset">${offsetOptions.map(([days, label]) => `<option value="${days}">${label}</option>`).join('')}</select>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:8px;">
      <button class="btn btn-ghost" id="reminder-dismiss">Not Now</button>
      <button class="btn btn-primary" id="reminder-accept">${icon('plus', 15)} Add Reminder</button>
    </div>
  `);
}

// ---------------------------------------------------------------------------
// Calendar / Events
// ---------------------------------------------------------------------------
const EVENT_TYPE_META = {
  personal: { icon: 'note', label: 'Personal' },
  birthday: { icon: 'user', label: 'Birthday' },
  appointment: { icon: 'clock', label: 'Appointment' },
  medication: { icon: 'activity', label: 'Medication' },
  water: { icon: 'droplet', label: 'Water Reminder' },
  payment: { icon: 'key', label: 'Payment' },
  security: { icon: 'shield', label: 'Security' },
  task: { icon: 'check', label: 'Task' },
  custom: { icon: 'idcard', label: 'Custom' },
  expiry: { icon: 'clock', label: 'Expiry / Renewal' },
  general: { icon: 'note', label: 'Event' },
};

function calendarScreen() {
  const switcher = `
    <div class="cal-view-switch">
      ${[['month','Month'],['week','Week'],['day','Day'],['upcoming','Upcoming'],['completed','Completed']].map(([k, l]) =>
        `<button class="tab-btn ${state.calendarView === k ? 'active' : ''}" data-cal-view="${k}">${l}</button>`).join('')}
    </div>`;
  let body;
  if (state.calendarView === 'upcoming') body = upcomingEventsView();
  else if (state.calendarView === 'completed') body = completedEventsView();
  else if (state.calendarView === 'week') body = weekCalendarView();
  else if (state.calendarView === 'day') body = dayCalendarView();
  else body = monthCalendarView();
  return switcher + body;
}

function completedEventsView() {
  const items = state.completedEvents || [];
  if (items.length === 0) return `<div class="empty-state"><div class="empty-icon">${icon('check', 22)}</div><div>No completed events yet.</div></div>`;
  return items.map((ev) => `
    <div class="card item-row" data-event-id="${ev.id}" style="cursor:pointer;">
      <div class="item-badge">${icon((EVENT_TYPE_META[ev.eventType] || EVENT_TYPE_META.personal).icon, 18)}</div>
      <div class="item-main">
        <div class="item-title">${esc(ev.title)}</div>
        <div class="item-sub">${esc(ev.startDate)}${ev.startTime ? ' · ' + esc(ev.startTime) : ''} · Completed</div>
      </div>
    </div>`).join('');
}

// Week and day views reuse the already-loaded month event range, so
// navigating between them never needs a new server call.
function weekCalendarView() {
  const cursor = state.calendarDay ? parseISODate(state.calendarDay) : new Date();
  const start = new Date(cursor); start.setDate(cursor.getDate() - cursor.getDay());
  const days = Array.from({ length: 7 }, (_, i) => { const d = new Date(start); d.setDate(start.getDate() + i); return d; });
  const todayStr = todayISO();
  const byDate = {};
  for (const ev of state.events) (byDate[ev.occurrenceDate] = byDate[ev.occurrenceDate] || []).push(ev);
  return `
    <div class="cal-toolbar">
      <div class="cal-month-label">${days[0].toLocaleDateString(undefined, { month: 'short', day: 'numeric' })} -- ${days[6].toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}</div>
    </div>
    <div class="cal-week">
      ${days.map((d) => {
        const ds = toISO(d);
        const evs = byDate[ds] || [];
        return `<div class="cal-week-col ${ds === todayStr ? 'cal-cell-today' : ''}">
          <div class="cal-week-head">${d.toLocaleDateString(undefined, { weekday: 'short' })} ${d.getDate()}</div>
          ${evs.length ? evs.map((ev) => `<button class="cal-event-chip" data-event-id="${ev.id}">${esc(ev.title)}</button>`).join('') : '<div class="cal-more">--</div>'}
        </div>`;
      }).join('')}
    </div>`;
}

function dayCalendarView() {
  const d = state.calendarDay ? parseISODate(state.calendarDay) : new Date();
  const ds = toISO(d);
  const evs = (state.events || []).filter((ev) => ev.occurrenceDate === ds);
  return `
    <div class="cal-toolbar">
      <div class="cal-month-label">${d.toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}</div>
    </div>
    ${evs.length === 0 ? `<div class="empty-state"><div class="empty-icon">${icon('clock', 22)}</div><div>No events on this day.</div></div>`
      : evs.map((ev) => `
        <div class="card item-row" data-event-id="${ev.id}" style="cursor:pointer;">
          <div class="item-badge">${icon((EVENT_TYPE_META[ev.eventType] || EVENT_TYPE_META.personal).icon, 18)}</div>
          <div class="item-main">
            <div class="item-title">${esc(ev.title)}</div>
            <div class="item-sub">${ev.startTime ? esc(ev.startTime) : 'All day'}${ev.recurrence !== 'none' ? ' · Repeats' : ''}</div>
          </div>
        </div>`).join('')}`;
}

function parseISODate(s) { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); }
function toISO(d) { return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; }

function monthCalendarView() {
  const { year, month } = state.calendarCursor;
  const monthName = new Date(year, month, 1).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
  const firstDay = new Date(year, month, 1);
  const startOffset = firstDay.getDay();
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const todayStr = todayISO();

  const byDate = {};
  for (const ev of state.events) (byDate[ev.occurrenceDate] = byDate[ev.occurrenceDate] || []).push(ev);

  const cells = [];
  for (let i = 0; i < startOffset; i++) cells.push('<div class="cal-cell cal-cell-empty"></div>');
  for (let day = 1; day <= daysInMonth; day++) {
    const dateStr = `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    const dayEvents = byDate[dateStr] || [];
    cells.push(`
      <div class="cal-cell ${dateStr === todayStr ? 'cal-cell-today' : ''}">
        <div class="cal-cell-day">${day}</div>
        ${dayEvents.slice(0, 3).map((ev) => `<button class="cal-event-chip" data-event-id="${ev.id}" title="${esc(ev.title)}">${icon(EVENT_TYPE_META[ev.eventType]?.icon || 'note', 10)} ${esc(ev.title)}</button>`).join('')}
        ${dayEvents.length > 3 ? `<div class="cal-more">+${dayEvents.length - 3} more</div>` : ''}
      </div>`);
  }

  return `
    <div class="cal-toolbar">
      <div class="cal-nav">
        <button class="icon-btn" id="cal-prev">${icon('arrowLeft', 16)}</button>
        <div class="cal-month-label">${monthName}</div>
        <button class="icon-btn" id="cal-next">${icon('arrowRight', 16)}</button>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="tab-btn" data-cal-view="upcoming">Upcoming</button>
        <button class="btn btn-primary btn-sm" id="cal-add-event">${icon('plus', 14)} Add Event</button>
      </div>
    </div>
    <div class="cal-grid cal-grid-head">${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map((d) => `<div>${d}</div>`).join('')}</div>
    <div class="cal-grid">${cells.join('')}</div>`;
}

function upcomingEventsView() {
  const items = state.upcomingEvents || [];
  return `
    <div class="cal-toolbar">
      <div style="font-weight:700;color:var(--navy);font-size:15px;">Upcoming</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <label style="font-size:12.5px;color:var(--text-muted);">Show next
          <select id="upcoming-window" style="margin-left:6px;padding:6px 8px;border-radius:8px;border:1px solid var(--border);font-size:13px;">
            ${UPCOMING_WINDOW_OPTIONS.map(([d, l]) => `<option value="${d}" ${upcomingWindowDays() === d ? 'selected' : ''}>${l}</option>`).join('')}
          </select>
        </label>
        <button class="tab-btn" data-cal-view="month">Month View</button>
        <button class="btn btn-primary btn-sm" id="cal-add-event">${icon('plus', 14)} Add Event</button>
      </div>
    </div>
    ${items.length === 0 ? `<div class="empty-state"><div class="empty-icon">${icon('clock', 22)}</div><div>Nothing coming up in the next ${upcomingWindowDays()} days.</div></div>` : items.map((ev) => upcomingEventRow(ev)).join('')}`;
}

function upcomingEventRow(ev) {
  const meta = EVENT_TYPE_META[ev.eventType] || EVENT_TYPE_META.general;
  const when = ev.daysRemaining === 0 ? 'Today' : ev.daysRemaining === 1 ? 'Tomorrow' : `${ev.daysRemaining} days remaining`;
  return `
    <div class="card item-row" data-event-id="${ev.id}" style="cursor:pointer;">
      <div class="item-badge">${icon(meta.icon, 18)}</div>
      <div class="item-main">
        <div class="item-title">${esc(ev.title)}</div>
        <div class="item-sub">${new Date(ev.occurrenceDate).toLocaleDateString(undefined, { month: 'long', day: 'numeric' })} · ${when}</div>
      </div>
    </div>`;
}

function todayISO() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

const REMINDER_OPTIONS = [
  [0, 'At event time'], [5, '5 minutes before'], [15, '15 minutes before'], [30, '30 minutes before'],
  [60, '1 hour before'], [120, '2 hours before'], [1440, '1 day before'], [10080, '1 week before'],
];
const EVENT_TYPE_ORDER = ['personal', 'birthday', 'appointment', 'medication', 'water', 'payment', 'security', 'task', 'custom'];
const REPEAT_OPTIONS = [['none', 'Does not repeat'], ['daily', 'Daily'], ['weekly', 'Weekly'], ['monthly', 'Monthly'], ['annually', 'Yearly']];

function eventModal(m) {
  const ev = m.event;
  const selectedReminders = new Set((ev?.reminders || []).map((r) => r.minutesBefore));
  return modalShell(ev ? 'Edit Event' : 'New Event', `
    <form id="event-form">
      <div class="field"><label>Event Title</label><input name="title" required value="${esc(ev?.title || '')}" placeholder="e.g. Doctor Appointment" /></div>
      <div class="field"><label>Event Type</label>
        <select name="eventType">
          ${EVENT_TYPE_ORDER.map((k) => `<option value="${k}" ${(ev?.eventType || 'personal') === k ? 'selected' : ''}>${EVENT_TYPE_META[k].label}</option>`).join('')}
        </select>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div class="field"><label>Date</label><input name="startDate" type="date" required value="${ev?.startDate || todayISO()}" /></div>
        <div class="field"><label>Time</label><input name="startTime" type="time" value="${ev?.startTime || ''}" /></div>
      </div>
      <div class="field"><label>Location (optional)</label><input name="location" value="${esc(ev?.location || '')}" placeholder="Optional" /></div>
      <div class="field"><label>Notes (optional)</label><textarea name="description" rows="2" placeholder="Optional">${esc(ev?.description || '')}</textarea></div>
      <div class="field"><label>Reminders</label>
        <div class="reminder-grid">
          ${REMINDER_OPTIONS.map(([mins, label]) => `
            <label class="reminder-chip ${selectedReminders.has(mins) ? 'on' : ''}">
              <input type="checkbox" name="reminder" value="${mins}" ${selectedReminders.has(mins) ? 'checked' : ''} />${esc(label)}
            </label>`).join('')}
        </div>
        <div class="field-hint">Pick any combination. Each one fires at its own time before the event.</div>
      </div>
      <div class="field"><label>Repeat</label>
        <select name="recurrence">
          ${REPEAT_OPTIONS.map(([k, l]) => `<option value="${k}" ${(ev?.recurrence || 'none') === k ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
      </div>
      <button class="btn btn-primary btn-block" type="submit">${ev ? 'Save Changes' : 'Save Event'}</button>
      ${ev ? `
        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;">
          <button type="button" class="btn btn-subtle btn-sm" id="event-toggle-complete" style="flex:1;">${ev.completed ? 'Reopen' : 'Mark as completed'}</button>
          <button type="button" class="btn btn-subtle btn-sm" id="event-duplicate" style="flex:1;">${icon('copy', 13)} Duplicate</button>
          <button type="button" class="btn btn-danger btn-sm" id="delete-event-btn" style="flex:1;">${ICON.trash} Delete</button>
        </div>` : ''}
    </form>`);
}

function bindEventFormEvents() {
  const form = document.getElementById('event-form');
  if (form) {
    form.querySelectorAll('.reminder-chip input').forEach((cb) => {
      cb.onchange = () => cb.closest('.reminder-chip').classList.toggle('on', cb.checked);
    });
    form.onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const reminders = fd.getAll('reminder').map((v) => ({ minutesBefore: Number(v) }));
      const data = {
        title: fd.get('title'), startDate: fd.get('startDate'), startTime: fd.get('startTime') || null,
        eventType: fd.get('eventType'), recurrence: fd.get('recurrence'), location: fd.get('location') || null,
        description: fd.get('description') || null, reminders,
      };
      try {
        if (state.modal.event) await api('PUT', `/api/events/${state.modal.event.id}`, data);
        else await api('POST', '/api/events', data);
        toast(state.modal.event ? 'Changes saved successfully.' : 'Event saved.');
        state.modal = null;
        await navigate('calendar');
      } catch (err) { toast('Unable to save changes. Please try again.', 'error'); }
    };
  }
  const deleteBtn = document.getElementById('delete-event-btn');
  if (deleteBtn) deleteBtn.onclick = async () => {
    try {
      await api('DELETE', `/api/events/${state.modal.event.id}`);
      toast('Event deleted');
      state.modal = null;
      await navigate('calendar');
    } catch (err) { toast(err.message, 'error'); }
  };
  const completeBtn = document.getElementById('event-toggle-complete');
  if (completeBtn) completeBtn.onclick = async () => {
    try {
      const ev = state.modal.event;
      await api('POST', `/api/events/${ev.id}/complete`, { completed: !ev.completed });
      toast(ev.completed ? 'Event reopened' : 'Marked as completed');
      state.modal = null;
      await navigate('calendar');
    } catch (err) { toast(err.message, 'error'); }
  };
  const dupBtn = document.getElementById('event-duplicate');
  if (dupBtn) dupBtn.onclick = async () => {
    try {
      await api('POST', `/api/events/${state.modal.event.id}/duplicate`, {});
      toast('Event duplicated');
      state.modal = null;
      await navigate('calendar');
    } catch (err) { toast(err.message, 'error'); }
  };
}

function bindReminderSuggestionEvents() {
  const dismissBtn = document.getElementById('reminder-dismiss');
  if (dismissBtn) dismissBtn.onclick = () => { state.modal = null; render(); };
  const acceptBtn = document.getElementById('reminder-accept');
  if (acceptBtn) acceptBtn.onclick = async () => {
    const { detected, itemTitle, itemId } = state.modal;
    const daysBefore = Number(document.getElementById('reminder-offset').value);
    const title = detected.eventType === 'birthday' ? `${itemTitle}'s Birthday` : `${itemTitle} — ${detected.label}`;
    try {
      await api('POST', '/api/events', {
        title, startDate: detected.isoDate, eventType: detected.eventType, recurrence: detected.recurrence,
        linkedItemId: itemId, reminders: [{ daysBefore, time: '08:00' }],
      });
      toast('Reminder created');
      state.modal = null;
      render();
    } catch (err) { toast(err.message, 'error'); }
  };
}

function itemDetailModal(m) {
  const item = m.item;
  const revealed = !!state.revealCache[item.id];
  const payload = revealed ? state.revealCache[item.id] : item.payload;
  const fieldsHtml = item.type === 'custom'
    ? (payload?.fields || []).filter((f) => f.name || f.value).map((f) => {
      const sensitive = !!f.sensitive || isAutoSensitive(f.name); // safety net for items saved before auto-detection existed
      return `
      <div class="field"><label>${esc(f.name)}</label>
        <div style="font-family:${sensitive ? 'monospace' : 'inherit'};font-size:13.5px;padding:10px 0;border-bottom:1px solid var(--border);white-space:pre-wrap;word-break:break-word;">
          ${sensitive && !revealed ? '••••••••••••' : esc(f.value)}
        </div>
      </div>`;
    }).join('') + (payload?.notes ? `<div class="field"><label>Notes</label><div style="font-size:13.5px;padding:10px 0;white-space:pre-wrap;">${esc(payload.notes)}</div></div>` : '')
    : Object.entries(payload || {}).filter(([, v]) => v !== '' && v !== undefined).map(([k, v]) => `
      <div class="field"><label>${k[0].toUpperCase()}${k.slice(1).replace(/([A-Z])/g, ' $1')}</label>
        <div style="font-family:${SENSITIVE_KEYS.has(k) ? 'monospace' : 'inherit'};font-size:13.5px;padding:10px 0;border-bottom:1px solid var(--border);white-space:pre-wrap;word-break:break-word;">
          ${SENSITIVE_KEYS.has(k) && !revealed ? '••••••••••••' : esc(v)}
        </div>
      </div>`).join('');
  const hasSensitive = item.type === 'custom' ? (payload?.fields || []).some((f) => !!f.sensitive || isAutoSensitive(f.name)) : Object.keys(payload || {}).some((k) => SENSITIVE_KEYS.has(k));
  return modalShell(esc(item.title), `
    <div style="font-size:12.5px;color:var(--text-muted);margin-bottom:12px;">Category: ${labelForType(item.type)}</div>
    ${fieldsHtml}
    ${item.type === 'document' ? documentFileSection(item) : ''}
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
      ${hasSensitive && !revealed ? `<button class="btn btn-outline btn-sm" id="detail-reveal">${ICON.eye} Reveal</button>` : ''}
      ${revealed ? `<button class="btn btn-subtle btn-sm" id="detail-copy">${ICON.copy} Copy</button>` : ''}
      ${revealed && item.type === 'password' ? `<button class="btn btn-subtle btn-sm" id="detail-breach-check">${icon('shield', 14)} Check for breaches</button>` : ''}
      ${revealed ? `<button class="btn btn-subtle btn-sm" id="detail-share">${icon('arrowRight', 14)} Share link</button>` : ''}
      <button class="btn btn-subtle btn-sm" id="detail-edit" data-id="${item.id}" data-type="${item.type}">${ICON.edit} Edit</button>
      <button class="btn btn-subtle btn-sm" id="detail-delete" data-id="${item.id}" data-title="${esc(item.title)}">${ICON.trash} Delete</button>
    </div>`);
}

function documentFileSection(item) {
  const meta = state.fileMetaCache?.[item.id];
  return `
    <div style="margin:14px 0;padding:12px;background:var(--bg);border-radius:10px;">
      <div style="font-size:12.5px;font-weight:600;margin-bottom:8px;">Attached File</div>
      ${meta === undefined ? `<div style="font-size:12.5px;color:var(--text-muted);">Loading…</div>` :
        meta === null ? `<button class="btn btn-outline btn-sm" id="attach-file-btn" data-item-id="${item.id}">${icon('plus', 14)} Attach File (PDF/PNG/JPEG, 6MB max)</button>` :
        `<div style="display:flex;align-items:center;gap:10px;">
           <span style="font-size:13px;">${meta.file_name} <span style="color:var(--text-muted);">(${Math.round(meta.size_bytes / 1024)} KB)</span></span>
           <button class="link-btn" id="download-file-btn" data-item-id="${item.id}">${icon('copy', 13)} Download</button>
           <button class="link-btn" id="remove-file-btn" data-item-id="${item.id}" style="color:var(--danger);">Remove</button>
         </div>`}
    </div>`;
}

function reauthModal(m) {
  return modalShell('Confirm it\'s you', `
    <div style="font-size:13px;color:var(--text-muted);margin-bottom:14px;">Re-enter your master password to reveal this secret.</div>
    <form id="reauth-form">
      <div class="field"><label>Master Password</label><input name="password" type="password" required /></div>
      <div id="reauth-error"></div>
      <button class="btn btn-primary btn-block" type="submit">Reveal</button>
    </form>`);
}

function confirmModal({ title, body, confirmLabel, danger }) {
  return modalShell(title, `
    <div style="font-size:14px;line-height:1.6;margin-bottom:16px;">${body}</div>
    <div style="display:flex;gap:10px;justify-content:flex-end;">
      <button class="btn btn-ghost" id="modal-cancel">Cancel</button>
      <button class="btn ${danger ? 'btn-danger-solid' : 'btn-primary'}" id="modal-confirm">${confirmLabel}</button>
    </div>`);
}

function changePasswordModal() {
  return modalShell('Change Master Password', `
    <form id="change-password-form">
      <div class="field"><label>Current Master Password</label><input name="currentPassword" type="password" required autocomplete="current-password" /></div>
      <div class="field"><label>New Master Password</label><input name="newPassword" type="password" required minlength="8" autocomplete="new-password" /></div>
      <div class="field"><label>Confirm New Password</label><input name="confirm" type="password" required autocomplete="new-password" /></div>
      <div id="cp-error"></div>
      <button class="btn btn-primary btn-block" type="submit">Update Password</button>
    </form>`);
}

function changePinModal() {
  return modalShell('Change PIN', `
    <form id="change-pin-form">
      <div class="field"><label>New PIN (4–6 digits)</label><input name="pin" required pattern="\\d{4,6}" /></div>
      <div class="field"><label>Confirm PIN</label><input name="confirm" required pattern="\\d{4,6}" /></div>
      <div id="pin-modal-error"></div>
      <button class="btn btn-primary btn-block" type="submit">Save PIN</button>
    </form>`);
}

function deleteAccountModal() {
  return modalShell('Delete your account', `
    <div style="font-size:14px;line-height:1.6;margin-bottom:16px;">This permanently removes your encrypted vault — every saved password, note, and personal record. This cannot be undone.</div>
    <form id="delete-account-form">
      <div class="field"><label>Type "DELETE MY ACCOUNT" to confirm</label><input name="confirmText" required placeholder="DELETE MY ACCOUNT" /></div>
      <div class="field"><label>Master Password</label><input name="password" type="password" required /></div>
      <div id="da-error"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end;">
        <button class="btn btn-ghost" type="button" id="modal-cancel">Cancel</button>
        <button class="btn btn-danger-solid" type="submit">Delete Account</button>
      </div>
    </form>`);
}

// ---------------------------------------------------------------------------
// Event binding — auth screens
// ---------------------------------------------------------------------------
function bindAuthEvents() {
  root.querySelectorAll('[data-toggle]').forEach((btn) => {
    btn.onclick = () => {
      const input = root.querySelector(`[name="${btn.dataset.toggle}"], #${btn.dataset.toggle}`);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      btn.textContent = input.type === 'password' ? ICON.eye : ICON.eyeOff;
    };
  });

  const loginForm = document.getElementById('login-form');
  if (loginForm) loginForm.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(loginForm);
    try {
      const res = await api('POST', '/api/auth/login', { email: fd.get('email'), password: fd.get('password') });
      state.user = res.user; state.csrfToken = res.csrfToken; state.unlocked = true; state.screen = 'app';
      state.loginAttempts = 0;
      await loadDashboardData();
      await loadAvatar(); loadRecentSearches();
      resetIdleWatch();
  startReminderPolling();
      render();
    } catch (err) {
      state.loginAttempts++;
      document.getElementById('login-error').innerHTML = `<div class="error-banner">${ICON.warn} ${err.message}</div>`;
    }
  };

  const bio = document.getElementById('login-biometric');
  if (bio) bio.onclick = () => toast('Enter your email first, then use PIN or biometrics from the lock screen after signing in once.', 'warn');
  const pinBtn = document.getElementById('login-pin');
  if (pinBtn) pinBtn.onclick = () => toast('Sign in with your master password first — PIN unlock is available afterwards from the lock screen.', 'warn');

  const goRegister = document.getElementById('go-register');
  if (goRegister) goRegister.onclick = () => { state.screen = 'register'; render(); };
  const goRecovery = document.getElementById('go-recovery');
  if (goRecovery) goRecovery.onclick = () => { state.screen = 'recovery'; state.recovery = { step: 1, email: '', code: '' }; render(); };
  const backLogin = document.getElementById('back-login');
  if (backLogin) backLogin.onclick = () => { state.screen = 'login'; render(); };

  const avatarPickBtn = document.getElementById('avatar-pick-btn');
  const avatarFileInput = document.getElementById('avatar-file-input');
  if (avatarPickBtn && avatarFileInput) {
    avatarPickBtn.onclick = () => avatarFileInput.click();
    avatarFileInput.onchange = () => {
      const file = avatarFileInput.files[0];
      if (!file) return;
      if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) { toast('Use a PNG, JPEG, or WEBP image.', 'error'); return; }
      if (file.size > 2 * 1024 * 1024) { toast('Image is too large (2MB limit).', 'error'); return; }
      const reader = new FileReader();
      reader.onload = () => {
        const dataUrl = reader.result;
        state.pendingAvatarBase64 = dataUrl.split(',')[1];
        state.pendingAvatarMime = file.type;
        const preview = document.getElementById('avatar-preview');
        if (preview) preview.innerHTML = `<img src="${dataUrl}" alt="" />`;
      };
      reader.readAsDataURL(file);
    };
  }

  const registerForm = document.getElementById('register-form');
  if (registerForm) registerForm.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(registerForm);
    if (fd.get('password') !== fd.get('confirm')) {
      document.getElementById('register-error').innerHTML = `<div class="error-banner">${ICON.warn} Passwords don't match.</div>`;
      return;
    }
    try {
      const res = await api('POST', '/api/auth/register', { name: fd.get('name'), email: fd.get('email'), password: fd.get('password'), recoveryEmail: fd.get('email') });
      state.user = res.user; state.csrfToken = res.csrfToken; state.unlocked = true;
      state.pendingRecoveryKey = res.recoveryKey;
      if (state.pendingAvatarBase64) {
        try {
          await api('POST', '/api/profile/avatar', { mimeType: state.pendingAvatarMime, dataBase64: state.pendingAvatarBase64 });
        } catch { /* non-fatal — account creation already succeeded */ }
        state.pendingAvatarBase64 = null; state.pendingAvatarMime = null;
      }
      state.screen = 'recovery-key-reveal';
      render();
    } catch (err) {
      document.getElementById('register-error').innerHTML = `<div class="error-banner">${ICON.warn} ${err.message}</div>`;
    }
  };

  const copyKey = document.getElementById('copy-recovery-key');
  if (copyKey) copyKey.onclick = () => { navigator.clipboard?.writeText(state.pendingRecoveryKey); toast('Recovery key copied'); };
  const continueBtn = document.getElementById('continue-after-recovery-key');
  if (continueBtn) continueBtn.onclick = async () => {
    state.screen = 'app'; state.active = 'dashboard';
    await loadDashboardData();
    await loadAvatar(); loadRecentSearches();
    resetIdleWatch();
  startReminderPolling();
    render();
  };

  bindRecoveryEvents();
  bindUnlockEvents();
}

function bindRecoveryEvents() {
  const sendCode = document.getElementById('rec-send-code');
  if (sendCode) sendCode.onclick = async () => {
    const email = document.getElementById('rec-email').value;
    try {
      await api('POST', '/api/recovery/request', { email });
      state.recovery = { ...state.recovery, email, step: 2 };
      render();
    } catch (err) { document.getElementById('rec-error').innerHTML = `<div class="error-banner">${err.message}</div>`; }
  };
  const verifyCode = document.getElementById('rec-verify-code');
  if (verifyCode) verifyCode.onclick = async () => {
    const code = document.getElementById('rec-code').value;
    try {
      await api('POST', '/api/recovery/verify-code', { email: state.recovery.email, code });
      state.recovery = { ...state.recovery, code, step: 3 };
      render();
    } catch (err) { document.getElementById('rec-error').innerHTML = `<div class="error-banner">${err.message}</div>`; }
  };
  const doReset = document.getElementById('rec-reset');
  if (doReset) doReset.onclick = async () => {
    const recoveryKey = document.getElementById('rec-key').value;
    const newPassword = document.getElementById('rec-newpw').value;
    try {
      await api('POST', '/api/recovery/reset', { email: state.recovery.email, code: state.recovery.code, recoveryKey, newPassword });
      toast('Master password reset. Please sign in.');
      state.screen = 'login';
      render();
    } catch (err) { document.getElementById('rec-error').innerHTML = `<div class="error-banner">${err.message}</div>`; }
  };
}

function bindUnlockEvents() {
  root.querySelectorAll('[data-key]').forEach((btn) => {
    btn.onclick = async () => {
      const k = btn.dataset.key;
      if (k === '⌫') state.pinBuffer = state.pinBuffer.slice(0, -1);
      else if (k === 'OK') return submitPin();
      else if (state.pinBuffer.length < 6) state.pinBuffer += k;
      render();
    };
  });
  const bioBtn = document.getElementById('unlock-biometric');
  if (bioBtn) bioBtn.onclick = () => tryBiometricUnlock();
  const pwInstead = document.getElementById('unlock-password-instead');
  if (pwInstead) pwInstead.onclick = () => { document.getElementById('unlock-password-form').classList.toggle('hidden'); };
  const pwSubmit = document.getElementById('unlock-password-submit');
  if (pwSubmit) pwSubmit.onclick = async () => {
    const password = document.getElementById('unlock-password').value;
    try {
      await api('POST', '/api/auth/unlock/password', { password });
      await afterUnlock();
    } catch (err) { toast(err.message, 'error'); }
  };
  const signOut = document.getElementById('unlock-signout');
  if (signOut) signOut.onclick = async () => { try { await api('POST', '/api/auth/logout', {}); } catch {} resetToLogin(); };
}

async function submitPin() {
  const pin = state.pinBuffer;
  try {
    // The server checks the duress PIN first, independent of the real
    // PIN's lockout state — see server/app.js POST /api/auth/unlock/pin.
    // A single call handles both cases; the response tells us which one.
    const res = await api('POST', '/api/auth/unlock/pin', { pin });
    state.pinBuffer = '';
    if (res.duress) { await enterDuressMode(); return; }
    await afterUnlock();
  } catch (err) {
    state.pinBuffer = '';
    document.getElementById('pin-error').textContent = err.message;
    if (err.status === 429) state.pinLockedUntil = Date.now() + 30000;
    render();
  }
}

async function tryBiometricUnlock() {
  const token = localStorage.getItem(`vx_device_token_${state.user.id}`);
  if (!token) { toast('Biometric unlock isn\'t set up on this device. Use PIN or your master password, then enable it from Settings.', 'warn'); return; }
  state.screen = 'biometric'; render();
  setTimeout(async () => {
    try {
      await api('POST', '/api/auth/unlock/device', { deviceToken: token });
      await afterUnlock();
    } catch (err) {
      toast(err.message, 'error');
      state.screen = 'unlock'; render();
    }
  }, 1100);
}

async function afterUnlock() {
  state.unlocked = true; state.duress = false; state.screen = 'app';
  await loadDashboardData();
  await loadAvatar(); loadRecentSearches();
  resetIdleWatch();
  startReminderPolling();
  render();
}

// Duress mode never calls a single real vault endpoint. state.duress gates
// dashboardScreen() to a fixed decoy render, and every nav/add/reveal action
// is disabled at the UI layer — belt-and-braces on top of the server-side
// guarantee that no VEK was ever cached for this session (see auth.js).
async function enterDuressMode() {
  state.unlocked = true; state.duress = true; state.screen = 'app'; state.active = 'dashboard';
  state.avatarDataUrl = null;
  render();
}

// ---------------------------------------------------------------------------
// Event binding — unlocked app
// ---------------------------------------------------------------------------
function bindAppEvents() {
  root.querySelectorAll('[data-nav]').forEach((el) => { el.onclick = () => navigate(el.dataset.nav); });
  const menuBtn = document.getElementById('menu-btn'); if (menuBtn) menuBtn.onclick = () => { state.mobileOpen = true; render(); };
  const scrim = document.getElementById('scrim'); if (scrim) scrim.onclick = () => { state.mobileOpen = false; render(); };
  const fab = document.getElementById('fab-add'); if (fab) fab.onclick = () => { state.modal = { type: 'add-info' }; render(); };

  const doLock = async () => { try { await api('POST', '/api/auth/lock', {}); } catch {} state.unlocked = false; state.duress = false; state.screen = 'unlock'; state.modal = null; toast('Vault locked'); render(); };
  ['lock-vault-btn', 'topbar-lock', 'lock-vault-btn-2'].forEach((id) => { const el = document.getElementById(id); if (el) el.onclick = doLock; });
  const topbarSearch = document.getElementById('topbar-search');
  if (topbarSearch) topbarSearch.onclick = openSearch;

  bindModalEvents();
  bindDashboardEvents();
  bindPasswordsEvents();
  bindPersonalEvents();
  bindNotesEvents();
  bindTabbedTypeEvents();
  bindDocumentsEvents();
  bindCustomItemsEvents();
  bindCalendarEvents();
  bindWalkingEvents();
  bindSecurityEvents();
  bindSettingsEvents();
}

function bindDashboardEvents() {
  const openBtn = document.getElementById('open-search');
  if (openBtn) openBtn.onclick = openSearch;
}

let searchRequestSeq = 0;
async function runSearch() {
  const q = state.searchQuery.trim();
  if (!q) { state.searchResults = null; state.searchEventResults = null; state.searchLoading = false; renderPreservingSearchFocus(); return; }
  const mySeq = ++searchRequestSeq;
  state.searchLoading = true;
  renderPreservingSearchFocus();
  try {
    const cat = state.searchCategory === 'all' ? '' : `&category=${encodeURIComponent(state.searchCategory)}`;
    const res = await api('GET', `/api/search?q=${encodeURIComponent(q)}${cat}`);
    if (mySeq !== searchRequestSeq) return; // a newer keystroke's request already superseded this one
    state.searchResults = res.results;
    state.searchEventResults = res.events;
    state.searchLoading = false;
    saveRecentSearch(q);
    renderPreservingSearchFocus();
  } catch (err) {
    if (mySeq !== searchRequestSeq) return;
    state.searchLoading = false;
    toast(err.message, 'error');
    renderPreservingSearchFocus();
  }
}

// A full render() rebuilds the search input from scratch, which would
// otherwise steal focus and reset the cursor to the end on every debounced
// keystroke. This captures and restores both across the rebuild.
function renderPreservingSearchFocus() {
  const input = document.getElementById('search-input');
  const wasFocused = document.activeElement === input;
  const caret = input ? input.selectionStart : null;
  render();
  if (wasFocused) {
    const next = document.getElementById('search-input');
    if (next) {
      next.focus();
      if (caret !== null) next.setSelectionRange(caret, caret);
    }
  }
}

function bindPasswordsEvents() {
  const filter = document.getElementById('pw-filter');
  if (filter) filter.oninput = () => {
    const q = filter.value.toLowerCase();
    const filtered = state.passwordItems.filter((i) => i.title.toLowerCase().includes(q) || (i.searchUsername || '').toLowerCase().includes(q));
    document.getElementById('pw-list').innerHTML = passwordListHtml(filtered);
    bindPasswordRowEvents();
  };
  ['open-add-password', 'open-add-password-2'].forEach((id) => { const el = document.getElementById(id); if (el) el.onclick = () => { state.modal = { type: 'add-password' }; render(); }; });
  bindPasswordRowEvents();
}

function bindPasswordRowEvents() {
  root.querySelectorAll('[data-reveal]').forEach((btn) => {
    btn.onclick = () => requestReveal(btn.dataset.reveal, (payload) => {
      state.revealCache[btn.dataset.reveal] = payload;
      navigate('passwords');
    }, () => {
      if (state.revealCache[btn.dataset.reveal]) { delete state.revealCache[btn.dataset.reveal]; navigate('passwords'); }
    });
  });
  root.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.onclick = () => requestReveal(btn.dataset.copy, (payload) => {
      navigator.clipboard?.writeText(payload.password || '');
      toast('Password copied to clipboard');
    });
  });
  root.querySelectorAll('[data-edit-password]').forEach((btn) => {
    btn.onclick = async () => {
      const item = await api('GET', `/api/vault/items/${btn.dataset.editPassword}`);
      state.modal = { type: 'edit-password', item: item.item };
      render();
    };
  });
  root.querySelectorAll('[data-delete-item]').forEach((btn) => {
    btn.onclick = () => { state.modal = { type: 'confirm-delete', id: btn.dataset.deleteItem, title: btn.dataset.deleteTitle }; render(); };
  });
}

async function requestReveal(itemId, onSuccess, onAlreadyRevealedToggle) {
  if (onAlreadyRevealedToggle && state.revealCache[itemId]) return onAlreadyRevealedToggle();
  if (state.duress) {
    // Decoy items' "secrets" are already plaintext locally — nothing to
    // re-authenticate against, and definitely nothing to send to a server.
    const decoyItem = [...DECOY.passwordItems, ...DECOY.noteItems].find((i) => i.id === itemId);
    if (decoyItem) onSuccess(decoyItem.payload);
    return;
  }
  state.modal = {
    type: 'reauth',
    onSubmit: async (password) => {
      const res = await api('POST', `/api/vault/items/${itemId}/reveal`, { reauth: { method: 'password', value: password } });
      onSuccess(res.item.payload);
    },
  };
  render();
}

function bindPersonalEvents() {
  const form = document.getElementById('personal-form');
  if (!form) return;
  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const payload = Object.fromEntries(PERSONAL_FIELDS.map(([k]) => [k, fd.get(k) || '']));
    payload.notes = fd.get('notes') || '';
    try {
      if (state.personalItem) {
        await api('PUT', `/api/vault/items/${state.personalItem.id}`, { payload });
      } else {
        await api('POST', '/api/vault/items', { type: 'personal', title: 'Personal Information', payload });
      }
      toast('Personal information saved');
      const detectionFields = PERSONAL_FIELDS.map(([key, label]) => ({ name: label, value: payload[key] }));
      await loadPersonal();
      render();
      await maybeSuggestReminders(detectionFields, fd.get('fullName') || 'Personal Information', state.personalItem?.id);
    } catch (err) { toast(err.message, 'error'); }
  };
}

function bindNotesEvents() {
  ['open-add-note'].forEach((id) => { const el = document.getElementById(id); if (el) el.onclick = () => { state.modal = { type: 'add-note' }; render(); }; });
  root.querySelectorAll('[data-reveal-note]').forEach((btn) => {
    btn.onclick = () => {
      const id = btn.dataset.revealNote;
      if (state.revealCache[id]) { delete state.revealCache[id]; navigate('notes'); return; }
      requestReveal(id, (payload) => { state.revealCache[id] = payload; navigate('notes'); });
    };
  });
  root.querySelectorAll('[data-edit-note]').forEach((btn) => {
    btn.onclick = async () => {
      const item = await api('GET', `/api/vault/items/${btn.dataset.editNote}`);
      state.modal = { type: 'edit-note', item: item.item };
      render();
    };
  });
  root.querySelectorAll('[data-delete-item]').forEach((btn) => {
    btn.onclick = () => { state.modal = { type: 'confirm-delete', id: btn.dataset.deleteItem, title: btn.dataset.deleteTitle }; render(); };
  });
}

function bindTabbedTypeEvents() {
  root.querySelectorAll('[data-type-tab]').forEach((btn) => {
    btn.onclick = () => {
      const key = btn.dataset.typeTab;
      if (state.active === 'developer') state.developerTab = key;
      else if (state.active === 'physical') state.physicalTab = key;
      else if (state.active === 'medical') state.medicalTab = key;
      render();
    };
  });
  root.querySelectorAll('[data-add-type]').forEach((btn) => {
    btn.onclick = () => { state.modal = { type: 'add-generic', itemType: btn.dataset.addType }; render(); };
  });
  root.querySelectorAll('[data-generic-reveal]').forEach((btn) => {
    btn.onclick = () => {
      const id = btn.dataset.genericReveal;
      if (state.revealCache[id]) { delete state.revealCache[id]; navigate(state.active); return; }
      requestReveal(id, (payload) => { state.revealCache[id] = payload; navigate(state.active); });
    };
  });
  root.querySelectorAll('[data-generic-edit]').forEach((btn) => {
    btn.onclick = async () => {
      const item = await api('GET', `/api/vault/items/${btn.dataset.genericEdit}`);
      state.modal = { type: 'edit-generic', itemType: btn.dataset.genericType, item: item.item };
      render();
    };
  });
  root.querySelectorAll('[data-open-item]').forEach((el) => {
    el.onclick = async () => {
      try {
        const res = await api('GET', `/api/vault/items/${el.dataset.openItem}`);
        state.modal = { type: 'item-detail', item: res.item };
        if (res.item.type === 'document') loadFileMetaFor(res.item.id);
        render();
      } catch (err) { toast(err.message, 'error'); }
    };
  });
  root.querySelectorAll('[data-delete-item]').forEach((btn) => {
    btn.onclick = () => { state.modal = { type: 'confirm-delete', id: btn.dataset.deleteItem, title: btn.dataset.deleteTitle }; render(); };
  });
}

function bindDocumentsEvents() {
  const openAdd = document.getElementById('open-add-document');
  if (openAdd) openAdd.onclick = () => { state.modal = { type: 'add-generic', itemType: 'document' }; render(); };
}

function bindCustomItemsEvents() {
  const openAdd = document.getElementById('open-add-custom');
  if (openAdd) openAdd.onclick = () => { state.modal = { type: 'add-custom', fields: [{ name: '', value: '', sensitive: false }] }; render(); };
}

function bindCalendarEvents() {
  const prevBtn = document.getElementById('cal-prev');
  if (prevBtn) prevBtn.onclick = async () => {
    let { year, month } = state.calendarCursor;
    month--; if (month < 0) { month = 11; year--; }
    state.calendarCursor = { year, month };
    await loadCalendar();
    render();
  };
  const nextBtn = document.getElementById('cal-next');
  if (nextBtn) nextBtn.onclick = async () => {
    let { year, month } = state.calendarCursor;
    month++; if (month > 11) { month = 0; year++; }
    state.calendarCursor = { year, month };
    await loadCalendar();
    render();
  };
  root.querySelectorAll('[data-cal-view]').forEach((btn) => {
    btn.onclick = async () => { state.calendarView = btn.dataset.calView; await loadCalendar(); render(); };
  });
  const windowSel = document.getElementById('upcoming-window');
  if (windowSel) windowSel.onchange = async () => {
    try {
      await setUpcomingWindowDays(Number(windowSel.value));
      await loadCalendar();
      render();
    } catch (err) {
      toast('Could not save your calendar preference. Please try again.', 'error');
      render();
    }
  };
  const addBtn = document.getElementById('cal-add-event');
  if (addBtn) addBtn.onclick = () => { state.modal = { type: 'add-event' }; render(); };
  root.querySelectorAll('[data-event-id]').forEach((el) => {
    el.onclick = async () => {
      try {
        const res = await api('GET', `/api/events/${el.dataset.eventId}`);
        state.modal = { type: 'edit-event', event: res.event };
        render();
      } catch (err) { toast(err.message, 'error'); }
    };
  });
}

async function loadFileMetaFor(itemId) {
  state.fileMetaCache = state.fileMetaCache || {};
  state.fileMetaCache[itemId] = undefined;
  try {
    const res = await api('GET', `/api/vault/items/${itemId}/file/meta`);
    state.fileMetaCache[itemId] = res.file;
  } catch {
    state.fileMetaCache[itemId] = null;
  }
  if (state.modal?.type === 'item-detail' && state.modal.item.id === itemId) render();
}

function bindSecurityEvents() {
  const t2fa = document.getElementById('toggle-2fa');
  if (t2fa) t2fa.onclick = async () => { await api('POST', '/api/auth/2fa', { enabled: !state.security.twoFactorEnabled }); toast('Updated'); await loadSecurity(); render(); };
  const signoutAll = document.getElementById('signout-all');
  if (signoutAll) signoutAll.onclick = async () => { await api('POST', '/api/auth/sessions/revoke-others', {}); toast('Signed out of all other devices'); await loadSecurity(); render(); };
  const healthBtn = document.getElementById('run-health-scan');
  if (healthBtn) healthBtn.onclick = async () => {
    try { const res = await api('GET', '/api/security/health'); state.health = res; render(); }
    catch (err) { toast(err.message, 'error'); }
  };
  const verifyBtn = document.getElementById('verify-chain-btn');
  if (verifyBtn) verifyBtn.onclick = async () => {
    try { state.chainStatus = await api('GET', '/api/security/activity/verify'); render(); }
    catch (err) { toast(err.message, 'error'); }
  };
}

function bindSettingsEvents() {
  root.querySelectorAll('[data-settings-tab]').forEach((btn) => { btn.onclick = () => { state.settingsTab = btn.dataset.settingsTab; render(); }; });
  const openCP = document.getElementById('open-change-password'); if (openCP) openCP.onclick = () => { state.modal = { type: 'change-password' }; render(); };
  const openPin = document.getElementById('open-change-pin'); if (openPin) openPin.onclick = () => { state.modal = { type: 'change-pin' }; render(); };
  const privacySel = document.getElementById('notif-privacy');
  if (privacySel) privacySel.onchange = () => { setNotifPrivacyLevel(privacySel.value); toast('Notification privacy updated.'); };
  const toggleNotif = document.getElementById('toggle-notifications');
  if (toggleNotif) toggleNotif.onclick = async () => {
    if (typeof Notification === 'undefined') { toast('Notifications are not supported in this browser.', 'warn'); return; }
    if (Notification.permission === 'granted') { toast('To turn notifications off, use your browser\'s site settings.', 'warn'); return; }
    try {
      await enableClosedAppNotifications();
      toast('Notifications enabled on this device.');
      startReminderPolling();
    } catch (err) {
      toast(err.message || 'Could not enable notifications.', 'warn');
    }
    render();
  };
  const toggleBio = document.getElementById('toggle-biometric');
  if (toggleBio) toggleBio.onclick = async () => {
    if (state.user.biometricEnabled) {
      await api('POST', '/api/auth/biometric/disable', {});
      localStorage.removeItem(`vx_device_token_${state.user.id}`);
      state.user.biometricEnabled = false;
      toast('Biometric unlock disabled');
    } else {
      const res = await api('POST', '/api/auth/biometric/enable', {});
      // In a native app this token would be stored in Keychain/Keystore
      // behind Face ID/Touch ID/BiometricPrompt. This browser build stores
      // it in localStorage as the closest available stand-in — see README.
      localStorage.setItem(`vx_device_token_${state.user.id}`, res.deviceToken);
      state.user.biometricEnabled = true;
      toast('Biometric unlock enabled on this device');
    }
    render();
  };
  const toggle2faSettings = document.getElementById('toggle-2fa-settings');
  if (toggle2faSettings) toggle2faSettings.onclick = async () => { await api('POST', '/api/auth/2fa', { enabled: !state.security.twoFactorEnabled }); await loadSecurity(); render(); };
  root.querySelectorAll('[data-autolock]').forEach((btn) => {
    btn.onclick = async () => { await api('POST', '/api/auth/autolock', { ms: Number(btn.dataset.autolock) }); state.user.autoLockMs = Number(btn.dataset.autolock); toast('Auto-lock updated'); render(); };
  });
  root.querySelectorAll('[data-revoke-session]').forEach((btn) => {
    btn.onclick = async () => { toast('Use "Sign Out All Other Devices" to revoke sessions in this reference build.', 'warn'); };
  });
  ['signout-all-2'].forEach((id) => { const el = document.getElementById(id); if (el) el.onclick = async () => { await api('POST', '/api/auth/sessions/revoke-others', {}); toast('Signed out of all other devices'); await loadSecurity(); render(); }; });
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) logoutBtn.onclick = async () => { try { await api('POST', '/api/auth/logout', {}); } catch {} resetToLogin(); };
  const openDelete = document.getElementById('open-delete-account');
  if (openDelete) openDelete.onclick = () => { state.modal = { type: 'delete-account' }; render(); };

  const installBtn = document.getElementById('install-app-btn');
  if (installBtn) installBtn.onclick = async () => {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    const { outcome } = await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    if (outcome === 'accepted') toast('Installing…'); else render();
  };

  const recDone = document.getElementById('recovery-done');
  if (recDone) recDone.onclick = () => { state.pendingRecoveryKey = null; state.modal = null; render(); };
  const recCopy = document.getElementById('recovery-copy');
  if (recCopy) recCopy.onclick = () => { navigator.clipboard?.writeText(state.pendingRecoveryKey || ''); toast('Recovery key copied.'); };
  const regenForm = document.getElementById('regen-recovery-form');
  if (regenForm) regenForm.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(regenForm);
    try {
      const res = await api('POST', '/api/auth/recovery-key/regenerate', { currentPassword: fd.get('currentPassword') });
      state.pendingRecoveryKey = res.recoveryKey;
      state.modal = { type: 'recovery-key-shown' };
      render();
    } catch (err) {
      document.getElementById('regen-recovery-error').innerHTML = `<div class="error-banner">${esc(err.message)}</div>`;
    }
  };
  const openInvite = document.getElementById('open-emergency-invite');
  if (openInvite) openInvite.onclick = () => { state.modal = { type: 'emergency-invite' }; render(); };
  const inviteForm = document.getElementById('emergency-invite-form');
  if (inviteForm) inviteForm.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(inviteForm);
    try {
      const res = await api('POST', '/api/emergency', { contactName: fd.get('contactName'), contactEmail: fd.get('contactEmail'), waitDays: Number(fd.get('waitDays')) });
      state.modal = { type: 'emergency-secret', name: res.contact.contactName, secret: res.secret, id: res.contact.id };
      state.emergency = [res.contact, ...(state.emergency || [])];
      render();
    } catch (err) {
      document.getElementById('emergency-invite-error').innerHTML = `<div class="error-banner">${esc(err.message)}</div>`;
    }
  };
  const emDone = document.getElementById('emergency-done');
  if (emDone) emDone.onclick = () => { state.modal = null; render(); };
  const emCopy = document.getElementById('emergency-copy');
  if (emCopy) emCopy.onclick = () => { navigator.clipboard?.writeText(location.origin + '/contact.html#id=' + state.modal?.id + '&code=' + (state.modal?.secret || '')); toast('Link copied.'); };
  root.querySelectorAll('[data-em-veto]').forEach((b) => b.onclick = async () => {
    try { await api('POST', `/api/emergency/${b.dataset.emVeto}/veto`, {}); toast('Request cancelled.'); await loadSecurity(); render(); }
    catch (err) { toast(err.message, 'error'); }
  });
  root.querySelectorAll('[data-em-revoke]').forEach((b) => b.onclick = async () => {
    try { await api('POST', `/api/emergency/${b.dataset.emRevoke}/revoke`, {}); toast('Contact removed.'); await loadSecurity(); render(); }
    catch (err) { toast(err.message, 'error'); }
  });
  const accountForm = document.getElementById('account-details-form');
  if (accountForm) accountForm.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(accountForm);
    try {
      const res = await api('PUT', '/api/auth/account-details', {
        name: fd.get('name'), email: fd.get('email'), currentPassword: fd.get('currentPassword'),
      });
      state.user = { ...state.user, ...res.user };
      toast('Account details updated.');
      render();
    } catch (err) {
      document.getElementById('account-details-error').innerHTML = `<div class="error-banner">${esc(err.message)}</div>`;
    }
  };
  const openDuress = document.getElementById('open-duress-pin');
  if (openDuress) openDuress.onclick = () => { state.modal = { type: 'duress-pin' }; render(); };
  const openExport = document.getElementById('open-export-backup');
  if (openExport) openExport.onclick = () => { state.modal = { type: 'export-backup' }; render(); };
  const openImport = document.getElementById('open-import-backup');
  if (openImport) openImport.onclick = () => { state.modal = { type: 'import-backup' }; render(); };

  const avatarPreview = document.getElementById('settings-avatar-preview');
  const avatarInput = document.getElementById('settings-avatar-input');
  const avatarPick = document.getElementById('settings-avatar-pick');
  if (avatarPick && avatarInput) {
    avatarPick.onclick = () => avatarInput.click();
    avatarInput.onchange = async () => {
      const file = avatarInput.files[0];
      if (!file) return;
      if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) { toast('Use a PNG, JPEG, or WEBP image.', 'error'); return; }
      if (file.size > 2 * 1024 * 1024) { toast('Image is too large (2MB limit).', 'error'); return; }
      const reader = new FileReader();
      reader.onload = async () => {
        try {
          await api('POST', '/api/profile/avatar', { mimeType: file.type, dataBase64: reader.result.split(',')[1] });
          state.avatarDataUrl = reader.result;
          toast('Profile picture updated');
          render();
        } catch (err) { toast(err.message, 'error'); }
      };
      reader.readAsDataURL(file);
    };
  }
  const avatarRemove = document.getElementById('settings-avatar-remove');
  if (avatarRemove) avatarRemove.onclick = async () => {
    try { await api('DELETE', '/api/profile/avatar', {}); state.avatarDataUrl = null; toast('Profile picture removed'); render(); }
    catch (err) { toast(err.message, 'error'); }
  };

  bindDuressPinFormEvents();
  bindBackupFormEvents();
}

function duressPinModal() {
  return modalShell('Set Up Duress PIN', `
    <div class="field-hint" style="margin-bottom:14px;">Entering this PIN at the lock screen looks like a completely normal unlock, but it never opens your real vault — it must be different from your regular PIN.</div>
    <form id="duress-pin-form">
      <div class="field"><label>Duress PIN (4–6 digits)</label><input name="pin" required pattern="\\d{4,6}" /></div>
      <div class="field"><label>Confirm Duress PIN</label><input name="confirm" required pattern="\\d{4,6}" /></div>
      <div id="duress-pin-error"></div>
      <button class="btn btn-primary btn-block" type="submit">Save Duress PIN</button>
    </form>
  `);
}

function bindDuressPinFormEvents() {
  const form = document.getElementById('duress-pin-form');
  if (!form) return;
  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    if (fd.get('pin') !== fd.get('confirm')) { document.getElementById('duress-pin-error').innerHTML = `<div class="error-banner">PINs don't match.</div>`; return; }
    try {
      await api('POST', '/api/auth/duress-pin', { pin: fd.get('pin') });
      toast('Duress PIN configured');
      state.modal = null; render();
    } catch (err) { document.getElementById('duress-pin-error').innerHTML = `<div class="error-banner">${err.message}</div>`; }
  };
}

function exportBackupModal() {
  return modalShell('Export Encrypted Backup', `
    <div class="field-hint" style="margin-bottom:14px;">Choose a password to protect this backup file. It's independent of your master password — use something you'll remember separately.</div>
    <form id="export-backup-form">
      <div class="field"><label>Backup Password</label><input name="exportPassword" type="password" required minlength="8" /></div>
      <div id="export-backup-error"></div>
      <button class="btn btn-primary btn-block" type="submit">${icon('copy', 15)} Download .vaultx File</button>
    </form>
  `);
}

function importBackupModal() {
  return modalShell('Import Backup', `
    <form id="import-backup-form">
      <div class="field"><label>Backup File (.vaultx)</label><input type="file" name="file" accept=".vaultx,application/json" required /></div>
      <div class="field"><label>Backup Password</label><input name="exportPassword" type="password" required /></div>
      <div id="import-backup-error"></div>
      <button class="btn btn-primary btn-block" type="submit">${icon('plus', 15)} Import</button>
    </form>
  `);
}

function bindBackupFormEvents() {
  const exportForm = document.getElementById('export-backup-form');
  if (exportForm) exportForm.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(exportForm);
    try {
      const backup = await api('POST', '/api/vault/export', { exportPassword: fd.get('exportPassword') });
      const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `vaultixgustar-backup-${new Date().toISOString().slice(0,10)}.vaultx`; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      toast('Backup downloaded');
      state.modal = null; render();
    } catch (err) { document.getElementById('export-backup-error').innerHTML = `<div class="error-banner">${err.message}</div>`; }
  };

  const importForm = document.getElementById('import-backup-form');
  if (importForm) importForm.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(importForm);
    const file = fd.get('file');
    if (!file || !file.name) { document.getElementById('import-backup-error').innerHTML = `<div class="error-banner">Choose a .vaultx file.</div>`; return; }
    try {
      const text = await file.text();
      const backup = JSON.parse(text);
      const res = await api('POST', '/api/vault/import', { exportPassword: fd.get('exportPassword'), backup });
      toast(`Imported ${res.imported} item(s)`);
      state.modal = null;
      await navigate(state.active);
    } catch (err) { document.getElementById('import-backup-error').innerHTML = `<div class="error-banner">${err.message || 'Invalid backup file.'}</div>`; }
  };
}

// ---------------------------------------------------------------------------
// Modal event binding
// ---------------------------------------------------------------------------
function bindModalEvents() {
  const scrim = document.getElementById('modal-scrim');
  if (scrim) scrim.onclick = (e) => { if (e.target === scrim) { state.modal = null; render(); } };
  const closeBtn = document.getElementById('modal-close');
  if (closeBtn) closeBtn.onclick = () => { state.modal = null; render(); };
  const cancelBtn = document.getElementById('modal-cancel');
  if (cancelBtn) cancelBtn.onclick = () => { state.modal = null; render(); };

  root.querySelectorAll('[data-pick-type]').forEach((btn) => {
    btn.onclick = () => {
      const type = btn.dataset.pickType;
      if (type === 'password') state.modal = { type: 'add-password' };
      else if (type === 'note') state.modal = { type: 'add-note' };
      else if (type === 'personal') { state.modal = null; navigate('personal'); return; }
      else if (type === 'custom-new') state.modal = { type: 'add-custom', fields: [{ name: '', value: '', sensitive: false }] };
      else if (type === 'event-new') state.modal = { type: 'add-event' };
      else state.modal = { type: 'add-generic', itemType: type };
      render();
    };
  });

  bindPasswordFormEvents();
  bindNoteFormEvents();
  bindGenericFormEvents();
  bindCustomFieldsFormEvents();
  bindEventFormEvents();
  bindReminderSuggestionEvents();
  bindReauthFormEvents();
  bindConfirmDeleteEvents();
  bindItemDetailEvents();
  bindChangePasswordFormEvents();
  bindChangePinFormEvents();
  bindDeleteAccountFormEvents();
  bindDuressPinFormEvents();
  bindBackupFormEvents();
}

function bindPasswordFormEvents() {
  const form = document.getElementById('password-form');
  if (!form) return;
  root.querySelectorAll('[data-toggle]').forEach((btn) => {
    btn.onclick = () => {
      const input = document.getElementById(btn.dataset.toggle);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      btn.textContent = input.type === 'password' ? ICON.eye : ICON.eyeOff;
    };
  });
  const toggleGen = document.getElementById('toggle-generator');
  if (toggleGen) toggleGen.onclick = async () => {
    const slot = document.getElementById('generator-slot');
    if (slot.innerHTML) { slot.innerHTML = ''; return; }
    slot.innerHTML = generatorHtml();
    bindGeneratorEvents(slot, (pw) => { document.getElementById('pw-field').value = pw; });
  };
  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const payload = { password: fd.get('password'), website: fd.get('website') || fd.get('title'), notes: fd.get('notes') };
    try {
      const editing = state.modal.type === 'edit-password';
      if (editing) {
        await api('PUT', `/api/vault/items/${state.modal.item.id}`, { title: fd.get('title'), category: fd.get('category'), searchUsername: fd.get('searchUsername'), payload });
      } else {
        await api('POST', '/api/vault/items', { type: 'password', title: fd.get('title'), category: fd.get('category'), searchUsername: fd.get('searchUsername'), payload });
      }
      toast(editing ? 'Password updated' : 'Saved securely — your information has been encrypted and stored.');
      state.modal = null;
      await navigate('passwords');
    } catch (err) { toast(err.message, 'error'); }
  };
}

function generatorHtml() {
  return `
    <div class="password-gen">
      <div class="gen-row"><div class="gen-display" id="gen-display">generating…</div><button type="button" class="btn btn-subtle" id="gen-refresh" style="padding:10px;">${icon('refresh', 16)}</button></div>
      <div class="gen-row"><span style="font-size:12.5px;">Length</span><input type="range" id="gen-length" min="8" max="32" value="16" style="flex:1;" /><span id="gen-length-val" style="font-weight:700;min-width:22px;">16</span></div>
      <div class="gen-opts">
        <label><input type="checkbox" id="gen-upper" checked /> Uppercase</label>
        <label><input type="checkbox" id="gen-lower" checked /> Lowercase</label>
        <label><input type="checkbox" id="gen-numbers" checked /> Numbers</label>
        <label><input type="checkbox" id="gen-symbols" checked /> Symbols</label>
      </div>
      <button type="button" class="btn btn-outline btn-block" id="gen-use">Use This Password</button>
    </div>`;
}

function bindGeneratorEvents(slot, onUse) {
  const opts = () => ({
    length: Number(slot.querySelector('#gen-length').value),
    upper: slot.querySelector('#gen-upper').checked,
    lower: slot.querySelector('#gen-lower').checked,
    numbers: slot.querySelector('#gen-numbers').checked,
    symbols: slot.querySelector('#gen-symbols').checked,
  });
  const regen = async () => {
    try {
      const res = await api('POST', '/api/tools/generate-password', opts());
      slot.querySelector('#gen-display').textContent = res.password;
      slot.dataset.current = res.password;
    } catch (err) { toast(err.message, 'error'); }
  };
  slot.querySelector('#gen-refresh').onclick = regen;
  slot.querySelector('#gen-length').oninput = (e) => { slot.querySelector('#gen-length-val').textContent = e.target.value; regen(); };
  ['gen-upper', 'gen-lower', 'gen-numbers', 'gen-symbols'].forEach((id) => { slot.querySelector(`#${id}`).onchange = regen; });
  slot.querySelector('#gen-use').onclick = () => onUse(slot.dataset.current || '');
  regen();
}

function bindNoteFormEvents() {
  const form = document.getElementById('note-form');
  if (!form) return;
  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    try {
      const editing = state.modal.type === 'edit-note';
      if (editing) await api('PUT', `/api/vault/items/${state.modal.item.id}`, { title: fd.get('title'), payload: { content: fd.get('content') } });
      else await api('POST', '/api/vault/items', { type: 'note', title: fd.get('title'), payload: { content: fd.get('content') } });
      toast('Note saved securely');
      state.modal = null;
      await navigate('notes');
    } catch (err) { toast(err.message, 'error'); }
  };
}

function bindGenericFormEvents() {
  const form = document.getElementById('generic-form');
  if (!form) return;
  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const type = fd.get('_type');
    const payload = {};
    for (const [k, v] of fd.entries()) if (k !== '_type' && k !== 'title') payload[k] = v;
    const previewKey = PREVIEW_FIELD[type];
    const searchUsername = previewKey ? (payload[previewKey] || '') : undefined;
    try {
      const editing = state.modal.item;
      let saved;
      if (editing) saved = await api('PUT', `/api/vault/items/${editing.id}`, { title: fd.get('title'), payload, searchUsername });
      else saved = await api('POST', '/api/vault/items', { type, title: fd.get('title'), payload, searchUsername });
      toast(editing ? 'Updated' : 'Saved securely — your information has been encrypted and stored.');
      state.modal = null;
      const configFields = FIELD_CONFIGS[type] || [];
      const detectionFields = configFields.map(([key, label]) => ({ name: label, value: payload[key] }));
      await navigate(state.active);
      await maybeSuggestReminders(detectionFields, fd.get('title'), saved.item.id);
    } catch (err) { toast(err.message, 'error'); }
  };
}

function bindReauthFormEvents() {
  const form = document.getElementById('reauth-form');
  if (!form) return;
  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    try {
      await state.modal.onSubmit(fd.get('password'));
      state.modal = null;
      render();
    } catch (err) {
      document.getElementById('reauth-error').innerHTML = `<div class="error-banner">${err.message}</div>`;
    }
  };
}

function bindConfirmDeleteEvents() {
  const confirmBtn = document.getElementById('modal-confirm');
  if (!confirmBtn || state.modal?.type !== 'confirm-delete') return;
  confirmBtn.onclick = async () => {
    try {
      await api('DELETE', `/api/vault/items/${state.modal.id}`);
      toast('Item deleted');
      delete state.revealCache[state.modal.id];
      const activeScreen = state.active;
      state.modal = null;
      await navigate(activeScreen);
    } catch (err) { toast(err.message, 'error'); }
  };
}

function bindItemDetailEvents() {
  const revealBtn = document.getElementById('detail-reveal');
  if (revealBtn) revealBtn.onclick = () => {
    const item = state.modal.item;
    requestReveal(item.id, (payload) => {
      state.revealCache[item.id] = payload;
      state.modal = { type: 'item-detail', item: { ...item, payload } };
      render();
    });
  };
  const copyBtn = document.getElementById('detail-copy');
  if (copyBtn) copyBtn.onclick = () => {
    const payload = state.revealCache[state.modal.item.id] || state.modal.item.payload;
    navigator.clipboard?.writeText(payload.password || JSON.stringify(payload));
    toast('Copied to clipboard');
  };
  const editBtn = document.getElementById('detail-edit');
  if (editBtn) editBtn.onclick = async () => {
    const type = editBtn.dataset.type;
    const item = await api('GET', `/api/vault/items/${editBtn.dataset.id}`);
    if (type === 'password') state.modal = { type: 'edit-password', item: item.item };
    else if (type === 'note') state.modal = { type: 'edit-note', item: item.item };
    else if (type === 'custom') state.modal = { type: 'edit-custom', item: item.item, fields: item.item.payload?.fields?.length ? item.item.payload.fields : [{ name: '', value: '', sensitive: false }] };
    else state.modal = { type: 'edit-generic', itemType: type, item: item.item };
    render();
  };
  const deleteBtn = document.getElementById('detail-delete');
  if (deleteBtn) deleteBtn.onclick = () => { state.modal = { type: 'confirm-delete', id: deleteBtn.dataset.id, title: deleteBtn.dataset.title }; render(); };

  const breachBtn = document.getElementById('detail-breach-check');
  if (breachBtn) breachBtn.onclick = () => checkBreach(state.modal.item);

  const shareBtn = document.getElementById('detail-share');
  if (shareBtn) shareBtn.onclick = () => { state.modal = { type: 'share-link', item: state.modal.item, step: 'options' }; render(); };

  const attachBtn = document.getElementById('attach-file-btn');
  if (attachBtn) attachBtn.onclick = () => { state.modal = { type: 'file-upload', itemId: attachBtn.dataset.itemId }; render(); };

  const downloadBtn = document.getElementById('download-file-btn');
  if (downloadBtn) downloadBtn.onclick = async () => {
    try {
      const res = await api('GET', `/api/vault/items/${downloadBtn.dataset.itemId}/file`);
      const bytes = Uint8Array.from(atob(res.dataBase64), (c) => c.charCodeAt(0));
      const blob = new Blob([bytes], { type: res.mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = res.fileName; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    } catch (err) { toast(err.message, 'error'); }
  };
  const removeFileBtn = document.getElementById('remove-file-btn');
  if (removeFileBtn) removeFileBtn.onclick = async () => {
    try {
      await api('DELETE', `/api/vault/items/${removeFileBtn.dataset.itemId}/file`);
      state.fileMetaCache[removeFileBtn.dataset.itemId] = null;
      toast('File removed');
      render();
    } catch (err) { toast(err.message, 'error'); }
  };

  bindFileUploadFormEvents();
  bindShareLinkEvents();
}

function fileUploadModal(m) {
  return modalShell('Attach File', `
    <div class="field-hint" style="margin-bottom:12px;">PDF, PNG, JPEG, or WEBP — 6MB maximum. The file is encrypted (AES-256-GCM) before it's stored.</div>
    <input type="file" id="file-upload-input" accept="application/pdf,image/png,image/jpeg,image/webp" />
    <div id="file-upload-error" style="margin-top:10px;"></div>
    <button class="btn btn-primary btn-block" id="file-upload-submit" style="margin-top:14px;" disabled>${icon('plus', 15)} Upload &amp; Encrypt</button>
  `);
}

function bindFileUploadFormEvents() {
  const input = document.getElementById('file-upload-input');
  const submitBtn = document.getElementById('file-upload-submit');
  if (!input || !submitBtn) return;
  let picked = null;
  input.onchange = () => {
    const file = input.files[0];
    if (!file) return;
    if (file.size > 6 * 1024 * 1024) { document.getElementById('file-upload-error').innerHTML = `<div class="error-banner">${ICON.warn} File is too large (6MB limit).</div>`; return; }
    picked = file;
    submitBtn.disabled = false;
  };
  submitBtn.onclick = async () => {
    if (!picked) return;
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        await api('POST', `/api/vault/items/${state.modal.itemId}/file`, {
          fileName: picked.name, mimeType: picked.type, dataBase64: reader.result.split(',')[1],
        });
        toast('File encrypted and attached');
        const itemId = state.modal.itemId;
        const item = await api('GET', `/api/vault/items/${itemId}`);
        state.modal = { type: 'item-detail', item: item.item };
        await loadFileMetaFor(itemId);
      } catch (err) {
        document.getElementById('file-upload-error').innerHTML = `<div class="error-banner">${ICON.warn} ${err.message}</div>`;
      }
    };
    reader.readAsDataURL(picked);
  };
}

// ---------------------------------------------------------------------------
// Have I Been Pwned breach check — real k-anonymity implementation.
//
// The password is hashed (SHA-1, per HIBP's documented protocol) entirely
// client-side via the browser's built-in Web Crypto API. Only the first 5
// hex characters of that hash ever leave the browser — never the password,
// never the full hash, and HIBP's API is designed so those 5 characters
// alone can't be reversed to the password. This server is never involved
// at all. It cannot be exercised from this sandbox (no outbound network
// access here) — see README "Breach monitoring" for how to verify it once
// deployed somewhere with normal internet access.
// ---------------------------------------------------------------------------
async function checkBreach(item) {
  const password = (state.revealCache[item.id] || item.payload || {}).password;
  if (!password) { toast('Reveal the password first.', 'warn'); return; }
  state.modal = { type: 'breach-result', status: 'checking' };
  render();
  try {
    const bytes = new TextEncoder().encode(password);
    const digest = await crypto.subtle.digest('SHA-1', bytes);
    const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const prefix = hex.slice(0, 5);
    const suffix = hex.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) throw new Error(`HIBP responded with ${res.status}`);
    const text = await res.text();
    const match = text.split('\n').map((l) => l.trim().split(':')).find(([s]) => s === suffix);
    state.modal = { type: 'breach-result', status: 'done', count: match ? Number(match[1]) : 0 };
  } catch (err) {
    state.modal = { type: 'breach-result', status: 'error', error: err.message };
  }
  render();
}

function breachResultModal(m) {
  let body;
  if (m.status === 'checking') {
    body = `<div style="text-align:center;padding:20px 0;color:var(--text-muted);">Checking against known breaches…</div>`;
  } else if (m.status === 'error') {
    body = `<div class="error-banner">${ICON.warn} Couldn't reach the breach-check service (${m.error}). This requires outbound internet access from your browser.</div>`;
  } else if (m.count > 0) {
    body = `<div class="rec-tip warn" style="margin:0;">${ICON.warn} This password has appeared in ${m.count.toLocaleString()} known data breaches. Change it as soon as possible.</div>`;
  } else {
    body = `<div class="rec-tip success" style="margin:0;">${ICON.check} Not found in any known breach data set.</div>`;
  }
  return modalShell('Breach Check', body + `<div class="field-hint" style="margin-top:12px;">Only the first 5 characters of this password's SHA-1 hash were ever sent, per HaveIBeenPwned's k-anonymity model — the password itself never left your browser.</div>`);
}

// ---------------------------------------------------------------------------
// Self-destructing share links — the AES key is generated and lives only in
// the browser and the resulting URL fragment (after #), which browsers
// never transmit in HTTP requests. The server only ever receives ciphertext.
// ---------------------------------------------------------------------------
function shareLinkModal(m) {
  if (m.step === 'options') {
    return modalShell('Create Share Link', `
      <div class="field"><label>Expires After</label>
        <select id="share-ttl"><option value="3600000">1 hour</option><option value="86400000" selected>1 day</option><option value="604800000">7 days</option></select>
      </div>
      <div class="field"><label>Maximum Uses</label>
        <select id="share-uses"><option value="1" selected>1 (self-destructs after first view)</option><option value="3">3</option><option value="10">10</option></select>
      </div>
      <div class="field-hint" style="margin-bottom:14px;">The decryption key never reaches this server — it's generated in your browser and embedded only in the link itself.</div>
      <button class="btn btn-primary btn-block" id="share-create-btn">${icon('key', 15)} Create Link</button>
    `);
  }
  if (m.step === 'result') {
    return modalShell('Share Link Ready', `
      <div class="field-hint" style="margin-bottom:10px;">Anyone with this link can view this item until it expires or its use limit is reached. Treat it like the secret itself.</div>
      <textarea readonly rows="3" style="width:100%;font-family:monospace;font-size:11.5px;padding:10px;border-radius:8px;border:1px solid var(--border);" onclick="this.select()">${m.url}</textarea>
      <button class="btn btn-outline btn-block" id="share-copy-btn" style="margin-top:10px;">${ICON.copy} Copy Link</button>
    `);
  }
  return '';
}

async function bindShareLinkEvents() {
  const createBtn = document.getElementById('share-create-btn');
  if (createBtn) createBtn.onclick = async () => {
    const item = state.modal.item;
    const payload = state.revealCache[item.id] || item.payload;
    const ttlMs = Number(document.getElementById('share-ttl').value);
    const maxUses = Number(document.getElementById('share-uses').value);
    try {
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = new TextEncoder().encode(JSON.stringify({ title: item.title, type: item.type, payload }));
      const ciphertextBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
      const ciphertextBytes = new Uint8Array(ciphertextBuf);
      // WebCrypto appends the GCM tag to the ciphertext; split the last 16 bytes off to match our server's {ciphertext, tag} shape.
      const tag = ciphertextBytes.slice(-16);
      const cipherOnly = ciphertextBytes.slice(0, -16);
      const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));

      const res = await api('POST', `/api/vault/items/${item.id}/share`, {
        ciphertext: bytesToBase64(cipherOnly), iv: bytesToBase64(iv), tag: bytesToBase64(tag), maxUses, ttlMs,
      });
      const url = `${location.origin}/share.html#id=${res.id}&key=${bytesToBase64Url(rawKey)}&iv=${bytesToBase64Url(iv)}`;
      state.modal = { type: 'share-link', item, step: 'result', url };
      render();
    } catch (err) { toast(err.message, 'error'); }
  };
  const copyBtn = document.getElementById('share-copy-btn');
  if (copyBtn) copyBtn.onclick = () => { navigator.clipboard?.writeText(state.modal.url); toast('Link copied'); };
}

function bytesToBase64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function bytesToBase64Url(bytes) { return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

function bindChangePasswordFormEvents() {
  const form = document.getElementById('change-password-form');
  if (!form) return;
  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    if (fd.get('newPassword') !== fd.get('confirm')) { document.getElementById('cp-error').innerHTML = `<div class="error-banner">Passwords don't match.</div>`; return; }
    try {
      await api('POST', '/api/auth/change-password', { currentPassword: fd.get('currentPassword'), newPassword: fd.get('newPassword') });
      toast('Master password changed');
      state.modal = null; render();
    } catch (err) { document.getElementById('cp-error').innerHTML = `<div class="error-banner">${err.message}</div>`; }
  };
}

function bindChangePinFormEvents() {
  const form = document.getElementById('change-pin-form');
  if (!form) return;
  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    if (fd.get('pin') !== fd.get('confirm')) { document.getElementById('pin-modal-error').innerHTML = `<div class="error-banner">PINs don't match.</div>`; return; }
    try {
      await api('POST', '/api/auth/pin', { pin: fd.get('pin') });
      state.user.hasPin = true;
      toast('PIN updated');
      state.modal = null; render();
    } catch (err) { document.getElementById('pin-modal-error').innerHTML = `<div class="error-banner">${err.message}</div>`; }
  };
}

function bindDeleteAccountFormEvents() {
  const form = document.getElementById('delete-account-form');
  if (!form) return;
  form.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    try {
      await api('DELETE', '/api/auth/account', { confirmText: fd.get('confirmText'), password: fd.get('password') });
      toast('Account deleted');
      resetToLogin();
    } catch (err) { document.getElementById('da-error').innerHTML = `<div class="error-banner">${err.message}</div>`; }
  };
}
