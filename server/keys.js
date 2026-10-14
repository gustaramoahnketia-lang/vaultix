// server/keys.js
//
// The password pepper decides whether every account can be opened, so it must
// never change silently. It is resolved once at start-up:
//   1. VAULTIX_KEY_PEPPER in .env, if it's a real value (placeholders are ignored).
//   2. Otherwise the value saved the first time the app ran, in <data folder>/keys.json.
//   3. If neither exists and accounts already exist, they were created before a
//      pepper was used, so the empty pepper is kept for them.
// If .env holds a different pepper from the one this vault was created with, the
// app refuses to start. Changing it would lock every account.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DATA_DIR, db } from './db.js';
import { setActivePepper } from './crypto.js';

const FILE = path.join(DATA_DIR, 'keys.json');
const fingerprint = (p) => crypto.createHash('sha256').update('vaultix-pepper:' + p).digest('hex');
const isPlaceholder = (v) => !v || /^\s*replace-with/i.test(v);

function resolvePepper() {
  const env = process.env.VAULTIX_KEY_PEPPER;
  const fromEnv = isPlaceholder(env) ? null : env.trim();
  const stored = fs.existsSync(FILE) ? JSON.parse(fs.readFileSync(FILE, 'utf8')) : null;

  if (fromEnv !== null) {
    if (stored && stored.fingerprint !== fingerprint(fromEnv)) {
      throw new Error('VAULTIX_KEY_PEPPER in .env does not match the key this vault was created with. Put the original value back. Changing it would lock every account, so the app will not start.');
    }
    return { pepper: fromEnv, stored };
  }
  if (stored) return { pepper: stored.pepper, stored };

  const hasAccounts = db.prepare('SELECT COUNT(*) AS n FROM users').get().n > 0;
  // Accounts from before the pepper was saved were created with an empty pepper.
  return { pepper: hasAccounts ? '' : crypto.randomBytes(32).toString('hex'), stored: null };
}

const { pepper, stored } = resolvePepper();
if (!stored) {
  fs.writeFileSync(FILE, JSON.stringify({ pepper, fingerprint: fingerprint(pepper), savedAt: new Date().toISOString() }), { mode: 0o600 });
}
setActivePepper(pepper);
