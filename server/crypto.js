// server/crypto.js
//
// All cryptographic primitives for VAULTIXgusTAR live here, and nowhere else.
// Every other module treats this file as the only place that touches keys.
//
// KDF NOTE (read this before assuming Argon2id is running):
// The brief asks for Argon2id. Argon2id itself is not in Node's standard
// library — the real `argon2` npm package binds to a native (C) module,
// and this sandbox has no network access to install it. Rather than fake
// an Argon2id call, this file uses Node's built-in `crypto.scrypt`, which
// is also a memory-hard, GPU/ASIC-resistant password KDF and is what
// Argon2id was designed to improve on — a legitimate, honestly-labelled
// substitute, not a silent downgrade to something like plain SHA-256/MD5.
// Swapping in real Argon2id in a networked environment is a one-file change
// (see README "Swapping in real Argon2id").

import crypto from 'node:crypto';

const SCRYPT_N = 2 ** 15; // CPU/memory cost factor (32768) — tuned for interactive login latency
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32; // 256-bit keys throughout

// Optional server-side "pepper": a secret held only in the environment
// (never in the database), appended to every low-entropy secret before it's
// hashed or used to derive a key. If the database is ever stolen but the
// app's environment is not, offline cracking of password/PIN hashes still
// requires the pepper. Unset in local dev — see .env.example.
function pepper() {
  return process.env.VAULTIX_KEY_PEPPER || '';
}

export function randomBytes(n) {
  return crypto.randomBytes(n);
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function scrypt(secret, salt, keylen = KEY_LEN) {
  return crypto.scryptSync(Buffer.from(secret + pepper(), 'utf8'), salt, keylen, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });
}

/** Derive a key from a low-entropy secret (master password, PIN, recovery key) + salt. */
export function deriveKey(secret, salt) {
  return scrypt(secret, salt, KEY_LEN);
}

/**
 * Create a storable, self-describing verifier for an authentication secret
 * (master password / PIN). Encodes algorithm + parameters + salt + hash so
 * parameters can change later without breaking existing users.
 */
export function hashSecret(secret) {
  const salt = randomBytes(16);
  const hash = scrypt(secret, salt, 32);
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export function verifySecret(secret, encoded) {
  if (!encoded) return false;
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltHex, hashHex] = parts;
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(Buffer.from(secret + pepper(), 'utf8'), salt, expected.length, {
    N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024,
  });
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

/** AES-256-GCM encrypt arbitrary JSON with a 32-byte key. Fresh random 96-bit IV every call. */
export function encryptJSON(obj, key) {
  const iv = randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, iv, tag };
}

/** Throws if the ciphertext/tag were tampered with (GCM authentication failure). */
export function decryptJSON({ ciphertext, iv, tag }, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

/** AES-256-GCM encrypt a raw Buffer (files) — same primitive as encryptJSON, no JSON wrapping. */
export function encryptRaw(buf, key) {
  const iv = randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, iv, tag };
}

export function decryptRaw({ ciphertext, iv, tag }, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Wrap (encrypt) a raw key — used to store the Vault Encryption Key under a KEK. */
export function wrapKey(rawKey, kek) {
  const iv = randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const ciphertext = Buffer.concat([cipher.update(rawKey), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, iv, tag };
}

export function unwrapKey({ ciphertext, iv, tag }, kek) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function newVaultKey() {
  return randomBytes(32);
}

export function passwordStrength(pw = '') {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'];
  return { score, label: labels[score] };
}

export function generatePassword({ length = 16, upper = true, lower = true, numbers = true, symbols = true }) {
  const sets = [];
  if (upper) sets.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if (lower) sets.push('abcdefghijkmnpqrstuvwxyz');
  if (numbers) sets.push('23456789');
  if (symbols) sets.push('!@#$%^&*()-_=+[]{}');
  if (sets.length === 0) sets.push('abcdefghijkmnpqrstuvwxyz23456789');
  const all = sets.join('');
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += all[bytes[i] % all.length];
  return out;
}

export function recoveryKeyPlain() {
  // Format: XXXX-XXXX-XXXX-XXXX using an unambiguous alphabet (no 0/O/1/I).
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = randomBytes(16);
  let out = [];
  for (let g = 0; g < 4; g++) {
    let group = '';
    for (let i = 0; i < 4; i++) group += alphabet[bytes[g * 4 + i] % alphabet.length];
    out.push(group);
  }
  return out.join('-');
}
