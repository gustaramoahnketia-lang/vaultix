import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Simulates the update problem: the account is created by one run of the app,
// and then the app is started again from separate processes, with and without
// the .env pepper. Each process is a fresh start, like reopening the app after
// an update.
const script = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'account-step.mjs');
const EMAIL = 'update-test@example.com';
const PASS = 'UpdateTest9!';

function step(action, dir, pepperEnv) {
  const env = { ...process.env, VAULTIX_DATA_DIR: dir };
  delete env.VAULTIX_KEY_PEPPER;
  if (pepperEnv !== undefined) env.VAULTIX_KEY_PEPPER = pepperEnv;
  return spawnSync(process.execPath, [script, action, EMAIL, PASS], { env, encoding: 'utf8' });
}

test('an account survives restarts with no .env pepper, and the saved pepper is used', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultix-upd-'));
  const reg = step('register', dir);
  assert.equal(reg.status, 0, reg.stderr);
  const again = step('login', dir);
  assert.equal(again.status, 0, `the same account must sign in after a restart: ${again.stderr}`);
  assert.match(again.stdout, /signed in as update-test@example.com/);
  assert.ok(fs.existsSync(path.join(dir, 'keys.json')), 'the pepper must be saved in the data folder');
  assert.ok(fs.existsSync(path.join(dir, 'vaultix.db')), 'the database must be in the data folder');
});

test('a placeholder pepper left in .env (from the old example file) is ignored, so accounts still open', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultix-upd-'));
  assert.equal(step('register', dir).status, 0);
  const res = step('login', dir, 'replace-with-a-long-random-value-and-never-commit-it');
  assert.equal(res.status, 0, `a placeholder must not break sign-in: ${res.stderr}`);
});

test('a different real pepper in .env stops the app from starting, instead of locking accounts', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultix-upd-'));
  assert.equal(step('register', dir).status, 0);
  const res = step('login', dir, 'a-different-real-pepper-value-1234567890');
  assert.notEqual(res.status, 0, 'a changed pepper must refuse to start');
  assert.match(res.stderr, /does not match the key this vault was created with/);
});

test('a wrong password is still refused after the restart', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultix-upd-'));
  assert.equal(step('register', dir).status, 0);
  const res = spawnSync(process.execPath, [script, 'login', EMAIL, 'WrongPass9!'], {
    env: { ...process.env, VAULTIX_DATA_DIR: dir }, encoding: 'utf8',
  });
  assert.notEqual(res.status, 0);
});
