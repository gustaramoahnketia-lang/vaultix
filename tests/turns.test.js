// SYNTHETIC routes only, generated in code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { routeTurns, turnSummary } from '../server/route.js';
import { initialState, applyGps } from '../server/movement.js';

const LAT0 = 5.6037, LNG0 = -0.1870, M = 111320;
const north = (m) => LAT0 + m / M;
const east = (m) => LNG0 + m / (M * Math.cos(LAT0 * Math.PI / 180));

test('a route north, then east, then north is one right turn and one left turn', () => {
  const pts = [
    [LAT0, LNG0, 0, 5],
    [north(20), LNG0, 10000, 5],
    [north(20), east(20), 20000, 5],   // east: right turn
    [north(40), east(20), 30000, 5],   // north: left turn
  ];
  const s = turnSummary(pts);
  assert.equal(s.right, 1);
  assert.equal(s.left, 1);
  assert.equal(s.reversal, 0);
});

test('inaccurate fixes are ignored, so a bad fix cannot create a turn', () => {
  const clean = [[LAT0, LNG0, 0, 5], [north(20), LNG0, 10000, 5], [north(40), LNG0, 20000, 5]];
  const withBad = [...clean.slice(0, 1), [north(20), east(30), 10000, 40], ...clean.slice(1)];
  assert.equal(turnSummary(withBad).total, 0, 'a 40 m accuracy fix in the middle must not produce a turn');
  assert.equal(turnSummary(clean).total, 0, 'a straight route has no turns');
});

test('points without an accuracy value are still used (older saved walks)', () => {
  const pts = [[LAT0, LNG0, 0], [north(20), LNG0, 10000], [north(20), east(20), 20000]];
  assert.equal(turnSummary(pts).right, 1);
});

test('the engine stores accuracy with each accepted route point', () => {
  let st = initialState();
  st = applyGps(st, [LAT0, LNG0, 1_000_000, 7]);
  assert.equal(st.points[0].length, 4);
  assert.equal(st.points[0][3], 7);
});

test('a turn needs two segments of at least 8 m, so GPS jitter creates none', () => {
  const pts = [];
  for (let i = 0; i < 12; i++) pts.push([north((i % 2) * 3), east((i % 3) * 3), i * 5000, 5]);
  assert.equal(turnSummary(pts).total, 0);
});

test('walking pace (fixes about 7 m apart) still produces a right turn', () => {
  const pts = [];
  let n = 0, e = 0;
  for (let i = 0; i < 20; i++) {
    if (i < 10) n += 7; else e += 7;
    pts.push([north(n), east(e), i * 5000, 5]);
  }
  assert.equal(turnSummary(pts).right, 1, 'a 7 m-per-fix walk must still show its turn');
});
