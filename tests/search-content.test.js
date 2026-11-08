import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, makeClient } from './helpers.js';

let ctx, user;
before(async () => {
  ctx = await startTestServer();
  user = makeClient(ctx.baseUrl);
  await user.post('/api/auth/register', { name: 'Search Tester', email: 'searchtester@example.com', password: 'SearchTest9!', recoveryEmail: 'searchtester@example.com' });
});
after(async () => { await ctx.close(); ctx.cleanup(); });

// The exact scenario from the spec: a "Personal Information" entry whose
// heading doesn't mention any of its actual field values.
test('field VALUES inside an entry are searchable, not just the heading', async () => {
  await user.post('/api/vault/items', {
    type: 'personal', title: 'Personal Information',
    payload: { fullName: 'Gustar', dob: '15/05/2000', nationality: 'Ghanaian', phone: '0551234567', email: 'example@email.com' },
  });

  const byFullDobField = await user.get('/api/search?q=Date%20of%20Birth');
  assert.ok(byFullDobField.body.results.some((r) => r.title === 'Personal Information'), 'searching the field LABEL "Date of Birth" should find the entry even though its JSON key is "dob"');

  const byValue = await user.get('/api/search?q=15%2F05%2F2000');
  assert.ok(byValue.body.results.some((r) => r.title === 'Personal Information'), 'searching the exact DOB value should find the entry');

  const byName = await user.get('/api/search?q=Gustar');
  assert.ok(byName.body.results.some((r) => r.title === 'Personal Information'), 'searching a field value (the name) should find the entry');

  const byNationality = await user.get('/api/search?q=Ghana');
  assert.ok(byNationality.body.results.some((r) => r.title === 'Personal Information'), 'partial match on a field value should find the entry');

  const byPhone = await user.get('/api/search?q=0551234567');
  assert.ok(byPhone.body.results.some((r) => r.title === 'Personal Information'), 'searching a phone number value should find the entry');
});

test('field NAMES are searchable — "birth" and "phone" find the field by name even without knowing the value', async () => {
  await user.post('/api/vault/items', {
    type: 'personal', title: 'My Personal Info',
    payload: { fullName: 'Akwasi', dateOfBirth: '01/01/1999', phoneNumber: '0209876543' },
  });

  const byBirth = await user.get('/api/search?q=birth');
  assert.ok(byBirth.body.results.some((r) => r.title === 'My Personal Info'));

  const byPhone = await user.get('/api/search?q=phone');
  assert.ok(byPhone.body.results.some((r) => r.title === 'My Personal Info'));
});

test('a case-insensitive, multi-word heading search finds the entry regardless of how the user originally named things', async () => {
  await user.post('/api/vault/items', {
    type: 'custom', title: 'My University Account',
    payload: { fields: [
      { name: 'Email', value: 'student@example.com', sensitive: false },
      { name: 'Username', value: 'gustar123', sensitive: false },
      { name: 'Password', value: 'Sup3rSecretPW!', sensitive: true },
      { name: 'Institution', value: 'Sunyani Technical University', sensitive: false },
    ] },
  });

  for (const q of ['University', 'university', 'STUDENT@EXAMPLE.COM', 'gustar123', 'Sunyani', 'My University Account']) {
    const res = await user.get(`/api/search?q=${encodeURIComponent(q)}`);
    assert.ok(res.body.results.some((r) => r.title === 'My University Account'), `query "${q}" should find "My University Account"`);
  }
});

test('sensitive field values never appear in search-result previews, even though they still count as a match', async () => {
  await user.post('/api/vault/items', {
    type: 'custom', title: 'Secret Club Membership',
    payload: { fields: [{ name: 'Membership Code', value: 'ULTRA-SECRET-1234', sensitive: true }] },
  });

  const res = await user.get('/api/search?q=ULTRA-SECRET-1234');
  const hit = res.body.results.find((r) => r.title === 'Secret Club Membership');
  assert.ok(hit, 'a sensitive field value should still be matchable');
  assert.equal(hit.matchedExcerpt, null, 'the sensitive value itself must never be echoed back in the result');
  assert.equal(hit.matchedSensitive, true);
});

test('leading/trailing whitespace and punctuation variations in the query are tolerated', async () => {
  await user.post('/api/vault/items', { type: 'password', title: 'Test Site', payload: { password: 'x' }, searchUsername: 'user@site.com' });
  const padded = await user.get('/api/search?q=%20%20Test%20Site%20%20');
  assert.ok(padded.body.results.some((r) => r.title === 'Test Site'));
});

test('no-result search returns an empty array, not an error', async () => {
  const res = await user.get('/api/search?q=zzz-definitely-not-anywhere-zzz');
  assert.equal(res.status, 200);
  assert.equal(res.body.count, 0);
  assert.deepEqual(res.body.results, []);
});

test('search requires an unlocked vault, and never returns another user\'s content matches', async () => {
  const other = makeClient(ctx.baseUrl);
  await other.post('/api/auth/register', { name: 'Other Searcher', email: 'othersearcher@example.com', password: 'OtherSearch9!', recoveryEmail: 'othersearcher@example.com' });
  await other.post('/api/vault/items', { type: 'personal', title: 'Other Persons Info', payload: { fullName: 'ShouldNotLeak', dob: '01/01/1990' } });

  const leaked = await user.get('/api/search?q=ShouldNotLeak');
  assert.equal(leaked.body.count, 0);

  await user.post('/api/auth/lock', {});
  const lockedSearch = await user.get('/api/search?q=Gustar');
  assert.equal(lockedSearch.status, 423);
  await user.post('/api/auth/unlock/password', { password: 'SearchTest9!' });
});

test('a custom field literally named "Password" is treated as sensitive even if the client claims it isn\'t (defense in depth, not just client trust)', async () => {
  // Simulates exactly the bug that was caught and fixed: a user creates a
  // custom field named "Password" but the client-supplied sensitive flag
  // is false — the server must not trust that.
  await user.post('/api/vault/items', {
    type: 'custom', title: 'My University Account 2',
    payload: { fields: [
      { name: 'Password', value: 'ShouldNeverAppearInSearch!', sensitive: false },
      { name: 'PIN', value: '4471', sensitive: false },
      { name: 'Favorite Color', value: 'Blue', sensitive: false },
    ] },
  });

  const pwSearch = await user.get('/api/search?q=ShouldNeverAppearInSearch!');
  const pwHit = pwSearch.body.results.find((r) => r.title === 'My University Account 2');
  assert.ok(pwHit, 'the value should still be matchable');
  assert.equal(pwHit.matchedExcerpt, null, 'a field named "Password" must never echo its value, regardless of the client-supplied sensitive flag');
  assert.equal(pwHit.matchedSensitive, true);

  const pinSearch = await user.get('/api/search?q=4471');
  const pinHit = pinSearch.body.results.find((r) => r.title === 'My University Account 2');
  assert.equal(pinHit.matchedExcerpt, null, 'a field named "PIN" must also be auto-treated as sensitive');

  // A genuinely non-sensitive field should NOT be masked.
  const colorSearch = await user.get('/api/search?q=Blue');
  const colorHit = colorSearch.body.results.find((r) => r.title === 'My University Account 2');
  assert.equal(colorHit.matchedExcerpt, 'Blue', 'an ordinary field should not be over-masked');
});
