import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkDetection } from '../scripts/detect-test.mjs';
import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1);
const reads = (count, { gap = 2, sub = 'learner_fixture', start = START, method = 'GET' } = {}) => Array.from({ length: count }, (_, i) => ({
  at: new Date(start + i * gap * 1000).toISOString(), method, identity: { sub },
}));

test('detect: practice contract cases all pass', async () => {
  const results = await checkDetection(detect);
  assert.equal(results.length, 6);
  assert.ok(results.every((r) => r.passed));
});

test('detect: only the burst user is proposed; normal subjects stay observed; output has only three keys', () => {
  const mixed = [...reads(100, { sub: 'normal_fixture' }), ...reads(125, { sub: 'burst_fixture' })].sort((a, b) => a.at.localeCompare(b.at));
  const out = detect(mixed);
  assert.deepEqual(out, { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'burst_fixture' });
  assert.deepEqual(detect(reads(100, { sub: 'normal_fixture' })), { action: 'observe' });
});

test('detect: window edges, unsorted input, non-GET and malformed events', () => {
  assert.equal(detect(reads(120)).action, 'observe');
  assert.equal(detect(reads(121)).action, 'propose_revocation');
  assert.equal(detect([...reads(121)].reverse()).action, 'propose_revocation');
  // 121 events with the first one exactly 10 minutes before the other 120: not one window
  const edge = [...reads(1, { start: START - 600000 }), ...reads(120)];
  assert.equal(detect(edge).action, 'observe');
  assert.equal(detect(reads(200, { method: 'POST' })).action, 'observe');
  const junk = [null, 1, 'x', {}, { at: 'nope', method: 'GET', identity: { sub: 'a' } }, { at: reads(1)[0].at, method: 'GET', identity: {} }];
  assert.equal(detect([...junk, ...reads(30)]).action, 'observe');
  assert.throws(() => detect('nope'), /invalid_detection_events/u);
});

test('detect: never echoes extra fields such as notes, tokens or names', () => {
  const noisy = reads(130).map((e) => ({ ...e, body: 'SECRET_NOTE', token: 'tok', name: '실명' }));
  const text = JSON.stringify(detect(noisy));
  assert.ok(!/SECRET_NOTE|tok|실명/u.test(text));
});
