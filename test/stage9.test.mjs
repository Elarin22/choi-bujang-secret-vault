import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { detect } from '../src/detect.mjs';
const events = (count, subject = 'practice_a', spacing = 2000) => Array.from({ length: count }, (_, i) => ({
  at: new Date(1700000000000 + i * spacing).toISOString(), method: 'GET', identity: { sub: subject },
}));

test('sliding-window count is strictly over 120, per subject, order-independent and input preserving', () => {
  const input = events(121).reverse(), before = structuredClone(input);
  assert.deepEqual(detect(events(120)), { action: 'observe' });
  assert.deepEqual(detect(input), { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'practice_a' });
  assert.deepEqual(input, before);
  assert.deepEqual(detect([...events(100), ...events(100, 'practice_b')]), { action: 'observe' });
  assert.deepEqual(detect(events(200, 'practice_a', 7000)), { action: 'observe' });
  assert.deepEqual(detect(events(200).map(e => ({ ...e, method: 'PUT' }))), { action: 'observe' });
});

test('invalid batch and extra secret/device data reject without an action or input logging', () => {
  for (const value of [null, {}, [{ ...events(1)[0], at: 'invalid' }],
    [{ ...events(1)[0], token: 'untrusted' }], [{ ...events(1)[0], identity: { sub: 'practice_a', device: 'extra' } }]]) {
    assert.throws(() => detect(value), { name: 'TypeError', message: 'invalid_detection_events' });
  }
});

test('detection executes independently and chooses a stable first proposal', async () => {
  const source = await readFile(new URL('../src/detect.mjs', import.meta.url), 'utf8');
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  assert.deepEqual(isolated.detect([...events(121, 'practice_b'), ...events(121, 'practice_a')]),
    { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'practice_a' });
});
