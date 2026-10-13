import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkDecider } from '../scripts/decider-test.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { RULE_IDS, decide } from '../src/decider.mjs';

test('device_registered: registered device allowed, unregistered or missing value denied', async () => {
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required']);
  const results = await checkDecider({ decide, ruleIds: RULE_IDS });
  assert.ok(results.length >= 2 && results.every((r) => r.passed));
  const { normal } = fixtureRequests();
  const { deviceRegistered, ...missing } = normal;
  for (const request of [{ ...normal, deviceRegistered: false }, missing, { ...normal, deviceRegistered: 'true' }]) {
    const out = await decide(request);
    assert.equal(out.decision, 'deny');
    assert.equal(out.reasonCode, 'device_not_registered');
    assert.deepEqual(out.ruleIds, ['device_registered']);
    assert.deepEqual(Object.keys(out).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  }
  assert.equal((await decide(normal)).decision, 'allow');
});

test('step_up_required: only the combined unusual event asks again; region alone, unknown or forged signals do not', async () => {
  const { RULE_IDS: ids, decide: d, describeRisk } = await import('../src/decider.mjs');
  assert.ok(ids.includes('step_up_required'));
  const { normal, suspicious } = fixtureRequests();
  const results = await checkDecider({ decide: d, ruleIds: ids });
  assert.equal(results.length, 4);
  assert.ok(results.every((r) => r.passed));
  assert.equal((await d(normal)).decision, 'allow');
  const asked = await d(suspicious);
  assert.deepEqual([asked.decision, asked.reasonCode], ['step_up', 'step_up_required']);
  assert.ok(describeRisk(suspicious).reasons.includes('unfamiliar_region'));
  const again = await d({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } });
  assert.equal(again.decision, 'allow');
  for (const stepUp of [{ verified: true, authAgeSeconds: 901 }, { verified: true, authAgeSeconds: null }, { verified: false, authAgeSeconds: null }]) {
    assert.equal((await d({ ...suspicious, stepUp })).decision, 'step_up');
  }
  // region alone, or only two of the three signals, never asks again
  assert.equal((await d({ ...normal, signals: { ...normal.signals, region: 'foreign' } })).decision, 'allow');
  assert.equal((await d({ ...suspicious, recentEvents: [] })).decision, 'allow');
  assert.equal((await d({ ...suspicious, signals: { ...suspicious.signals, network: 'usual' } })).decision, 'allow');
  // untrusted or missing sources are not promoted and not filled with normal values
  for (const source of ['client_header', 'none', undefined]) {
    assert.equal((await d({ ...suspicious, signals: { ...suspicious.signals, source } })).decision, 'allow');
  }
  assert.equal((await d({ ...suspicious, signals: undefined })).decision, 'allow');
  assert.equal((await d({ ...suspicious, deviceRegistered: false })).reasonCode, 'device_not_registered');
});
