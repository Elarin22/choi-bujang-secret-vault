import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkDecider } from '../scripts/decider-test.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { RULE_IDS, decide } from '../src/decider.mjs';

test('device_registered: registered device allowed, unregistered or missing value denied', async () => {
  assert.deepEqual([...RULE_IDS], ['device_registered']);
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
