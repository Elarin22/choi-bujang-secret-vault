import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

test('compound signals require step-up; engine-confirmed fresh authentication resolves it', async () => {
  const { normal, suspicious } = fixtureRequests();
  assert.equal((await decide(normal)).decision, 'allow');
  assert.equal((await decide(suspicious)).decision, 'step_up');
  assert.equal((await decide({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'allow');
  assert.equal((await decide({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 901 } })).decision, 'deny');
  assert.equal((await decide({ ...suspicious, deviceRegistered: false, stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'deny');
});

test('a location alone never permanently denies; missing or client-origin signals cannot be promoted', async () => {
  const { normal } = fixtureRequests();
  assert.equal((await decide({ ...normal, signals: { ...normal.signals, region: 'foreign' } })).decision, 'allow');
  assert.equal((await decide({ ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: null } })).decision, 'allow');
  for (const signals of [undefined, { ...normal.signals, source: 'client_header' },
    { ...normal.signals, source: 'none' }, { ...normal.signals, extra: true }]) {
    assert.equal((await decide({ ...normal, signals })).decision, 'deny');
  }
});

test('stale bursts do not count and fresh unusual-network late-hour bursts trigger verification', async () => {
  const { suspicious } = fixtureRequests();
  const req = { ...suspicious, signals: { ...suspicious.signals, region: 'local' } };
  assert.equal((await decide(req)).decision, 'step_up');
  assert.equal((await decide({ ...req, recentEvents: [{ kind: 'risk_signal', ageSeconds: 301, count: 100 }] })).decision, 'allow');
});
