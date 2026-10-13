import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

test('registered reads preserve the five-field contract and run in isolation', async () => {
  const source = await readFile(new URL('../src/decider.mjs', import.meta.url), 'utf8');
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  for (const [path, route] of [['/notes/demo', 'GET /notes/:id'], ['/api/my/notes', 'GET /api/my/notes'], ['/api/notes/demo', 'GET /api/notes/:id']]) {
    const { normal } = fixtureRequests();
    const req = { ...normal, path, route };
    const out = await isolated.decide(req);
    assert.deepEqual(Object.keys(out).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
    assert.equal(out.decision, 'allow'); assert.equal(out.requestId, req.requestId);
    assert.ok(out.ruleIds.every(id => RULE_IDS.includes(id)));
  }
});
test('registration is a verified boolean; malformed or injected contracts deny', async () => {
  for (const deviceRegistered of [false, 'true', 1, null, undefined]) {
    const { normal } = fixtureRequests();
    const out = await decide({ ...normal, deviceRegistered });
    assert.equal(out.decision, 'deny'); assert.equal(out.reasonCode, 'device_not_registered');
  }
  for (const patch of [
    { device: { registered: true } }, { identity: { role: 'operator' } },
    { schema: 'untrusted' }, { deviceId: '' }, { subjectId: '' }, { querySha256: 'invalid' },
    { at: new Date(Date.now() - 30000).toISOString() }, { recentEvents: [{}] },
    { stepUp: { verified: 'true', authAgeSeconds: 0 } },
  ]) assert.equal((await decide({ ...fixtureRequests().normal, ...patch })).decision, 'deny');
});
test('unlisted services, writes and route/path mismatches never widen access', async () => {
  for (const patch of [
    { service: 'notices' }, { method: 'POST' }, { route: 'GET /admin', path: '/admin' },
    { route: 'GET /api/notes', path: '/api/notes/all' }, { path: '/notes/../admin' }, { path: '/notes/%2e%2e' },
  ]) {
    const out = await decide({ ...fixtureRequests().normal, ...patch });
    assert.equal(out.decision, 'deny'); assert.ok(['route_not_allowed', 'write_not_allowed'].includes(out.reasonCode));
  }
});
test('stage 6 deployment metadata preserves identity and rejects invalid stage values', async () => {
  const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  const env = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'Student-A',
    VERCEL_GIT_REPO_SLUG: 'aleph-defense', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'student-defense.vercel.app' };
  const out = deploymentIdentity(env, config);
  assert.equal(out.step, config.step); assert.equal(out.judgeIssuer, config.judgeIssuer);
  assert.deepEqual(out.identityProvider, config.identityProvider);
  assert.deepEqual(out.allowedRoutes, config.allowedRoutes); assert.ok(!Object.hasOwn(out, 'sampleMarker'));
  for (const step of [0, 13, '6', 6.5]) assert.throws(() => deploymentIdentity(env, { ...config, step }));
});
