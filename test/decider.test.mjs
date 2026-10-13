import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkDecider } from '../scripts/decider-test.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { RULE_IDS, decide } from '../src/decider.mjs';

test('device_registered: registered device allowed, unregistered or missing value denied', async () => {
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required', 'exact_route_only', 'own_notes_zone', 'notice_zone']);
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

test('zone rules: own notes allowed, notice edit and unknown or look-alike paths denied', async () => {
  const { decide: d, RULE_IDS: ids } = await import('../src/decider.mjs');
  const { normal } = fixtureRequests();
  const req = (method, path, route) => ({ ...normal, method, path, route });
  const uuid = '3f2b8c1e-5d4a-4b6e-9c7d-1a2b3c4d5e6f';
  for (const [m, p, r] of [['GET', '/notes', 'GET /notes'], ['POST', '/notes', 'POST /notes'], ['GET', `/notes/${uuid}`, 'GET /notes/:id'],
    ['PUT', `/notes/${uuid}`, 'PUT /notes/:id'], ['DELETE', `/notes/${uuid}`, 'DELETE /notes/:id'], ['GET', '/api/notes', 'GET /api/notes'],
    ['GET', '/notices', 'GET /notices'], ['GET', `/notices/${uuid}`, 'GET /notices/:id']]) {
    const out = await d(req(m, p, r));
    assert.equal(out.decision, 'allow', `${m} ${p}`);
    assert.ok(out.ruleIds.every((id) => ids.includes(id)));
  }
  const noticeEdit = await d(req('PUT', `/notices/${uuid}`, 'PUT /notices/:id'));
  assert.deepEqual([noticeEdit.decision, noticeEdit.reasonCode], ['deny', 'zone_not_allowed']);
  const denied = [
    ['GET', '/notes/export', 'GET /notes/:id'], ['GET', '/notes/EXPORT', 'GET /notes/:id'], ['GET', '/admin', 'GET /admin'],
    ['PATCH', `/notes/${uuid}`, 'PATCH /notes/:id'], ['POST', '/notices', 'POST /notices'], ['DELETE', `/notices/${uuid}`, 'DELETE /notices/:id'],
    ['GET', `/notes/${uuid}/export`, 'GET /notes/:id'], ['GET', '/notes/../notices', 'GET /notes/:id'], ['GET', `/notes/${uuid}?export=1`, 'GET /notes/:id'],
    ['GET', `/notes/${uuid}`, 'GET /notices/:id'], ['GET', '', ''],
  ];
  for (const [m, p, r] of denied) {
    const out = await d(req(m, p, r));
    assert.equal(out.decision, 'deny', `${m} ${p}`);
    assert.equal(out.reasonCode, 'route_not_allowed');
    assert.deepEqual(out.ruleIds, ['exact_route_only']);
  }
  // the query never selects a feature: same decision with or without a query length
  assert.equal((await d({ ...normal, queryLength: 7 })).decision, 'allow');
  // unregistered devices are still refused first, even on a known route
  assert.equal((await d({ ...req('GET', '/notes', 'GET /notes'), deviceRegistered: false })).reasonCode, 'device_not_registered');
});

test('decider keeps no memory of who asked first: the same request gets the same decision in any order', async () => {
  const { decide: d } = await import('../src/decider.mjs');
  const { normal } = fixtureRequests();
  const noteId = '7a1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d';
  const req = (subjectId) => ({ ...normal, subjectId, method: 'GET', path: `/notes/${noteId}`, route: 'GET /notes/:id' });
  const first = await d(req('learner_B'));
  const second = await d(req('learner_A'));
  const again = await d(req('learner_B'));
  assert.deepEqual([first.decision, second.decision, again.decision], ['allow', 'allow', 'allow']);
  assert.deepEqual(first.ruleIds, second.ruleIds);
  // ownership is not decided here: the notes API answers 403 not_owner (see notes.test.mjs)
  assert.equal((await d({ ...req('learner_B'), method: 'PUT', path: `/notices/${noteId}`, route: 'PUT /notices/:id' })).reasonCode, 'zone_not_allowed');
});