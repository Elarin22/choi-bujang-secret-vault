import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { planPolicyRestore, applyPolicyRestore } from '../src/policy-recovery.mjs';
import { createRestoreHandler } from '../src/restore-api.mjs';
import { createRecoveryPlanHandler } from '../src/recovery-plan.mjs';
const backup = JSON.parse(await readFile(new URL('../backups/safe-policy.json', import.meta.url), 'utf8'));
const policy = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));

test('policy restore requires verified backup and displayed-diff confirmation; keeps unrelated rules and audit', () => {
  const other = { service: 'other', method: 'GET', pathPattern: '/other' };
  const state = { projectId: backup.projectId, policyRevision: 7, allowedRoutes: [other], audit: [{ kind: 'previous_event' }] };
  const plan = planPolicyRestore(state, backup);
  assert.deepEqual(plan.before, []); assert.deepEqual(plan.after, backup.allowedRoutes);
  assert.throws(() => applyPolicyRestore(state, backup, 'unapproved'), /restore_confirmation_required/);
  const restored = applyPolicyRestore(state, backup, plan.confirmation);
  assert.equal(restored.policyRevision, 8); assert.deepEqual(restored.allowedRoutes[0], other);
  assert.deepEqual(restored.audit[0], state.audit[0]); assert.equal(state.audit.length, 1);
  assert.throws(() => planPolicyRestore(state, { ...backup, policyRevision: 2 }), /invalid_policy_backup/);
  assert.throws(() => planPolicyRestore({ ...state, projectId: 'different' }, backup), /invalid_policy_backup/);
  assert.throws(() => applyPolicyRestore({ ...state, policyRevision: 8 }, backup, plan.confirmation), /restore_confirmation_required/);
});

test('restore endpoint uses verified owner, rejects caller-supplied backup/owner and checks RPC postconditions', async () => {
  const id = randomUUID(), owner = randomUUID(); let calls = 0, broken = false;
  const handler = createRestoreHandler({ policy, policyBackup: backup, approvalVerifier: async () => true,
    env: { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_SECRET_KEY: 'unit-test-only' },
    verifierFactory: () => async () => ({ userId: owner }), clientFactory: () => ({ async rpc(name, args) {
      calls++; assert.equal(name, 'vault_restore_note'); assert.deepEqual(args, { target_note_id: id, verified_owner_id: owner });
      return { data: { id, verified: !broken, content_hash: 'a'.repeat(64) }, error: null };
    } }) });
  const call = async (auth, method = 'POST', body) => { const res = { setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
    await handler({ method, query: { noteId: id }, headers: { authorization: auth }, body }, res); return res; };
  assert.equal((await call()).code, 401); assert.equal(calls, 0);
  assert.equal((await call('Bearer Fixture', 'POST', { owner_id: 'untrusted' })).code, 400); assert.equal(calls, 0);
  assert.equal((await call('Bearer Fixture', 'GET')).code, 405);
  const result = await call('Bearer Fixture'); assert.equal(result.code, 200); assert.deepEqual(result.body, { id, restored: true, verified: true });
  broken = true; assert.equal((await call('Bearer Fixture')).code, 502);
});

test('each preview rereads the copy and reports version/scope; bad or missing backup is never verified', async () => {
  let reads = 0, broken = false;
  const handler = createRecoveryPlanHandler({ configLoader: () => policy, backupLoader: () => {
    reads++; if (broken) throw new Error('missing'); return structuredClone(backup);
  } });
  const call = async () => { const res = { setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
    await handler({ method: 'GET' }, res); return res; };
  const first = await call(); assert.equal(first.code, 200); assert.equal(first.body.backupVerified, true);
  assert.equal(first.body.backupRevision, 1); assert.equal(first.body.scope, 'notes'); assert.equal(first.body.operationalPolicyWrite, false);
  broken = true; const second = await call(); assert.equal(second.code, 409); assert.equal(second.body.backupVerified, false); assert.equal(reads, 2);
});

test('missing or altered backup stops the restore before any RPC', async () => {
  let calls = 0;
  for (const backupLoader of [() => { throw new Error('missing'); }, () => ({ ...backup, policyRevision: 2 })]) {
    const handler = createRestoreHandler({ policy, backupLoader, approvalVerifier: async () => true, env: { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_SECRET_KEY: 'unit-test-only' },
      verifierFactory: () => async () => ({ userId: randomUUID() }), clientFactory: () => ({ async rpc() { calls++; } }) });
    const res = { setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
    await handler({ method: 'POST', query: { noteId: randomUUID() }, headers: { authorization: 'Bearer Fixture' } }, res);
    assert.equal(res.code, 503);
  }
  assert.equal(calls, 0);
});
