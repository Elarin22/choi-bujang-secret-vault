import assert from 'node:assert/strict';
import { test } from 'node:test';
import { restore } from '../lib/restore.mjs';
import { SAFE_POLICY_HASH, applyPolicyRestore, planPolicyRestore, verifyPolicyBackup } from '../src/policy-recovery.mjs';
import { readFileSync } from 'node:fs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const backup = () => JSON.parse(readFileSync(new URL('../backups/safe-policy.json', import.meta.url), 'utf8'));
const state = (allowedRoutes = config.allowedRoutes) => ({ projectId: config.repoUrl, policyRevision: 1, allowedRoutes, audit: [{ kind: 'old' }] });
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const NOTE = '33333333-3333-4333-8333-333333333333';
const HASH = 'a'.repeat(64);

test('policy backup: verified copy passes, missing or tampered copy stops', () => {
  assert.match(SAFE_POLICY_HASH, /^[a-f0-9]{64}$/u);
  assert.equal(verifyPolicyBackup(backup(), config.repoUrl).service, 'notes');
  for (const bad of [undefined, null, {}, { ...backup(), policyRevision: 2 }, { ...backup(), allowedRoutes: [...backup().allowedRoutes, 'GET /api/notes'] },
    { ...backup(), allowedRoutes: ['GET /api/notices'] }]) {
    assert.throws(() => verifyPolicyBackup(bad, config.repoUrl), /invalid_policy_backup/u);
  }
  assert.throws(() => verifyPolicyBackup(backup(), 'https://github.com/other/repo'), /invalid_policy_backup/u);
  assert.throws(() => planPolicyRestore(state(), undefined), /invalid_policy_backup/u);
});

test('policy plan shows version and changes before anything is written; apply needs the confirmation', () => {
  const same = planPolicyRestore(state(), backup());
  assert.equal(same.unchanged, true);
  const breached = state(['GET /api/notes', 'GET /api/my/notes', 'POST /api/notes', 'GET /api/export', ...config.allowedRoutes.filter((r) => r.includes('notices'))]);
  const plan = planPolicyRestore(breached, backup());
  assert.equal(plan.backupRevision, 1);
  assert.ok(plan.added.includes('GET /api/notes/:id') && plan.added.includes('PUT /api/notes/:id'));
  assert.ok(plan.removed.includes('GET /api/notes'));
  assert.equal(plan.preservedOtherRoutes.length, 3 + 1);
  assert.throws(() => applyPolicyRestore(breached, backup(), 'wrong'), /restore_confirmation_required/u);
  const next = applyPolicyRestore(breached, backup(), plan.confirmation);
  assert.equal(next.policyRevision, 2);
  assert.deepEqual(next.allowedRoutes.filter((r) => /notes/u.test(r)), backup().allowedRoutes);
  assert.ok(next.allowedRoutes.includes('GET /api/notices') && next.allowedRoutes.includes('GET /api/export'));
  assert.deepEqual(next.audit[0], { kind: 'old' });
  assert.equal(next.audit.length, 2);
  assert.equal(breached.policyRevision, 1);
});

function harness({ rpc, method = 'POST', user = B, query = { noteId: NOTE }, body, loadBackup = backup, loadPolicy = () => config } = {}) {
  const calls = [];
  const out = { headers: {} };
  const res = { setHeader: (k, v) => { out.headers[k] = v; }, status: (c) => { out.code = c; return res; }, json: (b) => { out.body = b; return res; } };
  const db = { rpc: async (name, args) => { calls.push([name, args]); return rpc ? rpc(args) : { data: { id: args.target_note_id, verified: true, content_hash: HASH }, error: null }; } };
  const deps = () => ({ verify: async () => (user ? { userId: user } : null), db });
  const req = { method, query, body, headers: { authorization: 'Bearer x' } };
  return { calls, out, run: async () => { await restore(req, res, deps, { loadBackup, loadPolicy }); return out; } };
}

test('restore route: only the verified owner restores one note; others and bad input are refused', async () => {
  const ok = harness();
  const out = await ok.run();
  assert.equal(out.code, 200);
  assert.deepEqual(out.body, { id: NOTE, restored: true, verified: true });
  assert.deepEqual(ok.calls, [['restore_note', { target_note_id: NOTE, verified_owner_id: B }]]);
  // another user's backup: the stored owner does not match, so the database function reports not found
  const other = harness({ user: A, rpc: () => ({ data: null, error: { code: 'P0002' } }) });
  assert.equal((await other.run()).code, 404);
  assert.equal((await harness({ rpc: () => ({ data: null, error: { code: 'P0001' } }) }).run()).code, 409);
  assert.equal((await harness({ rpc: () => ({ data: { id: NOTE, verified: false, content_hash: HASH }, error: null }) }).run()).code, 502);
  assert.equal((await harness({ method: 'GET' }).run()).code, 405);
  assert.equal((await harness({ user: null }).run()).code, 401);
  assert.equal((await harness({ query: { noteId: 'export' } }).run()).code, 400);
  for (const body of [{ owner_id: A }, { title: 'x' }, [1]]) {
    const h = harness({ body });
    assert.equal((await h.run()).code, 400);
    assert.equal(h.calls.length, 0);
  }
});

test('restore route: missing, corrupt or out-of-sync policy copy stops before storage is touched', async () => {
  const missing = harness({ loadBackup: () => { throw new Error('ENOENT'); } });
  assert.equal((await missing.run()).code, 503);
  assert.equal(missing.calls.length, 0);
  const corrupt = harness({ loadBackup: () => ({ ...backup(), policyRevision: 9 }) });
  assert.equal((await corrupt.run()).code, 503);
  const drift = harness({ loadPolicy: () => ({ ...config, allowedRoutes: [...config.allowedRoutes, 'GET /api/notes'] }) });
  const out = await drift.run();
  assert.deepEqual([out.code, out.body.reason], [503, 'policy_restore_required']);
  assert.equal(drift.calls.length, 0);
});
