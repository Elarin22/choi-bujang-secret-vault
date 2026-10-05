import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('step 3 attack check sends no real credentials and expects rejection', async () => {
  const originalFetch = globalThis.fetch;
  const seen = [];
  const cfg = { ...config, step: 3, identityProvider: { issuer: 'https://abcdefghij.supabase.co/auth/v1' } };
  try {
    globalThis.fetch = async (url, init) => {
      seen.push([String(url), init.method ?? 'GET']);
      return String(url).endsWith('/data.json') ? new Response('nf', { status: 404 }) : new Response('{}', { status: 401 });
    };
    const results = await runAttackChecks(cfg);
    assert.equal(results.length, 4);
    assert.ok(results.every((r) => /거부|보이지 않음/u.test(r.observed)));
    assert.equal(seen.length, 4);
    globalThis.fetch = async () => new Response(JSON.stringify([{ id: 'a' }]), { status: 200 });
    const open = await runAttackChecks(cfg);
    assert.match(open[1].observed, /거부되지 않음/u);
    await assert.rejects(runAttackChecks({ ...cfg, identityProvider: { issuer: 'https://REPLACE-X.supabase.co/auth/v1' } }));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
