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

test('step 2 attack check reads data.json and api without credentials', async () => {
  const originalFetch = globalThis.fetch;
  const urls = [];
  const cfg = { ...config, step: 2 };
  try {
    globalThis.fetch = async (url, init) => {
      urls.push(String(url));
      assert.equal(init.redirect, 'error');
      return String(url).endsWith('/api/notes')
        ? new Response(JSON.stringify({ notes: [{ title: 'x', content: 'y' }] }), { status: 200 })
        : new Response('not found', { status: 404 });
    };
    const [file, api] = await runAttackChecks(cfg);
    assert.deepEqual(urls, ['https://student-defense.vercel.app/data.json', 'https://student-defense.vercel.app/api/notes']);
    assert.match(file.observed, /보이지 않음/u);
    assert.match(api.observed, /1건/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('notes api rejects non-GET and fails closed without env', async () => {
  const { default: handler } = await import('../api/notes.js');
  const make = (method) => {
    const out = { headers: {} };
    const res = { setHeader: (k, v) => { out.headers[k] = v; }, status: (c) => { out.code = c; return res; },
      json: (b) => { out.body = b; return res; } };
    return [{ method }, res, out];
  };
  const saved = { u: process.env.SUPABASE_URL, k: process.env.SUPABASE_SECRET_KEY };
  delete process.env.SUPABASE_URL; delete process.env.SUPABASE_SECRET_KEY;
  try {
    let [req, res, out] = make('POST');
    await handler(req, res);
    assert.equal(out.code, 405);
    [req, res, out] = make('GET');
    await handler(req, res);
    assert.equal(out.code, 500);
  } finally {
    if (saved.u) process.env.SUPABASE_URL = saved.u;
    if (saved.k) process.env.SUPABASE_SECRET_KEY = saved.k;
  }
});
