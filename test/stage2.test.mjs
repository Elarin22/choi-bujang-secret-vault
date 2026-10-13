import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, access } from 'node:fs/promises';

function response() {
  return { headers: {}, setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
}
test('latest static files have no seed and browser uses the bundled SDK', async () => {
  await assert.rejects(access(new URL('../data.json', import.meta.url)));
  await assert.rejects(access(new URL('../public/data.json', import.meta.url)));
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const vault = await readFile(new URL('../public/vault.html', import.meta.url), 'utf8');
  assert.ok(vault.includes('src="/app.js"'));
  assert.ok(html.includes('src="/connect.js"'));
  assert.ok(!html.includes('SUPABASE_SECRET_KEY'));
  assert.ok(!vault.includes('SUPABASE_SECRET_KEY'));
  assert.ok(!/실습용 가상.{1,20}기록/u.test(html));
});
