import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { build } from 'esbuild';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (!Number.isInteger(config.step) || config.step < 2 || config.step > 12) throw new Error('현재 빌드는 2~12단계 서버 자료실 전용입니다.');
await mkdir(resolve(root, 'public'), { recursive: true });
await rm(resolve(root, 'public', 'data.json'), { force: true });
console.log('공개 데이터 복사를 제거하고 서버 자료실을 준비했습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}

if (config.step >= 3) await build({ entryPoints: [resolve(root, 'src/browser.mjs')], outfile: resolve(root, 'public/app.js'), bundle: true, format: 'esm', platform: 'browser', minify: true, sourcemap: false });
if (config.step >= 11) await build({ entryPoints: [resolve(root, 'src/connect-browser.mjs')], outfile: resolve(root, 'public/connect.js'), bundle: true, format: 'esm', platform: 'browser', minify: true, sourcemap: false });
if (config.step >= 12) await build({ entryPoints: [resolve(root, 'src/operations-browser.mjs')], outfile: resolve(root, 'public/operations.js'), bundle: true, format: 'esm', platform: 'browser', minify: true, sourcemap: false });
