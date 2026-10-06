import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
for (const leftover of ['data.json', 'public/data.json']) {
  const exists = await access(resolve(root, leftover)).then(() => true, () => false);
  if (exists) throw new Error(`${leftover} 파일이 남아 있습니다. 2단계부터 자료는 코드 밖(DB)에만 둡니다.`);
}
await mkdir(resolve(root, 'public'), { recursive: true });
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  const allowedRoutes = Array.isArray(config.allowedRoutes)
    ? config.allowedRoutes.filter((route) => typeof route === 'string') : [];
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify({ ...identity, allowedRoutes }, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
