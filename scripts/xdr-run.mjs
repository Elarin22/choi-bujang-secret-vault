import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runBruteForce } from '../xdr/brute-force/run.mjs';

const root = resolve(import.meta.dirname, '..');
const scenario = process.argv[2];
if (scenario !== 'brute-force') {
  process.stderr.write('사용법: npm run xdr:run -- brute-force\n');
  process.exit(2);
}
try {
  const { result, rules, logLines } = await runBruteForce();
  await mkdir(resolve(root, 'xdr/brute-force'), { recursive: true });
  await writeFile(resolve(root, 'xdr/brute-force/result.json'), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  await writeFile(resolve(root, 'xdr/brute-force/deny-rules.json'), `${JSON.stringify(rules, null, 2)}\n`, 'utf8');
  await writeFile(resolve(root, 'xdr/alerts.log'), logLines.length ? `${logLines.join('\n')}\n` : '', 'utf8');
  const { block, alert, record } = result.counts;
  process.stdout.write(`block ${block} · alert ${alert} · record ${record} (경보 ${result.alertCount}건, 뽑은 줄 ${result.extractedRows}줄)\n`);
  process.stdout.write(`정상 이벤트를 block한 경우: ${result.normalBlocked.length}건\n`);
  if (result.normalBlocked.length) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`xdr 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}
