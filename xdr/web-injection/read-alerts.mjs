import { readFile } from 'node:fs/promises';
import { extract, redact, MASK } from '../brute-force/read-alerts.mjs';

export { extract, redact, MASK };

// 경보에서 시각·출발 주소·계정·규칙 수준·설명(과 경보 번호)만 뽑는다.
// 요청 주소(url)와 그 밖의 값은 복사하지 않고, 비밀값처럼 보이는 값은 가린다. 원본은 고치지 않는다.
// 입력: 경보 배열, 또는 경보 묶음 파일 경로({alerts:[...]} 형식 · 배열 · 줄 단위 JSON 모두 가능)
export async function readAlerts(source) {
  let list = source;
  if (!Array.isArray(source)) {
    const text = await readFile(source, 'utf8');
    try {
      const parsed = JSON.parse(text);
      list = Array.isArray(parsed) ? parsed : parsed?.alerts;
    } catch {
      list = text.split(/\r?\n/u).filter((line) => line.trim()).map((line) => JSON.parse(line));
    }
  }
  if (!Array.isArray(list)) throw new Error('Wazuh 경보 배열을 찾지 못했습니다.');
  return list.map(extract);
}
