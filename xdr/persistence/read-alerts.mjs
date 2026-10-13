import { readFile } from 'node:fs/promises';
import { extract, redact, MASK } from '../brute-force/read-alerts.mjs';

export { extract, redact, MASK };

// 확인용 읽기 모듈: decide.mjs 는 이 파일을 불러오지 않는다.
// 경보에서 시각·출발 주소·계정·규칙 수준·설명(과 경보 번호)만 뽑는다. 파일 경로·서명 정보 등 나머지 값은 복사하지 않는다.
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
