import { projectAlert, readFixture } from '../read-alerts.mjs';

// 확인용 읽기 모듈: 경보 수만큼 시각·출발 주소·계정·수준·설명 다섯 필드를 돌려준다. decide.mjs 는 이 파일을 불러오지 않는다.
export async function readAlerts(path = new URL('../fixtures/privilege.json', import.meta.url)) {
  return (await readFixture(path, 'privilege')).alerts.map(projectAlert);
}
