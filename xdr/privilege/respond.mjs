import { publishDecisions, withXdr } from '../ztna-overlay.mjs';

// 기존 판정기 규칙은 그대로 두고, 확인 단계 하나만 더하는 연결입니다.
export function connectDecider(baseDecide, rules) {
  return withXdr(baseDecide, rules.filter(rule => rule.moduleKey === 'privilege'));
}
export async function respond(root, fixture, result) {
  if (fixture?.moduleKey !== 'privilege' || result?.moduleKey !== 'privilege'
      || !Array.isArray(fixture.alerts) || !Array.isArray(result.decisions)
      || result.decisions.length !== fixture.alerts.length) throw new Error('privilege 응답 형식을 확인하세요.');
  const expected = new Set(fixture.alerts.map(alert => alert.id));
  if (expected.size !== fixture.alerts.length) throw new Error('중복 경보 번호를 확인하세요.');
  const decisions = result.decisions.map(row => {
    if (!expected.delete(row.alertId) || !Number.isFinite(row.confidence)
        || row.confidence < 0 || row.confidence > 1
        || row.action !== (row.confidence >= 0.85 ? 'block' : row.confidence >= 0.5 ? 'alert' : 'record')
        || typeof row.reason !== 'string'
        || !/^pv_(admin_group_add|unusual_admin_command|offhours_privilege_use|unconfirmed|normal):/u.test(row.reason)) {
      throw new Error('privilege 판정 결과를 확인하세요.');
    }
    // 알림 로그에는 패턴 이름만 남기고 경로·계정·주소는 쓰지 않는다.
    return { alertId: row.alertId, action: row.action, confidence: row.confidence,
      reason: row.reason.split(':', 1)[0] };
  });
  return publishDecisions(root, fixture, { ...result, decisions });
}
