import patterns from './patterns.json' with { type: 'json' };
import { classifyAlert } from '../classify-alert.mjs';
import { ambiguous, decision } from '../jev.mjs';
export { setJevReviewer } from '../jev.mjs';

export async function decide(alert) {
  const row = classifyAlert(alert);
  if (!row.timestamp || !row.sourceIp) return decision(0.5, 'auth_failure_burst: invalid event; alert only');
  const text = row.description;
  const count = Math.max(0, Number(alert?.data?.count) || 0);
  const accounts = new Set(String(alert?.data?.accounts ?? '').split(',').filter(Boolean)).size;
  const failure = /(?:로그인|비밀번호|인증).{0,25}실패|실패.{0,25}(?:로그인|비밀번호)|failed (?:password|login)|authentication fail/iu.test(text);
  const spray = /여러 계정|계정\s*\d+개|서로 다른 계정|계정 이름을 바꿔|password spray/iu.test(text);
  const repeated = /연속|이어졌|쌓였|실패.{0,4}\d+건|failures|attempts/iu.test(text);
  const window = text.match(/(\d+)\s*분\s*(?:안|동안)/u);
  const withinWindow = !window || Number(window[1]) * 60 <= patterns[0].maxWindowSeconds;
  if (row.level >= patterns[1].minLevel && spray
      && ((accounts >= patterns[1].minAccounts && /같은 비밀번호|연속|일정한 간격/iu.test(text))
          || (failure && count >= patterns[1].minCount))) {
    return decision(0.96, 'password_spray: repeated failures across accounts');
  }
  if (failure && repeated && withinWindow && row.level >= patterns[0].minLevel && count >= patterns[0].minCount) {
    return decision(0.96, 'auth_failure_burst: repeated failures within sensor window');
  }
  if ((failure && count > 1) || spray || row.level >= 5) return ambiguous(spray ? 'password_spray' : 'auth_failure_burst', row.level, count);
  return decision(0.1, 'auth_normal: no corroborated attack pattern');
}
