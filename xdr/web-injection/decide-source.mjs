import patterns from './patterns.json' with { type: 'json' };
import { classifyAlert } from '../classify-alert.mjs';
import { ambiguous, decision } from '../jev.mjs';
export { setJevReviewer } from '../jev.mjs';

export async function decide(alert) {
  const row = classifyAlert(alert);
  if (!row.timestamp || !row.sourceIp) return decision(0.5, 'web_unconfirmed: invalid event; alert only');
  const text = row.description;
  let url = String(alert?.data?.url ?? '').slice(0, 4096);
  for (let i = 0; i < 2; i++) { try { url = decodeURIComponent(url); } catch { break; } }
  const signals = [
    /SQL\s*(?:구문|표식)|데이터베이스 조회를 이어|sql injection/iu.test(text) || /\bunion\s+(?:all\s+)?select\b|\bor\s+['"\d]+\s*=\s*['"\d]+/iu.test(url),
    /스크립트\s*(?:삽입|표식)|script injection/iu.test(text) || /<script\b|on(?:error|load)\s*=|javascript\s*:/iu.test(url),
    /경로.{0,15}(?:거슬러|이탈)|path traversal/iu.test(text) || /\.\.\//u.test(url),
    /명령 구분자|command injection/iu.test(text) || /(?:;|\|\||&&)\s*(?:cat|id|whoami|curl|wget)\b/iu.test(url),
  ];
  const count = Math.max(0, Number(alert?.data?.count) || 0);
  const index = signals.findIndex(Boolean);
  if (index >= 0 && count >= patterns[index].minCount && row.level >= patterns[index].minLevel) {
    return decision(0.96, `${patterns[index].name}: corroborated repeated injection attempts`);
  }
  if (index >= 0 || row.level >= 5) return ambiguous(index >= 0 ? patterns[index].name : 'web_unconfirmed', row.level, count);
  return decision(0.1, 'web_normal: no corroborated attack pattern');
}
