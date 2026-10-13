import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { isIP } from 'node:net';

// 기존 판정기 규칙은 고치지 않고, 확인 단계 하나만 더하는 연결입니다. decide.mjs 는 판단만 하고 이 파일이 규칙·알림을 씁니다.
const MODULE_KEY = 'exfiltration';
const TTL_MS = 15 * 60 * 1000;
const NAME_PATTERN = /^ex_(new_destination_bulk|offhours_archive|alt_channel|unconfirmed|normal):/u;
const safeId = value => /^[A-Za-z0-9._-]{1,80}$/u.test(value ?? '') && !/sb_secret_|Bearer|eyJ/iu.test(value);

// 회사 안쪽·특수 주소는 목적지 차단 대상이 아니다. (정상 사용자를 막는 규칙을 만들지 않기 위함)
// 문서용 대역(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)은 시험 자료이므로 허용한다.
export function isBlockableDestination(value) {
  const ip = String(value ?? '');
  const kind = isIP(ip);
  if (kind === 4) {
    const [a, b] = ip.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168));
  }
  if (kind === 6) {
    const lower = ip.toLowerCase();
    return !(lower === '::' || lower === '::1' || /^f[cd]/u.test(lower) || /^fe[89ab]/u.test(lower)
      || lower.startsWith('::ffff:') || lower.startsWith('ff'));
  }
  return false;
}

// block 후보 하나를 만료 시각과 근거 경보 번호가 붙은 목적지 거부 규칙으로 바꾼다. 해당 없으면 null.
export function destinationRule(alert, row, normalDestinations = new Set()) {
  const time = Date.parse(alert?.timestamp);
  const destination = alert?.data?.dstip;
  if (row?.action !== 'block' || !(row.confidence >= 0.85) || !Number.isFinite(time)
      || !safeId(alert?.id) || !isBlockableDestination(destination)
      || destination === alert?.data?.srcip || normalDestinations.has(destination)) return null;
  return {
    id: `xdr.${MODULE_KEY}.${alert.id}`, moduleKey: MODULE_KEY, destinationIp: destination,
    action: 'deny', confidence: row.confidence, evidenceAlertId: alert.id,
    issuedAt: new Date(time).toISOString(), expiresAt: new Date(time + TTL_MS).toISOString(),
    reason: row.reason,
  };
}

export function activeDestinationDenial(rules, { destinationIp, destinationVerified, at }) {
  // 목적지 주소는 운영 엔진이 확인해 넘긴 값만 쓴다. 브라우저가 보낸 값은 믿지 않는다.
  if (destinationVerified !== true || !isIP(String(destinationIp ?? ''))) return null;
  const now = Date.parse(at);
  if (!Number.isFinite(now)) return null;
  return rules.find(rule => rule.moduleKey === MODULE_KEY && rule.action === 'deny' && rule.confidence >= 0.85
    && rule.destinationIp === destinationIp && safeId(rule.evidenceAlertId)
    && Date.parse(rule.issuedAt) <= now && now < Date.parse(rule.expiresAt)) ?? null;
}

// 기존 판정기(baseDecide)는 그대로 두고, 확인된 목적지가 유효한 거부 규칙과 일치할 때만 거부한다. 나머지는 모두 위임한다.
export function connectDecider(baseDecide, rules) {
  const mine = rules.filter(rule => rule.moduleKey === MODULE_KEY);
  return async (request, verifiedContext = {}) => {
    const matched = activeDestinationDenial(mine, { ...verifiedContext, at: request.at });
    if (matched) return { schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'xdr_blocked', ruleIds: [matched.id] };
    return baseDecide(request);
  };
}

export async function respond(root, fixture, result) {
  if (fixture?.moduleKey !== MODULE_KEY || result?.moduleKey !== MODULE_KEY
      || !Array.isArray(fixture.alerts) || !Array.isArray(result.decisions)
      || result.decisions.length !== fixture.alerts.length) throw new Error('exfiltration 응답 형식을 확인하세요.');
  const expected = new Set(fixture.alerts.map(alert => alert.id));
  if (expected.size !== fixture.alerts.length) throw new Error('중복 경보 번호를 확인하세요.');
  const decisions = result.decisions.map(row => {
    if (!expected.delete(row.alertId) || !Number.isFinite(row.confidence)
        || row.confidence < 0 || row.confidence > 1
        || row.action !== (row.confidence >= 0.85 ? 'block' : row.confidence >= 0.5 ? 'alert' : 'record')
        || typeof row.reason !== 'string' || !NAME_PATTERN.test(row.reason)) {
      throw new Error('exfiltration 판정 결과를 확인하세요.');
    }
    // 알림 로그에는 패턴 이름만 남기고 주소·계정·파일 이름은 쓰지 않는다.
    return { alertId: row.alertId, action: row.action, confidence: row.confidence, reason: row.reason.split(':', 1)[0] };
  });

  // 정상 이벤트(record)가 향한 목적지는 막지 않는다.
  const byId = new Map(decisions.map(row => [row.alertId, row]));
  const normalDestinations = new Set(fixture.alerts
    .filter(alert => byId.get(alert.id)?.action === 'record').map(alert => alert.data?.dstip).filter(Boolean));
  const rules = fixture.alerts
    .map(alert => destinationRule(alert, byId.get(alert.id), normalDestinations)).filter(Boolean);

  const folder = join(root, 'xdr');
  await mkdir(folder, { recursive: true });
  const rulesPath = join(folder, 'deny-rules.json');
  let prior = [];
  try { prior = JSON.parse(await readFile(rulesPath, 'utf8')).rules ?? []; }
  catch (error) { if (error.code !== 'ENOENT') throw new Error('기존 XDR 규칙 파일을 확인하세요.'); }
  const combined = [...prior.filter(rule => rule.moduleKey !== MODULE_KEY), ...rules];
  await writeFile(rulesPath, `${JSON.stringify({ schema: 'aleph.xdr.deny.v1', rules: combined }, null, 2)}\n`);

  // 알림은 한 줄씩 쌓는다. 같은 경보를 다시 돌려도 같은 줄은 중복하지 않는다.
  const logPath = join(folder, 'alerts.log');
  let previous = [];
  try { previous = (await readFile(logPath, 'utf8')).split('\n').filter(Boolean).map(line => JSON.parse(line)); }
  catch (error) { if (error.code !== 'ENOENT') throw new Error('기존 XDR 알림 로그를 확인하세요.'); }
  const entries = new Map(previous.map(row => [`${row.moduleKey}:${row.alertId}`, row]));
  for (const row of decisions.filter(item => item.action !== 'record')) {
    if (!safeId(row.alertId)) continue;
    entries.set(`${MODULE_KEY}:${row.alertId}`, { moduleKey: MODULE_KEY, ...row });
  }
  await writeFile(logPath, `${[...entries.values()].map(row => JSON.stringify(row)).join('\n')}\n`);
  return rules;
}
