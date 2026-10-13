// Standalone, pure classification. Keep PATTERNS synchronized with patterns.json.
const PATTERNS = Object.freeze([
  { name: 'kc_remote_lookup', regex: '\\$\\{\\s*jndi\\s*:\\s*(?:ldap|ldaps|rmi)\\s*://[^\\s{}]+\\}', confidence: 0.96 },
  { name: 'kc_cve_reference', regex: 'CVE-2021-44228|Log4Shell|\\bjndi\\b', confidence: 0.6 },
  { name: 'kc_scanner_trace', regex: '취약점.{0,20}점검|점검\\s*도구|vulnerability\\s*(?:scan|check)|log4j.{0,12}(?:scan|check)', confidence: 0.55 },
]);
const MATCHERS = PATTERNS.map(pattern => new RegExp(pattern.regex, 'iu'));
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = value => typeof value === 'string' ? value.slice(0, 8192) : '';
function values(value) {
  if (typeof value === 'string') return [text(value)];
  if (Array.isArray(value)) return value.slice(0, 32).map(text);
  if (object(value)) return Object.values(value).slice(0, 32).map(text);
  return [];
}
function decision(confidence, pattern, detail) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: `${pattern}: ${detail}` };
}
export function decide(alert) {
  if (!object(alert) || !object(alert.rule) || !object(alert.data)) {
    return decision(0.5, 'kc_invalid', 'unconfirmed event; alert only');
  }
  const data = alert.data;
  const requestFields = ['url', 'useragent', 'headers', 'query', 'params', 'args', 'body'];
  const requestValues = requestFields.flatMap(key => values(data[key]));
  // Never execute or contact a lookup. Descriptions cannot trigger a block.
  if (requestValues.some(value => MATCHERS[0].test(value))) {
    return decision(PATTERNS[0].confidence, PATTERNS[0].name, 'complete remote lookup in request');
  }
  const context = [text(alert.rule.description), ...requestValues].join('\n');
  for (let index = 1; index < PATTERNS.length; index++) {
    if (MATCHERS[index].test(context)) return decision(PATTERNS[index].confidence,
      PATTERNS[index].name, 'incomplete or contextual evidence; alert only');
  }
  if (Number.isInteger(alert.rule.level) && alert.rule.level >= 5) {
    return decision(0.5, 'kc_unconfirmed', 'elevated event without complete lookup; alert only');
  }
  return decision(0.1, 'kc_normal', 'no known exploitation evidence');
}
