// Pure classification input: no file, network, environment or Node imports.
export function classifyAlert(alert) {
  const candidate = String(alert?.data?.srcip ?? '');
  let sourceIp = null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(candidate)
      && candidate.split('.').every(part => Number(part) <= 255 && String(Number(part)) === part)) sourceIp = candidate;
  else if (/^[a-f\d:]+$/iu.test(candidate) && candidate.includes(':')) {
    try { if (new URL(`http://[${candidate}]/`).hostname) sourceIp = candidate; } catch { /* invalid IPv6 */ }
  }
  const time = Date.parse(alert?.timestamp);
  return {
    timestamp: Number.isFinite(time) ? new Date(time).toISOString() : null,
    sourceIp,
    level: Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0,
    // Descriptions are used only for classification; reason never echoes them.
    description: String(alert?.rule?.description ?? '').slice(0, 2000),
  };
}
