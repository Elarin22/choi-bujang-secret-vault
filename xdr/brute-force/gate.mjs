// A step that can be added to a decider. It only reports a matching deny rule; it never allows anything.
// The current decision request contract has no source address, so sourceOf must come from engine-provided data.
export function findRule(srcip, rules, atMs) {
  if (!srcip || !Array.isArray(rules)) return null;
  return rules.find((r) => r.effect === 'deny' && r.match?.srcip === srcip
    && Date.parse(r.createdAt) <= atMs && atMs < Date.parse(r.expiresAt)) ?? null;
}

export function bruteForceStep(request, { rules, now = Date.now(), sourceOf = () => null } = {}) {
  const rule = findRule(sourceOf(request)?.srcip, rules, now);
  return rule ? { hit: true, ruleId: rule.id, expiresAt: rule.expiresAt, evidenceAlertIds: rule.evidenceAlertIds } : null;
}
