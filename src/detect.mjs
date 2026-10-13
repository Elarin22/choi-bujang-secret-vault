// Pure local contract from docs/DETECT_EVENTS.md. No token/body/log storage.
// Only the engine may deliver verified pseudonymous subjects and execute proposals.
export const DETECTION_RULE_IDS = Object.freeze(['burst_read']);
export function detect(events) {
  if (!Array.isArray(events) || events.length > 50000) throw new TypeError('invalid_detection_events');
  const groups = new Map();
  for (const event of events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)
      || Object.keys(event).sort().join(',') !== 'at,identity,method'
      || typeof event.at !== 'string' || !event.at.endsWith('Z') || !Number.isFinite(Date.parse(event.at))
      || typeof event.method !== 'string' || !/^[A-Z]{3,10}$/u.test(event.method)
      || !event.identity || typeof event.identity !== 'object' || Array.isArray(event.identity)
      || Object.keys(event.identity).join(',') !== 'sub'
      || typeof event.identity.sub !== 'string' || !/^[a-zA-Z\d_-]{1,160}$/u.test(event.identity.sub)) {
      throw new TypeError('invalid_detection_events');
    }
    if (event.method !== 'GET') continue;
    const times = groups.get(event.identity.sub) ?? [];
    times.push(Date.parse(event.at)); groups.set(event.identity.sub, times);
  }
  const candidates = [];
  for (const [subject, times] of groups) {
    times.sort((a, b) => a - b); let left = 0;
    for (let right = 0; right < times.length; right++) {
      while (times[right] - times[left] > 600000) left++;
      if (right - left + 1 > 120) { candidates.push({ subject, at: times[right] }); break; }
    }
  }
  candidates.sort((a, b) => a.at - b.at || a.subject.localeCompare(b.subject));
  if (candidates.length) return { action: 'propose_revocation', reasonCode: 'burst_read', subject: candidates[0].subject };
  return { action: 'observe' };
}
