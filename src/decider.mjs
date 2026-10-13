// Called only after the official engine verifies identity/device binding.
// This pure policy is not a public HTTP endpoint or an mTLS verifier.
export const RULE_IDS = Object.freeze(['device_registered', 'route_not_allowed', 'step_up_required', 'resource_zones', 'write_not_allowed']);
const REQUEST_KEYS = 'at,classId,deviceId,deviceRegistered,method,path,policyRevision,projectId,queryLength,querySha256,recentEvents,requestId,route,schema,service,signals,stepUp,subjectId';
const READ_PATHS = Object.freeze({
  'GET /api/my/notes': /^\/api\/my\/notes$/u,
  'GET /api/notes/:id': /^\/api\/notes\/(?!\.{1,2}$)[^/?#%\\\x00-\x1f]+$/u,
  'GET /notes/:id': /^\/notes\/(?!\.{1,2}$)[^/?#%\\\x00-\x1f]+$/u,
});
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
function validRequest(request) {
  if (!object(request) || Object.keys(request).sort().join(',') !== REQUEST_KEYS) return false;
  const at = Date.parse(request.at);
  return request.schema === 'aleph.decision.v1'
    && typeof request.requestId === 'string' && /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/iu.test(request.requestId)
    && ['classId', 'projectId', 'subjectId', 'service', 'method', 'path', 'route'].every(key => nonempty(request[key]))
    && typeof request.deviceId === 'string' && /^[a-f\d]{16}$/u.test(request.deviceId)
    && typeof request.deviceRegistered === 'boolean'
    && typeof request.at === 'string' && request.at.endsWith('Z') && Number.isFinite(at) && Math.abs(Date.now() - at) <= 5000
    && Number.isSafeInteger(request.policyRevision) && request.policyRevision >= 1
    && Number.isSafeInteger(request.queryLength) && request.queryLength >= 0
    && typeof request.querySha256 === 'string' && /^[a-f\d]{64}$/u.test(request.querySha256)
    && object(request.stepUp) && Object.keys(request.stepUp).sort().join(',') === 'authAgeSeconds,verified' && typeof request.stepUp.verified === 'boolean'
    && (request.stepUp.verified
      ? Number.isInteger(request.stepUp.authAgeSeconds) && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= 900
      : request.stepUp.authAgeSeconds === null)
    && Array.isArray(request.recentEvents) && request.recentEvents.length <= 12
    && request.recentEvents.every(event => object(event) && Object.keys(event).sort().join(',') === 'ageSeconds,count,kind' && nonempty(event.kind)
      && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0 && Number.isInteger(event.count) && event.count >= 0)
    && object(request.signals) && Object.keys(request.signals).sort().join(',') === 'hour,network,region,source'
    && ['none', 'judge_fixture'].includes(request.signals.source)
    && nonempty(request.signals.region) && nonempty(request.signals.network)
    && (request.signals.source !== 'none' || request.signals.region === 'unknown' && request.signals.network === 'unknown')
    && (request.signals.hour === null || Number.isInteger(request.signals.hour) && request.signals.hour >= 0 && request.signals.hour <= 23);
}
const respond = (request, decision, reasonCode, ruleId) => ({
  schema: 'aleph.decision.v1', requestId: typeof request?.requestId === 'string' ? request.requestId : '',
  decision, reasonCode, ruleIds: [ruleId],
});

export async function decide(request) {
  if (!validRequest(request) || request.deviceRegistered !== true) {
    return respond(request, 'deny', 'device_not_registered', 'device_registered');
  }
  // The current engine contract cannot prove resource ownership or instructor
  // membership for a mutation. Never grant writes from a caller's role claims.
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
    return respond(request, 'deny', 'write_not_allowed', 'write_not_allowed');
  }
  if (request.service !== 'notes' || !request.route.startsWith(`${request.method} `)
      || !Object.hasOwn(READ_PATHS, request.route) || !READ_PATHS[request.route].test(request.path)) {
    return respond(request, 'deny', 'route_not_allowed', 'route_not_allowed');
  }
  if (['export', 'backup', 'restore', 'admin', 'all', 'upload'].includes(request.path.split('/').at(-1)) || request.queryLength !== 0) {
    return respond(request, 'deny', 'route_not_allowed', 'resource_zones');
  }
  // These synthetic signals are practice/judge data, not verified real-world location.
  // No client-supplied location headers are promoted into engine signals.
  if (request.signals.source === 'judge_fixture') {
    const foreign = request.signals.region === 'foreign';
    const unusual = request.signals.network === 'unusual';
    const late = request.signals.hour !== null && (request.signals.hour < 6 || request.signals.hour >= 23);
    const burst = request.recentEvents.some(event => event.kind === 'risk_signal' && event.ageSeconds <= 300 && event.count >= 10);
    const compoundRisk = foreign && burst || unusual && late && burst || foreign && unusual && late;
    if (compoundRisk && !(request.stepUp.verified === true && request.stepUp.authAgeSeconds <= 900)) {
      return respond(request, 'step_up', 'step_up_required', 'step_up_required');
    }
  }
  // The policy scopes routes; the final notes API compares the verified user
  // with the stored owner in every query. subjectId is not a Supabase UUID.
  return respond(request, 'allow', 'approved', 'resource_zones');
}
