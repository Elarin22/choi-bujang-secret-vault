import { randomUUID } from 'node:crypto';
import { unavailableConnection } from '../public/connection-model.js';

// 서버 전용 연결부입니다. 헤더·쿠키·본문·"앱 설치됨" 표시는 기기 승인으로 쓰지 않습니다.
// 기기 승인 확인은 운영 반 엔진이 제공하는 공식 어댑터가 현재 사용자·기기·이 요청을 확인해 돌려준 결과만 믿습니다.
// 현재 이 프로젝트에는 그 어댑터가 제공되지 않았으므로 officialAdapter는 null이고, 모든 승인 확인은 닫힌 채로 실패합니다.
//   어댑터 모양: { getApproval(req, user) → 'approved' | 'pending' | 'denied', requestApproval(req, user) → 'pending' | 'approved' | 'denied' }
export const officialAdapter = null;
const KNOWN = ['approved', 'pending', 'denied'];

export function createDeviceService({ adapter = officialAdapter, now = () => new Date(), makeId = randomUUID } = {}) {
  const closed = () => unavailableConnection(makeId(), now().toISOString());
  const open = (approval) => ({ schema: 'vault.connection.v1', authority: 'ALEPH SDP engine', connected: true,
    approval, provider: 'ALEPH SDP engine', requestId: makeId(), checkedAt: now().toISOString() });
  return {
    // 승인 상태 조회: 어댑터가 없거나 실패하거나 모르는 값을 주면 닫힌 상태(unavailable)입니다.
    async status(req, user = null) {
      if (!adapter || typeof adapter.getApproval !== 'function') return closed();
      try {
        const approval = await adapter.getApproval(req, user);
        return KNOWN.includes(approval) ? open(approval) : closed();
      } catch { return closed(); }
    },
    // 승인 요청: 요청을 엔진에 전달할 뿐 권한을 바꾸지 않습니다. 결과는 엔진이 돌려준 값만 따릅니다.
    async request(req, user = null) {
      if (!adapter || typeof adapter.requestApproval !== 'function') return { ok: false, state: closed() };
      try {
        const approval = await adapter.requestApproval(req, user);
        return KNOWN.includes(approval) ? { ok: true, state: open(approval) } : { ok: false, state: closed() };
      } catch { return { ok: false, state: closed() }; }
    },
    // 보호 요청 하나가 승인된 기기에서 왔는지: true일 때만 통과합니다. 어댑터가 없으면 던집니다(닫힌 실패).
    async isApproved(req, user) {
      if (!adapter || typeof adapter.getApproval !== 'function') throw new Error('official_adapter_not_provided');
      return (await adapter.getApproval(req, user)) === 'approved';
    },
  };
}

export const deviceService = createDeviceService();

// 서버가 자료 API에서 승인을 다시 확인하도록 켜는 스위치(환경변수 REQUIRE_DEVICE_APPROVAL=1). 기본은 꺼짐이라 기존 정상·거부 결과가 그대로입니다.
export async function requireApprovedRequest(req, user, res, { enforce = process.env.REQUIRE_DEVICE_APPROVAL === '1', service = deviceService } = {}) {
  if (!enforce) return true;
  try {
    if (await service.isApproved(req, user) === true) return true;
    res.status(403).json({ error: '이 기기의 승인이 확인되지 않았습니다.', reason: 'device_approval_required' });
  } catch {
    res.status(503).json({ error: '기기 승인을 확인하지 못해 요청을 막았습니다.', reason: 'device_verification_unavailable' });
  }
  return false;
}

const headers = (res) => { res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); };

export function createStatusHandler({ service = deviceService } = {}) {
  return async (req, res) => {
    headers(res);
    if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); return res.status(405).json({ error: '허용되지 않는 요청 방식입니다.' }); }
    return res.status(200).json(await service.status(req, null));
  };
}

export function createApprovalHandler({ service = deviceService } = {}) {
  return async (req, res) => {
    headers(res);
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).json({ error: '허용되지 않는 요청 방식입니다.' }); }
    const { ok, state } = await service.request(req, null);
    return res.status(ok ? 200 : 503).json(ok ? state : { ...state, error: 'official_adapter_not_provided' });
  };
}
