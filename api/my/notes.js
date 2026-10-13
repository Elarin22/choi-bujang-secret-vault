import { collection, send } from '../../lib/notes.mjs';
import { getDeps } from '../../lib/server.mjs';

// 내 메모 목록 전용 경로: 읽기만 받고, 목록은 검증된 사용자의 owner_id로만 걸러 줍니다.
export default (req, res) => {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return send(res, 405, { error: '허용되지 않는 요청 방식입니다.' });
  }
  return collection(req, res, getDeps);
};
