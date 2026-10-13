import { connectionView } from './connection-model.js';

// 화면 잠금 장치일 뿐입니다. 실제 방어는 서버와 판정기가 요청마다 다시 합니다.
// 요청 전·후에 승인을 다시 확인하고, 승인이 철회되거나 오프라인이 되면 이미 받은 응답도 그리지 않습니다.
export function createApprovedAccess({ readState, isOnline, onLock }) {
  let epoch = 0;
  const invalidate = () => { epoch += 1; onLock(); };
  async function check() {
    if (!isOnline()) return false;
    try { return connectionView(await readState(), isOnline()).canOpen; } catch { return false; }
  }
  async function run(action) {
    const current = epoch;
    if (!await check() || current !== epoch) { onLock(); return { allowed: false }; }
    const value = await action();
    if (current !== epoch || !await check() || current !== epoch) { onLock(); return { allowed: false }; }
    return { allowed: true, value };
  }
  return { run, invalidate };
}
