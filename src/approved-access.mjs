import { connectionView } from './connection-model.mjs';

// UI gate only: the API independently verifies each protected request.
export function createApprovedAccess({ readState, isOnline, onLock }) {
  let epoch = 0;
  const invalidate = () => { epoch++; onLock(); };
  async function check() {
    if (!isOnline()) return false;
    try { return connectionView(await readState(), isOnline()).canOpen; }
    catch { return false; }
  }
  async function run(action) {
    const current = epoch;
    if (!await check() || current !== epoch) { onLock(); return { allowed: false }; }
    const value = await action();
    // Do not paint an in-flight response after revocation, logout or going offline.
    if (current !== epoch || !await check() || current !== epoch) {
      onLock(); return { allowed: false };
    }
    return { allowed: true, value };
  }
  return { run, invalidate };
}
