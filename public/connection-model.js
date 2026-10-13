// 기기 승인 상태를 화면에 어떻게 보여 줄지 정하는 순수 함수입니다(브라우저와 Node 시험이 같은 파일을 씁니다).
// 설치 표시나 '승인 요청' 버튼만으로는 열리지 않습니다. 서버가 엔진 확인 결과를 신선하게 돌려줄 때만 canOpen이 true입니다.
export const MAX_STATE_AGE_MS = 30000;

export function connectionView(state, online = true, now = Date.now()) {
  if (!online) return { label: '오프라인', canOpen: false, detail: '연결이 돌아오면 승인 상태를 다시 확인합니다. 오프라인에서는 자료를 열지 않습니다.' };
  const at = typeof state?.checkedAt === 'string' ? Date.parse(state.checkedAt) : NaN;
  if (!state || state.schema !== 'vault.connection.v1' || state.authority !== 'ALEPH SDP engine' || state.connected !== true
    || !Number.isFinite(at) || Math.abs(now - at) > MAX_STATE_AGE_MS) {
    return { label: '공식 접속 도구 미연결', canOpen: false, detail: '반별 접속 도구 연결 안내가 필요합니다. 앱 설치 표시나 요청 버튼만으로 기기 승인이 끝나지 않습니다.' };
  }
  if (state.approval === 'approved') return { label: '서버에서 승인 확인', canOpen: true, detail: '보호 요청은 서버와 판정기가 요청마다 다시 확인합니다.' };
  if (state.approval === 'pending') return { label: '승인 대기', canOpen: false, detail: '승인이 확인되기 전에는 자료를 표시하지 않습니다.' };
  return { label: '승인되지 않음', canOpen: false, detail: '승인이 확인되기 전에는 자료를 표시하지 않습니다.' };
}

// 승인 확인 연결이 없거나 실패했을 때 서버가 돌려주는 닫힌 상태입니다.
export function unavailableConnection(requestId, checkedAt) {
  return { schema: 'vault.connection.v1', authority: 'student_server', connected: false,
    approval: 'unavailable', provider: 'ALEPH SDP engine', requestId, checkedAt };
}
