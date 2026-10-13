export function connectionView(state, online = true) {
  if (!online) return { label: '오프라인', canOpen: false, detail: '연결이 돌아오면 승인 상태를 다시 확인합니다.' };
  const at = typeof state?.checkedAt === 'string' ? Date.parse(state.checkedAt) : NaN;
  if (!state || state.schema !== 'vault.connection.v1' || state.authority !== 'ALEPH SDP engine' || state.connected !== true
    || !Number.isFinite(at) || Math.abs(Date.now() - at) > 30000) {
    return { label: '공식 접속 도구 미연결', canOpen: false, detail: '반별 접속 도구 연결 안내가 필요합니다. 설치 표시나 요청 버튼만으로 승인이 완료되지 않습니다.' };
  }
  if (state.approval === 'approved') return { label: '서버에서 승인 확인', canOpen: true, detail: '보호 요청은 제공 엔진과 자료 API에서 다시 확인합니다.' };
  return { label: state.approval === 'pending' ? '승인 대기' : '승인되지 않음', canOpen: false, detail: '승인 확인 전에는 자료를 표시하지 않습니다.' };
}

export function unavailableConnection(requestId, checkedAt) {
  return { schema: 'vault.connection.v1', authority: 'student_server', connected: false,
    approval: 'unavailable', provider: 'ALEPH SDP engine', requestId, checkedAt };
}
