// 탈환 작전실 화면이 서버 요약(/api/ops-summary)을 어떻게 보여 줄지 정하는 순수 함수입니다(브라우저와 Node 시험이 같은 파일을 씁니다).
// 화면은 성공 문구를 만들지 않습니다. 서버가 돌려준 status 이름을 그대로 한국어 라벨로 바꿔 보여 줄 뿐이고,
// 모르는 값이나 빠진 값은 「미확인」으로 둡니다. 가상 메모 본문은 이 요약에 없으며 여기서도 다루지 않습니다.
export const SUMMARY_SCHEMA = 'vault.ops.summary.v1';
export const STATUS_LABEL = Object.freeze({
  confirmed_now: '서버가 방금 확인함',
  declared_code: '코드에 적힘 · 시험하지 않음',
  not_connected: '미연결',
  not_run: '미실행',
});
export const statusLabel = (status) => STATUS_LABEL[status] ?? '미확인';

const count = (value) => (Number.isSafeInteger(value) && value >= 0 ? String(value) : '미확인');
const text = (value) => (typeof value === 'string' && value ? value : '미확인');

export function summaryRows(summary) {
  if (!summary || summary.schema !== SUMMARY_SCHEMA) return [];
  const { device, decider, detection, revocation, recovery } = summary;
  const rows = [
    { area: '기기 승인', item: '승인 상태', value: text(device?.approval), status: device?.status },
    { area: '판정기 규칙', item: '규칙 수', value: count(decider?.ruleCount), status: decider?.status },
    { area: '판정기 규칙', item: '규칙 이름', value: Array.isArray(decider?.ruleIds) ? decider.ruleIds.join(', ') : '미확인', status: decider?.status },
    { area: '판정기 규칙', item: '허용 경로 수', value: count(decider?.allowedRoutes), status: decider?.status },
    { area: '판정기 규칙', item: '심판 판정 결과', value: '없음', status: decider?.judgeVerdict?.status },
    { area: '탐지 사건', item: `${text(detection?.rule)} 기준`, value: `${count(detection?.windowMinutes)}분 안 GET ${count(detection?.limit)}건 초과`, status: detection?.status },
    { area: '탐지 사건', item: '받은 사건 수', value: detection?.events?.count === null ? '없음' : count(detection?.events?.count), status: detection?.events?.status },
    { area: '회수 상태', item: '실제 회수', value: revocation?.proposalOnly === true ? '제안만 만들고 집행하지 않음' : '미확인', status: revocation?.status },
    { area: '복구 버전', item: '정책 사본 버전', value: count(recovery?.backupRevision), status: recovery?.status },
    { area: '복구 버전', item: '현재 시험 정책 버전', value: count(recovery?.currentRevision), status: recovery?.status },
    { area: '복구 버전', item: '현재 정책과 사본', value: recovery?.policyMatchesBackup === true ? '같음' : recovery?.policyMatchesBackup === false ? `다름${recovery?.reason ? ` (${recovery.reason})` : ''}` : '미확인', status: recovery?.status },
    { area: '복구 버전', item: '감사 기록 줄 수', value: count(recovery?.auditEntries), status: recovery?.status },
    { area: '복구 버전', item: '메모 한 건 복원 실행', value: '실행 기록 없음', status: recovery?.noteRestoreRun?.status },
  ];
  return rows.map((row) => ({ ...row, label: statusLabel(row.status) }));
}

// 요약 속 승인 상태와 같은 때 따로 부른 /api/device-status 응답을 맞대어 봅니다.
// 요청 ID·시각은 요청마다 달라서 비교하지 않고, 승인 값과 연결 여부만 비교합니다.
export function crossCheck(summary, direct) {
  if (!summary || summary.schema !== SUMMARY_SCHEMA || !direct || typeof direct !== 'object') {
    return { match: null, detail: '비교할 응답이 없어 일치 여부를 알 수 없습니다.' };
  }
  const connectedSummary = summary.device?.status === 'confirmed_now';
  const connectedDirect = direct.connected === true && direct.authority === 'ALEPH SDP engine';
  const same = summary.device?.approval === direct.approval && connectedSummary === connectedDirect;
  return { match: same, detail: same ? '요약과 승인 상태 응답이 같습니다.' : '요약과 승인 상태 응답이 서로 다릅니다. 이 화면의 수치를 믿지 마세요.' };
}