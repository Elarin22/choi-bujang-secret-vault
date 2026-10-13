// 8단계: 요청마다 서버가 구별할 수 있는 자원 ID. 자료실의 구역 두 개를 서로 다른 종류로 표시합니다.
// 기존 자료 id와 API 주소는 그대로 두고, 응답 헤더 X-Resource-Id로만 종류를 덧붙입니다.
export const RESOURCE_KINDS = Object.freeze({ note: 'note', notice: 'notice' });

export function resourceId(kind, id) {
  if (!Object.values(RESOURCE_KINDS).includes(kind) || typeof id !== 'string' || !id) throw new Error('자원 종류나 id가 맞지 않습니다.');
  return `${kind}:${id}`;
}

export function parseResourceId(value) {
  const [kind, id, ...rest] = String(value).split(':');
  return Object.values(RESOURCE_KINDS).includes(kind) && id && !rest.length ? { kind, id } : null;
}
