// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  return {
    renderIdentity({ me, devices, sessions } = {}) {
      const root = document.createElement('section');
      root.className = 'student-identity';
      root.setAttribute('aria-label', '학생 구현: 로그인 사용자·기기·세션');

      const node = (tag, text, className) => {
        const element = document.createElement(tag);
        element.textContent = text;
        if (className) element.className = className;
        return element;
      };
      const addMode = (parent, resource) => {
        const modeText = {
          demo: '예제 자료',
          disconnected: '연결 없음',
          unknown: '확인 불가',
        }[resource?.mode];
        if (modeText) parent.append(node('p', modeText, 'student-identity-mode'));
      };
      const addResourceState = (parent, resource, label) => {
        addMode(parent, resource);
        if (resource?.status === 'loading') {
          parent.append(node('p', '불러오는 중', 'student-identity-loading'));
          return false;
        }
        if (resource?.status === 'error') {
          const message = resource.error?.message || '확인 불가';
          parent.append(node('p', `연결 실패: ${message}`, 'student-identity-error'));
          return false;
        }
        if (resource?.status !== 'ok') {
          parent.append(node('p', `${label}: 확인 불가`, 'student-identity-unknown'));
          return false;
        }
        return true;
      };
      const deviceStatus = (status) => ({
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      }[status] || '확인 불가');
      const sessionStatus = (status) => ({
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      }[status] || '확인 불가');

      const account = node('div', null, 'student-identity-account');
      root.append(node('h3', '로그인 사용자'));
      root.append(account);
      if (addResourceState(account, me, '로그인 사용자')) {
        const user = me.data?.user;
        if (user) account.append(node('p', `${user.label || '이름 확인 불가'} · ID: ${user.id || '확인 불가'}`));
        else account.append(node('p', '로그인 사용자: 확인 불가', 'student-identity-unknown'));
      }

      const deviceSection = node('div', null, 'student-identity-devices');
      root.append(node('h3', '기기'));
      root.append(deviceSection);
      if (me?.status === 'ok' && me.data?.device) {
        const device = me.data.device;
        deviceSection.append(node('p', `현재 기기: ${device.label || '이름 확인 불가'} · ID: ${device.id || '확인 불가'} · ${deviceStatus(device.status)}`));
      }
      if (addResourceState(deviceSection, devices, '기기 목록')) {
        const list = node('ul', null, 'student-identity-list');
        for (const device of Array.isArray(devices.data) ? devices.data : []) {
          list.append(node('li', `${device.label || '이름 확인 불가'} · ID: ${device.id || '확인 불가'} · ${deviceStatus(device.status)}`));
        }
        if (!list.childNodes.length) deviceSection.append(node('p', '표시할 기기가 없습니다.'));
        else deviceSection.append(list);
      }

      const sessionSection = node('div', null, 'student-identity-sessions');
      root.append(node('h3', '로그인 세션'));
      root.append(sessionSection);
      if (me?.status === 'ok' && me.data?.session) {
        const session = me.data.session;
        sessionSection.append(node('p', `현재 세션: ID ${session.id || '확인 불가'} · ${sessionStatus(session.status)}`));
      }
      if (addResourceState(sessionSection, sessions, '세션 목록')) {
        const list = node('ul', null, 'student-identity-list');
        for (const session of Array.isArray(sessions.data) ? sessions.data : []) {
          list.append(node('li', `ID: ${session.id || '확인 불가'} · ${sessionStatus(session.status)}`));
        }
        if (!list.childNodes.length) sessionSection.append(node('p', '표시할 세션이 없습니다.'));
        else sessionSection.append(list);
      }

      return root;
    },
    renderDecision() { return '학생 구현 대기: 서버의 판정과 이유를 연결하세요.'; },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
