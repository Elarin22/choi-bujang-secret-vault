// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  let eventFilters = { kind: 'all', appId: 'all', access: 'all', expandedId: null };
  let eventDataSignature = null;
  const resetEventView = () => {
    eventFilters = { kind: 'all', appId: 'all', access: 'all', expandedId: null };
  };

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
        deviceSection.append(node('p', `현재 기기: ${device.label || '이름 확인 불가'} · ID: ${device.id || '확인 불가'} · ${deviceStatus(device.status)} (${device.status || 'unknown'})`));
      }
      if (addResourceState(deviceSection, devices, '기기 목록')) {
        const list = node('ul', null, 'student-identity-list');
        for (const device of Array.isArray(devices.data) ? devices.data : []) {
          list.append(node('li', `${device.label || '이름 확인 불가'} · ID: ${device.id || '확인 불가'} · ${deviceStatus(device.status)} (${device.status || 'unknown'})`));
        }
        if (!list.childNodes.length) deviceSection.append(node('p', '표시할 기기가 없습니다.'));
        else deviceSection.append(list);
      }

      const sessionSection = node('div', null, 'student-identity-sessions');
      root.append(node('h3', '로그인 세션'));
      root.append(sessionSection);
      if (me?.status === 'ok' && me.data?.session) {
        const session = me.data.session;
        sessionSection.append(node('p', `현재 세션: ID ${session.id || '확인 불가'} · ${sessionStatus(session.status)} (${session.status || 'unknown'})`));
      }
      if (addResourceState(sessionSection, sessions, '세션 목록')) {
        const list = node('ul', null, 'student-identity-list');
        for (const session of Array.isArray(sessions.data) ? sessions.data : []) {
          list.append(node('li', `ID: ${session.id || '확인 불가'} · ${sessionStatus(session.status)} (${session.status || 'unknown'})`));
        }
        if (!list.childNodes.length) sessionSection.append(node('p', '표시할 세션이 없습니다.'));
        else sessionSection.append(list);
      }

      return root;
    },
    renderDecision({ status, data, error, appId } = {}) {
      const root = document.createElement('section');
      root.className = 'student-decision';
      root.setAttribute('aria-label', '학생 구현: 업무 앱 접근 판정');

      const addText = (tag, text, className) => {
        const element = document.createElement(tag);
        element.textContent = text;
        if (className) element.className = className;
        root.append(element);
      };
      addText('h3', '업무 앱 접근 요청 결과');

      if (status === 'idle') {
        addText('p', '업무 앱을 골라 접속을 요청하세요.', 'student-decision-idle');
        return root;
      }
      if (status === 'loading') {
        addText('p', '접근 판정 확인 중', 'student-decision-loading');
        if (appId) addText('p', `앱 ID: ${appId}`);
        return root;
      }
      if (status === 'error') {
        if (appId) addText('p', `앱 ID: ${appId}`);
        addText('p', `요청 실패: ${error?.message || '오류 내용을 확인할 수 없습니다.'}`, 'student-decision-error');
        addText('p', '요청 실패는 접근 거부 판정이 아닙니다.');
        return root;
      }
      if (status !== 'ok') {
        addText('p', '판정 확인 불가 (unknown)', 'student-decision-unknown');
        return root;
      }

      const decision = data?.decision;
      const labels = {
        allow: '접근 허용',
        deny: '접근 거부',
        challenge: '추가 인증 또는 확인 필요',
        unknown: '확인 불가',
      };
      const hasKnownDecision = typeof decision === 'string' && Object.hasOwn(labels, decision);
      const decisionText = hasKnownDecision
        ? `${labels[decision]} (${decision})`
        : `확인 불가 (unknown${decision == null ? '' : `; 원래 값: ${String(decision)}`})`;
      const resultAppId = data?.appId || appId || '확인 불가';
      addText('p', `앱 ID: ${resultAppId}`);
      addText('p', decisionText, decision === 'deny' ? 'student-decision-deny' : 'student-decision-result');
      addText('p', `판정 이유: ${data?.reason || '이유를 확인할 수 없습니다.'}`);
      addText('p', `판정 시각: ${data?.checkedAt || '시각을 확인할 수 없습니다.'}`);
      if (decision === 'allow') addText('p', '접근 허용은 정책 판정이며 실제 앱 접속 성공을 보장하지 않습니다.');
      if (decision === 'challenge') addText('p', '이 앱이 추가 인증 또는 확인 절차를 대신 수행하지 않습니다.');
      return root;
    },
    renderEvents({ status, mode, data, error } = {}) {
      const root = document.createElement('section');
      root.className = 'student-events';
      root.setAttribute('aria-label', '학생 구현: 내 접속 기록과 XDR 경보');
      const make = (tag, text, className) => {
        const element = document.createElement(tag);
        if (text !== undefined && text !== null) element.textContent = text;
        if (className) element.className = className;
        return element;
      };
      const title = make('h3', '내 접속 기록과 XDR 경보');
      root.append(title);

      if (status === 'loading') {
        resetEventView();
        eventDataSignature = null;
        root.append(make('p', '기록을 불러오는 중', 'student-events-loading'));
        return root;
      }
      if (status === 'error') {
        resetEventView();
        eventDataSignature = null;
        const message = error?.message || '오류 내용을 확인할 수 없습니다.';
        if (error?.code === 'CONTRACT_MISMATCH' || error?.code === 'ENGINE_RESULT_UNVERIFIED') {
          root.append(make('p', `기록 확인 불가: ${message}`, 'student-events-unknown'));
        } else {
          root.append(make('p', `기록을 불러오지 못했습니다: ${message}`, 'student-events-error'));
        }
        return root;
      }
      if (status !== 'ok' || !Array.isArray(data)) {
        resetEventView();
        eventDataSignature = null;
        root.append(make('p', '기록 확인 불가', 'student-events-unknown'));
        return root;
      }

      const signature = JSON.stringify(data);
      if (signature !== eventDataSignature) resetEventView();
      eventDataSignature = signature;
      root.append(make('p', '서버가 전달한 본인 기록만 표시합니다. 전체 로그나 다른 사용자 기록은 아닙니다.', 'student-events-scope'));
      if (mode === 'demo') root.append(make('p', '예제 자료', 'student-events-mode'));

      const accessLabels = { allowed: '접근 허용', denied: '접근 거부', unknown: '확인 불가' };
      const sessionLabels = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      const deviceLabels = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const stateText = (kind, value) => {
        const labels = { access: accessLabels, session: sessionLabels, device: deviceLabels }[kind];
        if (typeof value === 'string' && Object.hasOwn(labels, value)) return `${labels[value]} (${value})`;
        return `확인 불가 (unknown${value == null ? '' : `; 원래 값: ${String(value)}`})`;
      };
      const kindText = (kind) => ({ access: '접속 기록', xdr: 'XDR 경보' }[kind] || `확인 불가 (${String(kind)})`);
      const appText = (appId) => appId ? String(appId) : '앱을 확인할 수 없음 (appId 없음)';
      const sortedEvents = [...data].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));

      const filterRow = make('div', undefined, 'student-events-filters');
      const choices = [
        { key: 'kind', label: '기록 종류', values: [...new Set(data.map((event) => event.kind))].sort(), text: kindText },
        { key: 'appId', label: '업무 앱', values: [...new Set(data.map((event) => event.appId).filter((value) => typeof value === 'string'))].sort(), text: (value) => value },
        { key: 'access', label: '접속 상태', values: [...new Set(data.map((event) => event.state?.access))].filter((value) => typeof value === 'string').sort(), text: (value) => stateText('access', value) },
      ];
      for (const choice of choices) {
        const label = make('label', choice.label, 'student-events-filter');
        const select = document.createElement('select');
        select.setAttribute('aria-label', choice.label);
        const allOption = document.createElement('option');
        allOption.value = 'all';
        allOption.textContent = '전체';
        select.append(allOption);
        for (const value of choice.values) {
          const option = document.createElement('option');
          option.value = value;
          option.textContent = choice.text(value);
          select.append(option);
        }
        select.value = eventFilters[choice.key];
        select.addEventListener('change', () => {
          eventFilters[choice.key] = select.value;
          eventFilters.expandedId = null;
          drawList();
        });
        label.append(select);
        filterRow.append(label);
      }
      root.append(filterRow);

      const list = make('ul', undefined, 'student-events-list');
      root.append(list);
      const addTextRows = (parent, heading, rows) => {
        parent.append(make('h4', heading));
        if (!Array.isArray(rows) || rows.length === 0) {
          parent.append(make('p', '없음'));
          return;
        }
        const items = make('ul');
        for (const row of rows) items.append(make('li', `${row.id || 'ID 확인 불가'}: ${row.text ?? ''}`));
        parent.append(items);
      };
      const detailFor = (event) => {
        const detail = make('section', undefined, 'student-event-detail');
        detail.setAttribute('data-student-event-detail', event.id);
        detail.hidden = eventFilters.expandedId !== event.id;
        detail.append(make('h4', '기록 상세'));
        detail.append(make('p', `사건 ID: ${event.id}`));
        detail.append(make('p', `업무 앱: ${appText(event.appId)}`));
        addTextRows(detail, '근거', event.evidence);
        addTextRows(detail, '규칙', event.rules);
        detail.append(make('h4', '현재 상태'));
        for (const [key, label] of [['access', '접속'], ['session', '세션'], ['device', '기기']]) {
          detail.append(make('p', `${label}: ${stateText(key, event.state?.[key])}`));
        }
        return detail;
      };
      function drawList() {
        list.replaceChildren();
        const visible = sortedEvents.filter((event) =>
          (eventFilters.kind === 'all' || event.kind === eventFilters.kind)
          && (eventFilters.appId === 'all' || event.appId === eventFilters.appId)
          && (eventFilters.access === 'all' || event.state?.access === eventFilters.access));
        if (visible.length === 0) {
          list.append(make('li', '선택한 조건에 맞는 기록이 없습니다.', 'student-events-filter-empty'));
          return;
        }
        for (const event of visible) {
          const item = make('li', undefined, 'student-event');
          item.setAttribute('data-student-event-id', event.id);
          item.append(make('h4', event.summary || '요약 없음'));
          item.append(make('p', `사건 ID: ${event.id} · 시각: ${event.at} · 종류: ${kindText(event.kind)} · 업무 앱: ${appText(event.appId)}`));
          const button = make('button', '상세 보기', 'student-event-detail-button');
          button.type = 'button';
          button.setAttribute('aria-label', `${event.id} 상세`);
          button.setAttribute('aria-expanded', eventFilters.expandedId === event.id ? 'true' : 'false');
          const detail = detailFor(event);
          button.addEventListener('click', () => {
            eventFilters.expandedId = eventFilters.expandedId === event.id ? null : event.id;
            detail.hidden = eventFilters.expandedId !== event.id;
            button.setAttribute('aria-expanded', detail.hidden ? 'false' : 'true');
          });
          item.append(button, detail);
          list.append(item);
        }
      }
      drawList();
      if (data.length === 0) {
        filterRow.hidden = true;
        list.replaceChildren(make('li', '표시할 기록이 없습니다.', 'student-events-empty'));
      }
      return root;
    },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
