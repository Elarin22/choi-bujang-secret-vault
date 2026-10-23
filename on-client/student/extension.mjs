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
        const actions = Array.isArray(event.supportedActions) ? event.supportedActions : [];
        if (actions.length > 0) {
          detail.append(make('h4', '미지원 조치'));
          detail.append(make('p', '조치 실행 연결은 준비 중입니다. 이 버튼은 요청을 보내지 않습니다.'));
          for (const action of actions) {
            const button = make('button', `${action} 미지원`, 'student-unsupported-action');
            button.type = 'button';
            button.disabled = true;
            button.setAttribute('aria-disabled', 'true');
            button.setAttribute('aria-label', `${action} 미지원`);
            detail.append(button);
          }
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
    renderStatus({ devices, sessions, notifications, diagnostics, mode } = {}) {
      const root = document.createElement('section');
      root.className = 'student-status';
      root.setAttribute('aria-label', '학생 구현: 상태·알림·도움정보');
      const make = (tag, text, className) => {
        const element = document.createElement(tag);
        if (text !== undefined && text !== null) element.textContent = text;
        if (className) element.className = className;
        return element;
      };
      const modeLabels = { connected: '연결됨', demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };
      const safeMode = Object.hasOwn(modeLabels, mode) ? mode : 'unknown';
      const deviceLabels = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const sessionLabels = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      const stateText = (labels, value) => typeof value === 'string' && Object.hasOwn(labels, value)
        ? `${labels[value]} (${value})`
        : `확인 불가 (unknown${value == null ? '' : `; 원래 값: ${String(value)}`})`;
      const safeCode = (value) => typeof value === 'string' && /^[A-Za-z0-9._:-]{1,80}$/.test(value) ? value : 'UNKNOWN';
      const safeText = (value, fallback = '확인 불가') => typeof value === 'string' ? value : fallback;
      const section = (name) => {
        const element = make('section', undefined, 'student-status-section');
        element.append(make('h4', name));
        root.append(element);
        return element;
      };

      root.append(make('h3', '상태·알림·도움정보'));
      root.append(make('p', `연결 모드: ${modeLabels[safeMode]}`));
      const deviceSection = section('기기');
      const sessionSection = section('현재 세션');
      const retryLine = '다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.';
      const showResourceError = (target, name, resource) => {
        const message = safeText(resource?.error?.message, '오류 내용을 확인할 수 없습니다.');
        const timeout = ['TIMEOUT', 'REQUEST_TIMEOUT', 'ENGINE_TIMEOUT'].includes(resource?.error?.code)
          || /시간이 초과|시간 초과|타임아웃/i.test(message);
        target.append(make('p', `${name}${timeout ? ' 요청 시간 초과' : '을(를) 불러오지 못했습니다'}: ${message}`, 'student-status-error'));
        target.append(make('p', retryLine));
      };
      const renderDevices = () => {
        if (devices?.status === 'loading') {
          deviceSection.append(make('p', '기기 목록을 불러오는 중'));
          return;
        }
        if (devices?.status === 'error') {
          showResourceError(deviceSection, '기기 목록', devices);
          return;
        }
        if (devices?.status !== 'ok' || !Array.isArray(devices.data)) {
          deviceSection.append(make('p', '기기 목록을 확인할 수 없습니다.'));
          return;
        }
        if (devices.data.length === 0) {
          deviceSection.append(make('p', '등록된 기기가 없습니다.'));
          return;
        }
        const list = make('ul');
        for (const device of devices.data) {
          list.append(make('li', `${safeText(device.label, '기기 이름 확인 불가')} · 보안 상태: ${stateText(deviceLabels, device.status)}`));
        }
        deviceSection.append(list);
      };
      const renderSessions = () => {
        sessionSection.append(make('p', '세션 정보는 현재 검증된 연결 하나만 표시하며, 지난 세션 목록이 아닙니다.'));
        if (sessions?.status === 'loading') {
          sessionSection.append(make('p', '현재 연결 정보를 불러오는 중'));
          return;
        }
        if (sessions?.status === 'error') {
          showResourceError(sessionSection, '현재 연결 정보', sessions);
          return;
        }
        if (sessions?.status !== 'ok' || !Array.isArray(sessions.data)) {
          sessionSection.append(make('p', '현재 연결 정보를 확인할 수 없습니다.'));
          return;
        }
        if (sessions.data.length === 0) {
          sessionSection.append(make('p', '현재 연결이 없습니다.'));
          return;
        }
        const list = make('ul');
        for (const session of sessions.data) {
          list.append(make('li', `세션 ID: ${safeText(session.id, '확인 불가')} · 상태: ${stateText(sessionLabels, session.status)}`));
        }
        sessionSection.append(list);
      };
      renderDevices();
      renderSessions();

      const notificationSection = section('주의 알림');
      if (!Array.isArray(notifications) || notifications.length === 0) {
        notificationSection.append(make('p', '주의할 알림이 없습니다.'));
      } else {
        const resourceNames = {
          me: '로그인 정보', apps: '업무 앱', events: '보안 기록', devices: '기기',
          sessions: '세션', access: '접속 판정', diagnostics: '도움정보',
        };
        const list = make('ul');
        for (const notification of notifications) {
          const resource = safeCode(notification?.resource);
          const code = safeCode(notification?.code);
          const resourceLabel = resourceNames[resource] || '기타 자료';
          list.append(make('li', `자료: ${resourceLabel} (${resource}) · 코드: ${code} · ${safeText(notification?.message, '알림 내용을 확인할 수 없습니다.')}`));
        }
        notificationSection.append(list);
      }

      const diagnosticsSection = section('비밀 없는 진단 정보');
      let safeDiagnostics = null;
      if (diagnostics?.status === 'loading') {
        diagnosticsSection.append(make('p', '진단 정보를 불러오는 중'));
      } else if (diagnostics?.status === 'error') {
        diagnosticsSection.append(make('p', `진단 정보를 불러오지 못했습니다: ${safeText(diagnostics.error?.message, '오류 내용을 확인할 수 없습니다.')}`));
      } else if (diagnostics?.status === 'ok' && diagnostics.data) {
        const data = diagnostics.data;
        const safeField = (value, pattern) => typeof value === 'string' && pattern.test(value) ? value : '확인 불가';
        const engineMode = ['connected', 'demo', 'disconnected', 'unknown'].includes(data.engine?.mode) ? data.engine.mode : 'unknown';
        safeDiagnostics = {
          requestId: safeField(data.requestId, /^[0-9a-f-]{36}$/i),
          component: safeField(data.component, /^[A-Za-z0-9._-]{1,64}$/),
          version: safeField(data.version, /^[A-Za-z0-9.+_-]{1,64}$/),
          checkedAt: safeField(data.checkedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/),
          engine: {
            mode: engineMode,
            code: safeField(data.engine?.code, /^[A-Z0-9_:-]{1,80}$/),
          },
        };
        for (const [label, value] of [
          ['requestId', safeDiagnostics.requestId], ['component', safeDiagnostics.component],
          ['version', safeDiagnostics.version], ['checkedAt', safeDiagnostics.checkedAt],
          ['engine.mode', safeDiagnostics.engine.mode], ['engine.code', safeDiagnostics.engine.code],
        ]) diagnosticsSection.append(make('p', `${label}: ${value}`));
      } else {
        diagnosticsSection.append(make('p', '진단 정보가 아직 조회되지 않았습니다. 제공 화면의 「도움정보 불러오기」를 누르세요.'));
      }

      root.append(make('p', '도움 요청에 사용할 상태와 비밀 없는 진단 항목을 복사합니다. 복사한 정보는 자동 전송되지 않습니다.'));
      const copyStatus = make('p', '', 'student-status-copy-result');
      copyStatus.setAttribute('role', 'status');
      copyStatus.setAttribute('aria-live', 'polite');
      const copyButton = make('button', '도움정보 복사', 'student-status-copy');
      copyButton.type = 'button';
      copyButton.setAttribute('aria-label', '도움정보 복사');
      copyButton.addEventListener('click', async () => {
        const payload = {
          mode: safeMode,
          devices: {
            status: safeCode(devices?.status),
            ...(devices?.status === 'ok' && Array.isArray(devices.data)
              ? { data: devices.data.map((device) => ({ label: safeText(device.label), status: safeCode(device.status) })) }
              : {}),
          },
          sessions: {
            status: safeCode(sessions?.status),
            ...(sessions?.status === 'ok' && Array.isArray(sessions.data)
              ? { data: sessions.data.map((session) => ({ id: safeText(session.id), status: safeCode(session.status) })) }
              : {}),
          },
          notifications: Array.isArray(notifications) ? notifications.map((item) => ({
            resource: safeCode(item?.resource), code: safeCode(item?.code), message: safeText(item?.message),
          })) : [],
          diagnostics: safeDiagnostics || { status: safeCode(diagnostics?.status) },
        };
        try {
          if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable');
          await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
          copyStatus.textContent = '도움정보를 복사했습니다. 자동 전송되지 않았습니다.';
        } catch {
          copyStatus.textContent = '도움정보를 복사하지 못했습니다. 브라우저의 클립보드 권한을 확인하세요.';
        }
      });
      root.append(copyButton, copyStatus);
      return root;
    },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection({ status, data, error, checkedAt } = {}) {
      const root = document.createElement('section');
      root.className = 'student-ai-connection';
      root.setAttribute('aria-label', '학생 구현: AI 연결 점검');

      const addText = (tag, text, className) => {
        const element = document.createElement(tag);
        element.textContent = text;
        if (className) element.className = className;
        root.append(element);
      };
      const safeCode = (value) => typeof value === 'string' && /^[A-Z0-9_:-]{1,80}$/.test(value)
        ? value
        : 'AI_REQUEST_UNVERIFIED';
      const safeMessage = typeof error?.message === 'string' && error.message.trim()
        ? error.message
        : '오류 내용을 확인할 수 없습니다.';

      addText('h3', 'AI 연결 점검');
      if (status === 'idle') {
        addText('p', 'AI 연결 점검 전', 'student-ai-connection-idle');
        addText('p', '다시 점검하려면 위쪽의 현재 API 연결 점검 버튼을 직접 누르세요.');
        return root;
      }
      if (status === 'loading') {
        addText('p', 'AI 연결 점검 중', 'student-ai-connection-loading');
        addText('p', '요청을 자동으로 다시 보내지 않습니다.');
        return root;
      }
      if (status === 'error') {
        const code = safeCode(error?.code);
        addText('p', `요청 실패 (${code}): ${safeMessage}`, 'student-ai-connection-error');
        addText('p', '이 상태는 접근 거부 판정이 아니라 AI 연결 점검 실패입니다.');

        const guidance = {
          ON_AI_PROVISIONING_PENDING: '담당자에게 계정 연결과 앱 권한 확인을 요청하세요.',
          WB_CLCO_AUTH_REQUIRED: '계정 연결을 다시 확인하고 담당자에게 확인을 요청하세요.',
          WB_CLCO_ACCESS_BLOCKED: '계정 연결을 다시 확인하고 담당자에게 앱 권한 확인을 요청하세요.',
          ON_AI_AUTHORIZATION_CHANGED: '계정 연결을 다시 확인하고 담당자에게 앱 권한 확인을 요청하세요.',
          WB_CLCO_COHORT_BUDGET_EXHAUSTED: '반 사용량을 담당자에게 확인하세요.',
          WB_CLCO_LIMIT_REACHED: '이용 한도를 담당자에게 확인하세요.',
          WB_CLCO_RATE_LIMITED: '요청 제한입니다. 잠시 뒤 직접 다시 점검하세요.',
          WB_CLCO_SESSION_CLOSED: '이용 시간을 확인하세요.',
          WB_CLCO_TIMEOUT: '시간 초과입니다. 잠시 뒤 직접 다시 점검하세요.',
          REQUEST_TIMEOUT: '시간 초과입니다. 잠시 뒤 직접 다시 점검하세요.',
          ENGINE_TIMEOUT: '시간 초과입니다. 잠시 뒤 직접 다시 점검하세요.',
          TIMEOUT: '시간 초과입니다. 잠시 뒤 직접 다시 점검하세요.',
          NETWORK_ERROR: '네트워크 오류입니다. 연결을 확인하고 잠시 뒤 직접 다시 점검하세요.',
          WB_CLCO_CANCELLED: '취소됨. 이전 결과는 현재 결과가 아닙니다.',
          CANCELLED: '취소됨. 이전 결과는 현재 결과가 아닙니다.',
          REQUEST_CANCELLED: '취소됨. 이전 결과는 현재 결과가 아닙니다.',
          MODEL_NOT_CONFIGURED: '담당자에게 사용할 모델 허용 설정 확인을 요청하세요.',
          ON_AI_MODEL_LIST_EMPTY: '담당자에게 모델 허용 설정 확인을 요청하세요.',
        }[code];
        if (guidance) addText('p', guidance, 'student-ai-connection-guidance');
        else addText('p', '원인을 확인할 수 없습니다. 담당자에게 확인을 요청하세요.', 'student-ai-connection-guidance');
        addText('p', '다시 점검은 사용자가 위쪽 버튼을 직접 눌러야 합니다.');
        return root;
      }
      if (status === 'ok') {
        const authorization = data?.audienceAuthorization;
        const authorizationLabel = authorization === 'test'
          ? '시험 연결 점검(test)'
          : authorization === 'verified'
            ? '앱 권한 확인 후 점검(verified)'
            : '확인 불가(unknown)';
        const modelCount = Number.isFinite(data?.modelCount) ? String(data.modelCount) : '확인 불가';
        const time = typeof checkedAt === 'string' && checkedAt ? checkedAt : '확인 불가';

        addText('p', `점검 결과: ${authorizationLabel}`, 'student-ai-connection-result');
        if (data?.transportChecked === true) addText('p', '앱 서버를 통한 연결 경로 점검 완료');
        addText('p', `사용 가능한 모델 수: ${modelCount}`);
        addText('p', `점검 시각: ${time}`);
        addText('p', '연결만 점검했으며 사건 설명은 아직 실행하지 않았습니다.');
        return root;
      }

      addText('p', 'AI 연결 점검 확인 불가', 'student-ai-connection-unknown');
      addText('p', '다시 점검하려면 위쪽의 현재 API 연결 점검 버튼을 직접 누르세요.');
      return root;
    },
    renderExplanation({ event, explanation, checkedAt } = {}) {
      const root = document.createElement('section');
      root.className = 'student-explanation';
      root.setAttribute('aria-label', '학생 구현: 사건 설명');
      const addText = (tag, text, className) => {
        const element = document.createElement(tag);
        element.textContent = text;
        if (className) element.className = className;
        root.append(element);
      };
      const safeCode = (value) => typeof value === 'string' && /^[A-Z0-9_:-]{1,80}$/.test(value)
        ? value
        : null;
      const fail = (message, code = safeCode(explanation?.error?.code)) => {
        addText('p', code ? `오류 코드: ${code}` : '오류 코드를 확인할 수 없습니다.', 'student-explanation-error-code');
        addText('p', message, 'student-explanation-error');
        addText('p', '기록은 그대로입니다. AI 설명 실패는 보안 기록이나 업무 앱 판정을 바꾸지 않습니다.');
        return root;
      };

      addText('h3', '사건 설명');
      if (!event || event.id == null) {
        addText('p', '보안 기록에서 기록을 먼저 고르세요.');
        return root;
      }
      if (explanation?.status === 'loading') {
        addText('p', 'AI 설명을 요청하는 중입니다.', 'student-explanation-loading');
        return root;
      }
      if (explanation?.status === 'error') {
        const code = safeCode(explanation.error?.code);
        const message = typeof explanation.error?.message === 'string' && explanation.error.message.trim()
          ? explanation.error.message
          : '오류 내용을 확인할 수 없습니다.';
        addText('p', code ? `AI 설명 실패 (${code}): ${message}` : `AI 설명 실패: ${message}`, 'student-explanation-error');
        addText('p', '기록은 그대로입니다. AI 설명 실패는 보안 기록이나 업무 앱 판정을 바꾸지 않습니다.');
        return root;
      }
      if (explanation?.status !== 'ok') {
        addText('p', '이 기록의 AI 설명을 아직 요청하지 않았습니다.');
        return root;
      }

      const data = explanation.data;
      if (data?.executed === true) {
        return fail('AI가 이미 실행했다고 답한 설명은 표시할 수 없습니다.');
      }
      if (data?.requiresHumanConfirmation !== true || data?.executed !== false) {
        return fail('사람 확인 및 미실행 조건을 확인할 수 없어 설명을 표시하지 않습니다.');
      }
      if (typeof data?.summary !== 'string' || !data.summary.trim()) {
        return fail('AI 설명 요약이 없어 내용을 표시할 수 없습니다.');
      }

      const evidence = Array.isArray(event.evidence) ? event.evidence : [];
      const rules = Array.isArray(event.rules) ? event.rules : [];
      const evidenceById = new Map(evidence.filter((row) => row && row.id != null).map((row) => [String(row.id), row]));
      if (!evidence.length) {
        return fail('이 기록에는 인용할 근거가 없어 AI 설명을 표시할 수 없습니다.');
      }
      if (!rules.length) {
        return fail('이 기록에는 확인할 규칙이 없어 AI 설명을 표시할 수 없습니다.');
      }
      if (evidenceById.size !== evidence.length || evidence.some((row) => typeof row.text !== 'string')) {
        return fail('기록의 근거 자료가 완전하지 않아 AI 설명을 표시할 수 없습니다.');
      }
      if (rules.some((rule) => !rule || rule.id == null || typeof rule.text !== 'string')) {
        return fail('기록의 규칙 자료가 완전하지 않아 AI 설명을 표시할 수 없습니다.');
      }
      if (!event.state || ['access', 'session', 'device'].some((key) => typeof event.state[key] !== 'string')) {
        return fail('기록의 현재 상태 자료를 확인할 수 없어 AI 설명을 표시할 수 없습니다.');
      }
      const evidenceIds = data.evidenceIds;
      const uniqueEvidenceIds = Array.isArray(evidenceIds) && new Set(evidenceIds.map(String)).size === evidenceIds.length;
      if (!uniqueEvidenceIds || evidenceIds.length !== evidenceById.size || evidenceIds.some((id) => !evidenceById.has(String(id)))) {
        return fail('근거 ID가 이 기록과 맞지 않아 AI 설명을 표시할 수 없습니다. 내용을 지어내지 않았습니다.');
      }

      if (!Array.isArray(event.supportedActions)) {
        return fail('연동 시스템의 지원 조치 목록을 확인할 수 없어 제안을 표시하지 않습니다.');
      }
      const supportedActions = event.supportedActions;
      const proposals = data.proposals;
      if (!Array.isArray(proposals) || proposals.length > 3) {
        return fail('조치 제안 자료를 확인할 수 없어 설명을 표시하지 않습니다.');
      }
      for (const proposal of proposals) {
        const refs = proposal?.evidenceIds;
        if (!proposal || typeof proposal.action !== 'string' || !supportedActions.includes(proposal.action)) {
          return fail('연동 시스템이 지원하지 않는 조치가 포함되어 설명을 표시할 수 없습니다.');
        }
        if (typeof proposal.reason !== 'string' || !proposal.reason.trim() || !Array.isArray(refs) || refs.length === 0
          || new Set(refs.map(String)).size !== refs.length || refs.some((id) => !evidenceById.has(String(id)))) {
          return fail('조치 제안의 근거가 이 기록과 맞지 않아 설명을 표시할 수 없습니다.');
        }
      }

      root.setAttribute('data-student-explanation-event', String(event.id));
      addText('p', `사건 ID: ${String(event.id)}`);
      addText('h4', 'AI 설명(참고용)');
      addText('p', data.summary, 'student-explanation-summary');
      if (typeof checkedAt === 'string' && checkedAt) addText('p', `설명 확인 시각: ${checkedAt}`);

      addText('h4', '인용 근거');
      for (const id of evidenceIds) {
        const row = evidenceById.get(String(id));
        addText('p', `근거 ${String(id)} — ${typeof row.text === 'string' ? row.text : '근거 글을 확인할 수 없습니다.'}`);
      }
      addText('h4', '규칙');
      for (const rule of rules) {
        addText('p', `${String(rule.id ?? 'ID 확인 불가')} — ${typeof rule.text === 'string' ? rule.text : '규칙 글을 확인할 수 없습니다.'}`);
      }

      addText('h4', '확인 불가 상태');
      const stateLabels = [
        ['access', '접속', ['allowed', 'denied', 'unknown']],
        ['session', '세션', ['active', 'expired', 'revoked', 'unknown']],
        ['device', '기기', ['compliant', 'noncompliant', 'unknown']],
      ];
      const unknownStates = stateLabels.filter(([key, , knownValues]) => event.state[key] === 'unknown' || !knownValues.includes(event.state[key]));
      if (unknownStates.length) {
        for (const [key, label] of unknownStates) addText('p', `${label}: 확인 불가(${String(event.state[key])})`);
      } else {
        addText('p', '없음');
      }

      addText('h4', '조치 제안');
      if (proposals.length === 0) {
        addText('p', supportedActions.length === 0
          ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상)'
          : 'AI가 제안한 조치가 없습니다.');
      } else {
        for (const proposal of proposals) {
          addText('p', `조치: ${proposal.action}`);
          addText('p', `이유: ${proposal.reason}`);
          addText('p', `근거 ID: ${proposal.evidenceIds.map(String).join(', ')}`);
          for (const id of proposal.evidenceIds) {
            const row = evidenceById.get(String(id));
            addText('p', `근거 ${String(id)} — ${typeof row.text === 'string' ? row.text : '근거 글을 확인할 수 없습니다.'}`);
          }
          addText('p', '사람 확인이 필요하며 실행되지 않았습니다.');
        }
      }
      return root;
    },
    renderAction({ status = 'idle', event = null, actionId = null, target = null, receipt = null, observation = null, message = '', confirmationExpiresAt = null, error = null } = {}) {
      const root = document.createElement('section');
      root.className = 'student-action';
      root.setAttribute('aria-label', '학생 구현: 조치 상태');
      const addText = (tag, text, className) => {
        const element = document.createElement(tag);
        element.textContent = text;
        if (className) element.className = className;
        root.append(element);
        return element;
      };
      const hasValue = (value) => value !== null && value !== undefined && value !== '';
      const rawStatus = typeof status === 'string' ? status : 'unknown';
      const labels = {
        idle: '아직 미실행(idle)',
        loading: '조치 상태 확인 중(loading) · 결과 미확인',
        prepared: '준비됨·미실행(prepared)',
        executing: '서버에 전달 중(executing) · 결과가 아직 확인되지 않았습니다',
        pending: '서버 접수·처리 중(pending) · 접수(ACK)는 효과 확인이 아닙니다',
        denied: '연동 시스템 거절(denied)',
        failed: '연동 시스템 실패(failed)',
        unknown: '결과 불명(unknown) · 효과 없음으로 판단할 수 없습니다',
        expired: '확인 기한 지남(expired) · 다시 준비해야 합니다',
        error: '요청이 처리되지 않았습니다(error)',
      };
      const effectConfirmed = rawStatus === 'succeeded' && observation?.effectApplied === true;
      if (effectConfirmed) {
        addText('p', '효과 확인(succeeded)', 'student-action-observed');
        if (hasValue(observation.observedAt)) addText('p', `관측 시각: ${String(observation.observedAt)}`);
        addText('p', 'effectApplied: true');
      } else if (rawStatus === 'succeeded') {
        addText('p', '결과 불명(unknown) · effectApplied: true가 확인되지 않아 효과를 판단할 수 없습니다', 'student-action-unknown');
        addText('p', '전달된 상태 코드: succeeded');
      } else {
        addText('p', labels[rawStatus] || `결과 불명(unknown) · 원래 상태 코드: ${rawStatus}`, rawStatus === 'denied' || rawStatus === 'failed' || rawStatus === 'error' ? 'student-action-error' : 'student-action-state');
      }

      if (rawStatus === 'idle') addText('p', '조치가 아직 실행되지 않았습니다. 제공 화면의 조치 준비와 사람 확인 절차를 이용하세요.');
      if (rawStatus === 'loading' || rawStatus === 'executing' || rawStatus === 'pending') {
        addText('p', '현재 전달 또는 조회 상태만 표시하며, 연동 시스템의 효과 결과는 아직 확인되지 않았습니다.');
      }
      if (rawStatus === 'unknown') addText('p', '효과 없음으로 간주하지 마세요. 제공 화면에서 연동 시스템 결과만 다시 조회하세요.');
      if (rawStatus === 'expired') addText('p', '이번 확인 기한은 지났습니다. 제공 화면에서 대상을 다시 확인하고 조치를 준비하세요.');
      if (rawStatus === 'error') {
        if (hasValue(error?.code)) addText('p', `오류 코드: ${String(error.code)}`);
        if (hasValue(error?.message)) addText('p', `요청 오류: ${String(error.message)}`);
        else if (hasValue(message)) addText('p', `요청 오류: ${String(message)}`);
      }
      if (rawStatus === 'denied' || rawStatus === 'failed') {
        if (hasValue(message)) addText('p', `서버 메시지: ${String(message)}`);
        else addText('p', '연동 시스템이 별도 메시지를 전달하지 않았습니다.');
      }
      if (rawStatus === 'loading' && hasValue(message)) addText('p', String(message));

      if (event && hasValue(event.id)) {
        root.setAttribute('data-student-action-event', String(event.id));
        addText('p', `사건 ID: ${String(event.id)}`);
        const evidenceIds = Array.isArray(event.evidence) ? event.evidence.map((item) => item?.id).filter(hasValue) : [];
        addText('p', `근거 ID: ${evidenceIds.length ? evidenceIds.map(String).join(', ') : '없음'}`);
      }
      if (hasValue(actionId)) addText('p', `조치 ID: ${String(actionId)}`);
      if (target && (hasValue(target.id) || hasValue(target.generation))) {
        addText('p', `실제 대상 ID: ${hasValue(target.id) ? String(target.id) : '확인 불가'}`);
        addText('p', `대상 세대: ${hasValue(target.generation) ? String(target.generation) : '확인 불가'}`);
      }
      if (receipt) {
        if (hasValue(receipt.requestId)) {
          root.setAttribute('data-student-action-request', String(receipt.requestId));
          addText('p', `요청 ID: ${String(receipt.requestId)}`);
        }
        if (hasValue(receipt.receiptId)) addText('p', `접수 ID: ${String(receipt.receiptId)}`);
        if (hasValue(receipt.version)) addText('p', `영수증 버전: ${String(receipt.version)}`);
      }
      if (rawStatus === 'prepared' && hasValue(confirmationExpiresAt)) {
        addText('p', `사람 확인 기한: ${String(confirmationExpiresAt)}`);
        addText('p', '준비만 된 상태이며 아직 실행되지 않았습니다. 제공 화면에서 실제 대상과 조치를 확인하세요.');
      }
      if (effectConfirmed && hasValue(receipt?.receiptId)) addText('p', `영수증 ID: ${String(receipt.receiptId)}`);
      if (observation && rawStatus !== 'succeeded' && hasValue(observation.observedAt)) {
        addText('p', `관측 시각: ${String(observation.observedAt)}`);
        addText('p', `effectApplied: ${String(observation.effectApplied)}`);
      }
      if (rawStatus === 'expired' && hasValue(error?.message)) addText('p', `안내: ${String(error.message)}`);
      return root;
    },
  };
}
