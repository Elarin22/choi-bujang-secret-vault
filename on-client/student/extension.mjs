// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView({ api, onChange } = {}) {
  let eventFilters = { kind: 'all', appId: 'all', access: 'all', expandedId: null };
  let eventDataSignature = null;
  let localPcStatus = { status: 'idle' };
  let localPcRequestGeneration = 0;
  const notifyStudentChange = () => {
    try { onChange?.(); } catch { /* 화면 갱신 콜백 실패는 제공 화면으로 전파하지 않습니다. */ }
  };
  const localReasonText = (code) => ({
    NETWORK_READ_DENIED: '현재 사용자 권한으로 네트워크 구성을 읽을 수 없습니다.',
    NETWORK_CIM_UNAVAILABLE: 'Windows CIM에서 네트워크 구성을 확인할 수 없습니다.',
    NETWORK_QUERY_FAILED: '네트워크 구성을 읽지 못했습니다.',
    FIREWALL_READ_DENIED: '현재 사용자 권한으로 방화벽 프로필을 읽을 수 없습니다.',
    FIREWALL_CIM_UNAVAILABLE: 'Windows CIM에서 방화벽 프로필을 확인할 수 없습니다.',
    FIREWALL_QUERY_FAILED: '방화벽 프로필을 읽지 못했습니다.',
    EVENT_LOG_READ_DENIED: '현재 사용자에게 이 Windows 로그의 읽기 권한이 없습니다.',
    EVENT_LOG_CIM_UNAVAILABLE: 'Windows 이벤트 로그 조회 기능을 사용할 수 없습니다.',
    EVENT_LOG_QUERY_FAILED: 'Windows 이벤트 로그 건수를 읽지 못했습니다.',
    WINDOWS_ONLY: 'Windows 환경에서만 조회할 수 있습니다.',
    POWERSHELL_UNAVAILABLE: 'PowerShell을 찾을 수 없습니다.',
    WINDOWS_STATUS_TIMEOUT: 'Windows 상태 조회 시간이 초과됐습니다.',
    WINDOWS_STATUS_INVALID: 'Windows 상태 응답 형식을 확인할 수 없습니다.',
    WINDOWS_STATUS_QUERY_FAILED: 'Windows 상태 조회를 완료하지 못했습니다.',
  }[code] || '읽기 권한 또는 Windows 조회 상태를 확인할 수 없습니다.');
  const validTime = (value) => typeof value === 'string' && Number.isFinite(Date.parse(value));
  const validWindowsSection = (value) => value && typeof value === 'object'
    && ['ok', 'unknown'].includes(value.status) && validTime(value.checkedAt)
    && (value.status === 'unknown' ? typeof value.reasonCode === 'string' : true);
  const validLocalPcStatus = (data) => {
    if (!data || typeof data !== 'object') return false;
    const network = data.network;
    if (!validWindowsSection(network)) return false;
    if (network.status === 'ok' && (!Array.isArray(network.interfaces) || network.interfaces.length > 64 || network.interfaces.some((row) =>
      !row || typeof row !== 'object' || typeof row.name !== 'string' || typeof row.type !== 'string'
      || !['ipv4', 'ipv6', 'gateways', 'dnsServers'].every((key) => Array.isArray(row[key]) && row[key].length <= 128 && row[key].every((entry) => typeof entry === 'string' && entry.length <= 128))))) return false;
    const firewall = data.firewall;
    if (!validWindowsSection(firewall)) return false;
    if (firewall.status === 'ok' && (!Array.isArray(firewall.profiles) || firewall.profiles.length !== 3
      || firewall.profiles.some((row) => !row || !['Domain', 'Private', 'Public'].includes(row.name) || typeof row.enabled !== 'boolean')
      || new Set(firewall.profiles.map((row) => row.name)).size !== 3)) return false;
    const events = data.events;
    if (!events || typeof events !== 'object' || events.windowHours !== 24 || !validTime(events.windowStart) || !validTime(events.windowEnd)) return false;
    return ['system', 'application'].every((name) => {
      const row = events[name];
      return validWindowsSection(row) && (row.status === 'unknown' || [row.errors, row.warnings].every((count) => Number.isSafeInteger(count) && count >= 0));
    });
  };
  const refreshLocalPcStatus = async () => {
    const requestGeneration = ++localPcRequestGeneration;
    localPcStatus = { status: 'loading' };
    notifyStudentChange();
    try {
      const result = await api?.get?.('/api/local-system-metrics');
      if (requestGeneration !== localPcRequestGeneration) return;
      if (result?.ok !== true) {
        localPcStatus = { status: 'error', error: result?.error || { message: '로컬 PC 상태를 조회하지 못했습니다.' } };
      } else if (!validLocalPcStatus(result.data)) {
        localPcStatus = { status: 'error', error: { message: '서버가 반환한 PC 상태 형식을 확인할 수 없습니다.' } };
      } else {
        localPcStatus = { status: 'ok', data: result.data };
      }
    } catch {
      if (requestGeneration !== localPcRequestGeneration) return;
      localPcStatus = { status: 'error', error: { message: '로컬 PC 상태 조회 중 오류가 발생했습니다.' } };
    }
    if (requestGeneration === localPcRequestGeneration) notifyStudentChange();
  };
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
    renderStatus({ me, access, events, devices, sessions, notifications, diagnostics, mode } = {}) {
      const startInitialLocalQuery = localPcStatus.status === 'idle';
      if (startInitialLocalQuery) localPcStatus = { status: 'loading' };
      const root = document.createElement('section');
      root.className = 'student-status';
      root.setAttribute('aria-label', '학생 구현: 핵심 기능·내 PC 상태·알림·도움정보');
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
      root.append(make('p', `업무 자료 모드: ${modeLabels[safeMode]}`));
      const coreSection = section('핵심 기능 3가지');
      const coreGrid = make('div', undefined, 'student-core-grid');
      const coreCard = (title, state, value, detail) => {
        const card = make('article', undefined, 'student-core-card');
        card.dataset.state = state;
        card.append(make('h5', title), make('p', value, 'student-core-value'), make('p', detail, 'student-core-detail'));
        coreGrid.append(card);
      };
      const user = me?.data?.user;
      const currentDevice = me?.data?.device;
      const currentSession = me?.data?.session;
      if (me?.status === 'loading') coreCard('계정·기기·세션', 'loading', '불러오는 중', '현재 로그인 자료를 확인하고 있습니다.');
      else if (me?.status === 'error') coreCard('계정·기기·세션', 'error', '확인 불가', safeText(me.error?.message, '로그인 자료를 불러오지 못했습니다.'));
      else if (me?.status === 'ok' && user) coreCard('계정·기기·세션', currentDevice?.status === 'noncompliant' || ['expired', 'revoked'].includes(currentSession?.status) ? 'attention' : 'ok',
        safeText(user.label, '사용자 이름 확인 불가'), `기기 ${safeText(currentDevice?.label)} · ${stateText(deviceLabels, currentDevice?.status)} · 세션 ${stateText(sessionLabels, currentSession?.status)}`);
      else coreCard('계정·기기·세션', 'unknown', '확인 불가', '현재 로그인 자료를 확인할 수 없습니다.');

      const decisionLabels = { allow: '접근 허용', deny: '접근 거부', challenge: '추가 인증 또는 확인 필요', unknown: '확인 불가' };
      const decisionValue = access?.data?.decision;
      if (access?.status === 'loading') coreCard('업무 앱 접근 판정', 'loading', '판정 확인 중', safeText(access.appName || access.appId, '선택 앱'));
      else if (access?.status === 'error') coreCard('업무 앱 접근 판정', 'error', '요청 실패', safeText(access.error?.message, '판정을 확인할 수 없습니다.'));
      else if (access?.status === 'ok') coreCard('업무 앱 접근 판정', decisionValue === 'deny' ? 'error' : decisionValue === 'challenge' ? 'attention' : decisionValue === 'allow' ? 'ok' : 'unknown',
        `${decisionLabels[decisionValue] || '확인 불가'} (${decisionLabels[decisionValue] ? decisionValue : 'unknown'})`, `${safeText(access.appName || access.appId, '앱 정보 확인 불가')} · ${safeText(access.data?.reason, '판정 이유 확인 불가')}`);
      else coreCard('업무 앱 접근 판정', 'idle', '요청 전', '업무 앱에서 앱을 선택해 접속을 요청하세요.');

      if (events?.status === 'loading') coreCard('접속 기록·XDR 경보', 'loading', '불러오는 중', '전달된 본인 기록을 확인하고 있습니다.');
      else if (events?.status === 'error') coreCard('접속 기록·XDR 경보', 'error', '확인 불가', safeText(events.error?.message, '보안 기록을 불러오지 못했습니다.'));
      else if (events?.status === 'ok' && Array.isArray(events.data)) {
        const accessCount = events.data.filter((event) => event.kind === 'access').length;
        const xdrCount = events.data.filter((event) => event.kind === 'xdr').length;
        coreCard('접속 기록·XDR 경보', 'ok', `전달받은 기록 ${events.data.length}건`, `접속 ${accessCount}건 · XDR 경보 ${xdrCount}건 · 전체 로그 아님`);
      } else coreCard('접속 기록·XDR 경보', 'unknown', '확인 불가', '서버가 전달한 기록 상태를 확인할 수 없습니다.');
      coreSection.append(coreGrid, make('p', '세 기능은 각 메뉴의 상세 화면에서 확인할 수 있습니다.', 'student-status-note'));

      const localSection = section('내 PC 상태: 네트워크·방화벽·Windows 로그');
      localSection.append(make('p', '현재 PC에서 직접 조회한 값입니다. SDP 서버 연결과 별개입니다. Windows 경고·오류 건수는 침해나 공격 탐지 결과가 아니며 이벤트 내용을 수집하지 않습니다.', 'student-status-note'));
      const localLive = make('p', '', 'student-local-live');
      localLive.setAttribute('role', 'status');
      localLive.setAttribute('aria-live', 'polite');
      localLive.setAttribute('aria-atomic', 'true');
      const localDetail = make('div', undefined, 'student-local-results');
      if (localPcStatus.status === 'loading') {
        localLive.textContent = '이 PC 상태를 조회하는 중입니다.';
        localLive.dataset.state = 'loading';
      } else if (localPcStatus.status === 'error') {
        localLive.textContent = `이 PC 상태를 조회하지 못했습니다: ${safeText(localPcStatus.error?.message, '오류 내용을 확인할 수 없습니다.')}`;
        localLive.dataset.state = 'error';
        localDetail.append(make('p', '확인 불가: 조회에 실패한 항목의 값은 표시하지 않았습니다. 다시 조회를 누르세요.', 'student-status-error'));
      } else if (localPcStatus.status === 'ok') {
        localLive.textContent = '이 PC 상태 조회 완료';
        localLive.dataset.state = 'ok';
        const data = localPcStatus.data;
        const timeText = (value) => validTime(value) ? new Date(value).toLocaleString('ko-KR') : '시각 확인 불가';
        const row = (title, text, time, state = 'ok') => {
          const item = make('article', undefined, 'student-local-card');
          item.dataset.state = state;
          item.append(make('h5', title), make('p', text, 'student-local-value'), make('p', `조회 시각: ${timeText(time)}`, 'student-local-time'));
          localDetail.append(item);
        };
        const network = data.network;
        if (network.status === 'unknown') row('네트워크 구성', `확인 불가: ${localReasonText(network.reasonCode)} (${safeText(network.reasonCode, 'UNKNOWN')})`, network.checkedAt, 'error');
        else {
          const interfaces = network.interfaces;
          row('네트워크 구성', `활성 인터페이스 ${interfaces.length}개`, network.checkedAt);
          for (const adapter of interfaces) {
            localDetail.append(make('p', `${adapter.name} (${adapter.type}) · IPv4 ${adapter.ipv4.length ? adapter.ipv4.join(', ') : '없음'} · IPv6 ${adapter.ipv6.length ? adapter.ipv6.join(', ') : '없음'} · 게이트웨이 ${adapter.gateways.length ? adapter.gateways.join(', ') : '없음'} · DNS ${adapter.dnsServers.length ? adapter.dnsServers.join(', ') : '없음'}`, 'student-local-description'));
          }
          if (interfaces.length === 0) localDetail.append(make('p', '활성 네트워크 인터페이스가 없습니다.', 'student-local-description'));
        }
        const firewall = data.firewall;
        if (firewall.status === 'unknown') row('방화벽 프로필 (읽기 전용)', `확인 불가: ${localReasonText(firewall.reasonCode)} (${safeText(firewall.reasonCode, 'UNKNOWN')})`, firewall.checkedAt, 'error');
        else {
          const profiles = firewall.profiles.map((profile) => `${profile.name}: ${profile.enabled ? '사용(Enabled: true)' : '사용 안 함(Enabled: false)'}`).join(' · ');
          row('방화벽 프로필 (읽기 전용)', profiles, firewall.checkedAt);
        }
        localDetail.append(make('p', `Windows 이벤트 집계 범위: 최근 ${data.events.windowHours}시간 · ${timeText(data.events.windowStart)} ~ ${timeText(data.events.windowEnd)}`, 'student-local-description'));
        const eventRow = (title, item) => {
          if (item.status === 'unknown') row(title, `확인 불가: ${localReasonText(item.reasonCode)} (${safeText(item.reasonCode, 'UNKNOWN')})`, item.checkedAt, 'error');
          else row(title, `경고 ${item.warnings}건 · 오류 ${item.errors}건`, item.checkedAt);
        };
        eventRow('System 로그', data.events.system);
        eventRow('Application 로그', data.events.application);
      } else {
        localLive.textContent = '아직 이 PC 상태를 조회하지 않았습니다.';
        localLive.dataset.state = 'idle';
      }
      const localRefresh = make('button', '다시 조회', 'student-local-refresh btn');
      localRefresh.type = 'button';
      localRefresh.disabled = localPcStatus.status === 'loading';
      localRefresh.setAttribute('aria-label', '내 PC 상태 다시 조회');
      localRefresh.addEventListener('click', () => { void refreshLocalPcStatus(); });
      localSection.append(localLive, localDetail, localRefresh);
      if (startInitialLocalQuery) queueMicrotask(() => { void refreshLocalPcStatus(); });

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
    renderVulnerabilities({ status = 'idle', mode = null, data = null, error = null } = {}) {
      const root = document.createElement('section');
      root.className = 'student-vulnerabilities';
      root.setAttribute('aria-label', '학생 구현: 설치 패키지 취약점 조회');
      const addText = (parent, tag, text, className) => {
        const element = document.createElement(tag);
        element.textContent = text;
        if (className) element.className = className;
        parent.append(element);
        return element;
      };
      const hasValue = (value) => value !== null && value !== undefined && value !== '';
      const rawStatus = typeof status === 'string' ? status : 'unknown';
      const stateLabels = {
        complete: '모두 조회(complete)',
        partial: '일부 조회 실패(partial)',
        not_checked: '아직 조회 안 함(not_checked)',
        not_configured: '조회 준비 미완료(not_configured)',
        unverifiable: 'lock 파일 확인 불가(unverifiable)',
      };

      if (rawStatus === 'idle') {
        addText(root, 'p', '조회 전(idle)');
        return root;
      }
      if (rawStatus === 'loading') {
        addText(root, 'p', '조회 중(loading)');
        return root;
      }
      if (rawStatus === 'error') {
        addText(root, 'p', `조회 실패(error): ${hasValue(error?.message) ? String(error.message) : '오류 메시지를 확인할 수 없습니다.'}`, 'student-vulnerabilities-error');
        return root;
      }
      if (rawStatus !== 'ok' || !data || typeof data !== 'object') {
        addText(root, 'p', `조회 결과 확인 불가(${rawStatus})`, 'student-vulnerabilities-unknown');
        return root;
      }

      const scanStatus = typeof data.status === 'string' ? data.status : 'unknown';
      addText(root, 'h3', stateLabels[scanStatus] || `조회 상태 확인 불가(${scanStatus})`);
      addText(root, 'p', `package-lock.json 버전: ${hasValue(data.lockfileVersion) ? String(data.lockfileVersion) : '확인 불가'}`);
      addText(root, 'p', `잠금 파일 해시: ${hasValue(data.lockfileHash) ? String(data.lockfileHash) : '확인 불가'}`);
      addText(root, 'p', `전체 조회 시각: ${hasValue(data.checkedAt) ? String(data.checkedAt) : '확인 불가'}`);

      const packages = Array.isArray(data.packages) ? data.packages : [];
      if (packages.length === 0) {
        const emptyText = scanStatus === 'not_configured'
          ? '프로젝트 조회 설정이 없어 조회된 패키지가 없습니다.'
          : scanStatus === 'not_checked'
            ? '조회가 수행되지 않아 취약점 유무를 확인하지 않았습니다.'
            : scanStatus === 'unverifiable'
              ? '설치 목록을 확인할 수 없어 패키지 취약점을 판단하지 않았습니다.'
              : '표시할 패키지 결과가 없습니다.';
        addText(root, 'p', emptyText);
        return root;
      }

      const packageLabels = {
        known_vulnerabilities: '알려진 항목 있음(known_vulnerabilities)',
        none_found: '알려진 항목 없음(none_found)',
        unverifiable: '조회 확인 불가(unverifiable)',
      };
      addText(root, 'h4', '패키지별 조회 결과');
      for (const pkg of packages) {
        const row = document.createElement('div');
        row.className = 'student-package-result';
        if (hasValue(pkg?.name)) row.setAttribute('data-student-package-name', String(pkg.name));
        if (hasValue(pkg?.version)) row.setAttribute('data-student-package-version', String(pkg.version));
        addText(row, 'h5', `${hasValue(pkg?.name) ? String(pkg.name) : '패키지 이름 확인 불가'} @ ${hasValue(pkg?.version) ? String(pkg.version) : '설치 버전 확인 불가'}`);
        const packageStatus = typeof pkg?.status === 'string' ? pkg.status : 'unknown';
        const vulnerabilities = Array.isArray(pkg?.vulnerabilities) ? pkg.vulnerabilities : [];
        if (packageStatus === 'unverifiable' && vulnerabilities.length > 0) {
          addText(row, 'p', '일부 확인·전체 조회 확인 불가(unverifiable)');
        } else {
          addText(row, 'p', packageLabels[packageStatus] || `조회 확인 불가(${packageStatus})`);
        }
        addText(row, 'p', `출처: ${hasValue(pkg?.source) ? String(pkg.source) : '확인 불가'}`);
        addText(row, 'p', `패키지 조회 시각: ${hasValue(pkg?.checkedAt) ? String(pkg.checkedAt) : '확인 불가'}`);
        if (vulnerabilities.length > 0) {
          addText(row, 'h6', '취약점 항목');
          for (const finding of vulnerabilities) {
            addText(row, 'p', `ID: ${hasValue(finding?.id) ? String(finding.id) : '확인 불가'} · 수정 시각: ${hasValue(finding?.modified) ? String(finding.modified) : '확인 불가'}`);
          }
        } else if (packageStatus === 'unverifiable') {
          addText(row, 'p', '조회가 완료되지 않아 취약점 유무를 확인할 수 없습니다.');
        }
        root.append(row);
      }
      return root;
    },
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
