# BYTE BACK 자료실 · 12단계 저장점

## 보너스 xdr-03 저장점 · 2026-10-13

「알려진 취약점」모듈을 xdr/known-cve에 추가했습니다. 공식 가상 경보 원본 24건은 그대로 보관하며 요청 머리글·주소·인자의 완전한 원격 JNDI 조회 구조만 block합니다. 취약점 이름·불완전한 흔적은 alert, 정상 이벤트는 record입니다. 단독 decide.mjs는 import·파일·네트워크 없이 계산합니다. 패턴 근거는 Apache CVE-2021-44228·MITRE T1190과 공식 가상 경보입니다.

재현: npm run xdr:run -- known-cve → block 8, alert 8, record 8. npm test → 기존 44개와 새 6개, 합계 50개 통과. 정상 차단 0, 읽기 24줄, 모의 overlay에서 공격 8건 거부·애매한/정상 거부 0. respond.mjs는 근거 경보 번호·15분 만료가 있는 block 후보만 기존 overlay에 넣고 패턴 이름만 로그에 남깁니다. 미확인 IP·만료·기존 정책 보존을 시험했습니다. 운영 릴레이 IP 계약은 여전히 미제공이며 실제 연결은 미검증입니다. 실제 심판 결과는 별도로 확인합니다.

## 최신 상태 · 2026-10-13

1~11단계는 실제 심판에서 각각 100점을 확인했습니다. 12단계는 코드 커밋 `6d83f22d5a508d94e1eb5f7bb4035e2fdfb42847`까지 총 여섯 접수 모두 `UNV_RUN_ENVIRONMENT`로 확인 불가·표시 0/100점입니다. 심판의 실행 명령과 첫 오류 로그는 아직 받지 못했습니다. 아래 이전 검토 이력의 재판정 대기는 이 결과로 갱신합니다.

위 코드에서 `npm test` 44개, `npm run check` 자기점검 20건, URL 입력 방식의 실측 20건·미실행 0, 실제 배포 커밋 일치를 확인했습니다. 자기점검은 심판 통과가 아닙니다. 운영 엔진 승인·회수 연결과 공식 41종 운영 재현은 별도 미검증입니다.

학원 PC에서는 이 저장소를 `git pull --ff-only`로 갱신하고 `npm ci` → `npm test`를 실행합니다. 기존 Vercel·Supabase 프로젝트와 서버 환경변수는 그대로 사용하며 SQL을 다시 초기화하지 않습니다. 작업 기록 저장소도 별도로 갱신한 뒤 [학원 재개 안내](https://github.com/myeongjundev/skt-aleph-defense-lab/blob/main/docs/HANDOFF-2026-10-13-BYTE-BACK.md)를 먼저 읽습니다. 해당 기록 저장소는 본인 GitHub 로그인으로 접근합니다.

## 단계별 구현 이력

1~5단계 운영 심판 각 100/100점, 총 500/500점을 확인했습니다. 5단계는 메모 요청을 기존 서버 함수로만 처리하며 원본 Data API 직접 권한을 닫습니다.

6단계 기기 등록 판정 규칙을 구현했습니다. 로컬 판정기 연습 2건, 기존 자료실·XDR 포함 시험 17개 및 빌드는 통과했습니다. 2026-10-13 운영 심판에서 커밋 21ec6b2ffe30798295d124aa739059d2f6333cb7의 6단계 100/100점, 조건 4개와 완결성 가점 3개 통과를 확인했습니다. 반별 엔진 안내 미제공으로 실제 mTLS 연결은 별도 미검증입니다.

배포: https://choi-bujang-secret-vault-sigma.vercel.app
저장소: https://github.com/myeongjundev/choi-bujang-secret-vault

7단계는 출처가 명확한 가상 복합 이상 신호에 step_up을 반환합니다. 지역 하나만으로 영구 차단하지 않습니다. 엔진 계약의 verified 재인증이 신선하면 요청을 다시 허용합니다. 클라이언트 출처·누락·중첩 추가 필드는 거부하고 none 신호에는 위치를 채우지 않습니다. 로컬 판정 연습 4건, fixture:7, 기존 기능 포함 시험 20개와 빌드가 통과했습니다. 운영 재로그인·자료 차단 연결은 반별 엔진 미제공으로 미검증입니다. 2026-10-13 실제 7단계 심판은 45c7c4da1ccb 커밋의 100/100점·조건 7개·가점 3개 통과를 확인했습니다.

Supabase Auth 공식 SDK의 signInWithPassword/signOut을 사용합니다. 비밀번호·토큰은 출력하거나 Git에 저장하지 않습니다. 브라우저 세션은 메모리에만 보관하며 새로고침하면 다시 로그인합니다. 서버는 원본 src/verify-login.mjs로 신원·서명·만료·발급자·대상을 검사합니다. judgeIssuer는 시작 틀의 운영 발급자를 보존했습니다.

## 설정과 실행

Vercel Production 서버 환경변수: SUPABASE_URL, SUPABASE_SECRET_KEY, SUPABASE_PUBLISHABLE_KEY. 사용자가 공식 UI에 직접 입력합니다. /api/auth-config는 공개 프로젝트 URL과 publishable key만 반환하며 서버 키는 반환하지 않습니다.
Supabase SQL Editor에서 sql/stage3.sql을 실행합니다. UUID user_notes 테이블에 RLS를 켜고 anon/authenticated 직접 접근을 회수합니다. 기존 notes의 가상 메모 네 건은 변경하거나 삭제하지 않습니다.
시험 계정은 Supabase Authentication → Users → Add user에서 사용자가 준비합니다. 비밀번호는 채팅에 보내지 않습니다.
npm ci; npm run build -- --local; node --test test/*.test.mjs
Vercel main push 후 자동 배포합니다. 공개 키를 추가한 뒤에는 Redeploy가 필요합니다.

## API 계약과 남은 약점

GET /api/notes는 로그인과 서버 기기/요청 승인이 모두 검증됐을 때 해당 사용자의 메모 배열을 반환합니다. 승인 어댑터 미연결은503입니다. POST는 {id?,title,body}, id는 UUID이며 생략 시 서버가 생성합니다. 생성 응답은 id를 포함합니다.
GET/PUT/DELETE /api/notes/:id, 단일 GET은 {id,title,body}, 삭제 후 GET은 404입니다. owner_id는 토큰을 검증해 얻은 ID만 저장하며 요청의 userId·role·owner_id는 신뢰하지 않습니다.
무토큰·위조·만료·다른 서비스 토큰은 자료 없이 401입니다. 목록과 단일 GET/PUT/DELETE 모두 검증한 userId와 owner_id를 SQL 조건으로 비교합니다. 다른 소유자 또는 없는 메모는 모두 404이며 수정·삭제로 상대 행을 바꾸지 않습니다. PUT은 title/body만 받으며 owner_id 등 추가 필드의 소유자 변경 시도는 400입니다. POST owner_id는 서버가 검증한 ID로 고정합니다. 실제 자료를 넣지 않습니다.

최신 정적 파일에는 메모 본문과 서버 키가 없습니다. 과거 공개 커밋·배포는 남아 있으므로 현재 파일 제거가 과거 노출 회수를 의미하지 않습니다. 캐시 방지·nosniff·CSP를 유지합니다. 공개 publishable key를 이용한 익명 Data API 직접 조회는 401 거부를 확인했습니다. 실제 authenticated 역할로 직접 Data API 요청하는 시험은 미실행이며 심판 점수에서도 제외됩니다.

npm run bundle의 직접 점검은 자기 점검이며 심판 판정이 아닙니다. bundle-notes.json과 artifacts/submission.json은 커밋하지 않습니다. 이후 단계 판정기·탐지기는 운영 엔진에 연결하지 않았습니다.

## 4단계 DB 권한 검토

sql/stage4.sql은 당시 직접 로그인 접근을 위한 설계 자료이며 실행하지 않았습니다. 5단계에서는 권한 추가 방향을 중단하고 sql/stage5.sql로 user_notes의 PUBLIC/anon/authenticated 직접 권한을 모두 회수합니다. RLS와 service_role의 서버 CRUD 권한은 유지합니다. 다른 테이블과 기존 자료는 보존합니다. 적용 전후 role_table_grants 및 has_table_privilege를 비교합니다.

브라우저의 Supabase 직접 메모 호출은 없음입니다. src/browser.mjs는 로그인(Auth)만 직접 호출하고 메모는 /api/notes 및 /api/notes/:id로 요청합니다. 원본 API는 https://cenxyqdoulktaqtkskeh.supabase.co/rest/v1/user_notes 이며 쿼리 없이 originalApiUrl에 기록합니다. 5단계 공개 배포 메타데이터에는 시드 표식을 내보내지 않습니다.

전용 프로젝트에 5단계 권한 회수 SQL을 적용했습니다. PUBLIC/anon/authenticated 직접 grant 0개, anon/authenticated의 7종 권한 모두 false를 확인했습니다. RLS는 유지되며 기존 가상 메모 네 건을 보존했습니다. 실제 사용자 로그인 수동 시험은 별도로 미실행입니다. 로컬 A/B 정상 CRUD·교차 거부 시험 7개는 통과했습니다.

A/B 초기 자료 소유자 연결은 실제 계정 준비 뒤 별도로 검토할 작업입니다. 기존 notes 네 건의 소유자나 본문을 임의로 바꾸지 않았습니다. 로컬 A/B 회귀시험은 양쪽 정상 CRUD, 교차 조회·수정·삭제 거부와 상대 행 보존, 소유자 변경 거부를 확인합니다.

## XDR 보너스 학습 모듈

무차별 로그인 및 웹 주입 모듈은 xdr/README.md에 실행·패턴·만료 규칙을 기록했습니다. 2026-10-07 운영 심판에서 두 과제 모두 통과했고 보너스 합산 180/600점을 확인했습니다. 6단계는 XDR 모듈·기존 자료실 API·로그인을 보존하고 별도 src/decider.mjs만 갱신합니다. 추가 XDR deny overlay는 별도 모듈이며 확인된 릴레이 출발 주소가 있는 호스트에서만 사용할 수 있습니다.

npm run xdr:build 후 npm run xdr:run -- brute-force 및 npm run xdr:run -- web-injection 으로 result.json을 다시 생성합니다. 모호한 경보의 실제 Jev 연결 정보가 없으므로 현재는 unavailable 알림 fallback이며, Jev 응답을 받았다고 기록하지 않습니다. npm run xdr:replay는 허용하는 시험용 기본 정책을 사용한 연결 모의 시험이고 운영 접속 판정이 아닙니다.

## 6단계 기기 등록 정책과 운영 연결 범위

6단계 당시 allowedRoutes는 notes 서비스의 GET /api/notes, GET /api/notes/:id, GET /notes/:id였습니다. 8단계 이후 모호한 목록 경로를 GET /api/my/notes로 좁혔습니다. 마지막 경로는 공식 엔진 요청 연습의 경로입니다. 서비스·method·pathPattern만 담고 비밀값은 없습니다. 공개 배포 식별기의 단계 범위는 기존 제출 계약에 맞춰 1~12를 지원합니다.

src/decider.mjs는 공식 aleph.decision.v1 18필드 입력을 검사하고 deviceRegistered === true일 때만 해당 자료실 읽기를 허용합니다. 미등록·확인 불가 입력은 device_not_registered, 미허용 서비스·route/path 불일치는 route_not_allowed로 거부합니다. 8단계 이후 소유/역할 증거가 없는 쓰기는 write_not_allowed입니다. 응답은 공식 5필드이며 RULE_IDS는 device_registered, route_not_allowed, step_up_required, resource_zones, write_not_allowed입니다. 제출 파일은 외부 import 없이 독립 실행됩니다.

엔진이 로그인·기기 인증서·주체 결합을 먼저 검증한다는 계약에 의존합니다. subjectId를 Supabase 사용자 ID와 비교하거나 브라우저의 userId/role/device를 신뢰하지 않습니다. 학생 판정기는 인증서를 검증하는 엔진이나 공개 HTTP 판정 endpoint가 아닙니다.

반별 접속 도구 설치 명령·등록부·릴레이 연결 안내는 제공받지 않았습니다. 설치 명령·CA·인증서·서명 키를 만들지 않았으며, 실제 mTLS 접속·다른 사용자 토큰과 기기 조합 시험은 미실행입니다. 11단계 보완 전에는 자료실 API가 로그인·소유권만 검사했지만, 보완 후에는 별도의 서버 승인 검증까지 요구합니다. 어댑터 미연결 상태에서는 인증됐더라도 503으로 자료 반환·변경을 중단합니다. 현재 점검 결과를 실제 기기 승인·접속 회수로 보고하지 않습니다.

실행: npm run decider:test; node --test test/*.test.mjs; npm run build -- --local.
커밋 후 npm run bundle은 실제 비로그인 HTTP 점검과 구분된 local fixture 판정만 기록합니다. bundle-notes.json·artifacts/submission.json 및 비밀 설정은 커밋하지 않습니다.

## 8단계 자원 구역

메모는 notes, 공지는 vault_notices라는 다른 저장소와 /api/notices/:id 경로를 사용합니다. 메모는 SQL의 owner_id 조건으로 본인에게만 CRUD를 제공합니다. 공지 PUT은 검증된 사용자와 서버 환경변수 INSTRUCTOR_USER_IDS의 UUID 목록을 비교하며 요청 role은 무시합니다. 미설정 목록은 공지 수정을 허용하지 않습니다. src/decider.mjs는 notes의 정확한 읽기 경로만 허용하며 기능 ID와 쿼리 스위치는 거부합니다. 8단계 첫 심판 48점(S08_OTHER_ZONE_ALLOWED)의 원인인 모호한 GET /api/notes와 소유자·역할 검증이 불가능한 쓰기를 릴레이 허용표에서 제거했습니다. 본인 목록은 GET /api/my/notes로 구분하고 동일한 SQL 소유자 필터를 사용합니다. 기존 브라우저 /api/notes CRUD의 최종 API 소유자 검사는 보존합니다. 공지 역할의 운영 엔진 계약은 없어 해당 서비스의 릴레이 허용은 미구현입니다. sql/stage8.sql은 기존 데이터 보존형 신규 가상 공지 저장소입니다. 2026-10-13 본인 Supabase SQL Editor에서 실행하고 가상 공지 1건을 확인했습니다. 8단계 실제 심판은 9942798e0e10c8a2f756c583f67195ea4632265b 커밋의 100/100점·조건 5개·가점 3개를 확인했습니다. 시험 22개와 빌드 통과.

## 9단계 탐지

docs/DETECT_EVENTS.md의 제공 연습 계약만 사용합니다. 같은 가명 주체의 GET가 임의 10분 창에서 120건을 초과할 때만 burst_read 사유로 propose_revocation을 제안합니다. 정확히 120건·다른 사용자 합산·시간 밖 조회는 observe, 잘못된 묶음은 거부합니다. 토큰·메모·실명은 로그나 파일에 저장하지 않습니다. 제공 계약에 네트워크/기기 대상 필드가 없어 만들지 않았습니다. 실제 회수·경과 시간·대상 기기 결합은 운영 엔진에서 별도 검증해야 합니다. npm run detect:test와 전체 회귀를 실행하며 9단계 실제 심판은 4b68f6cc117a5c073bcc3e5eea66d2e2fac7ad3d 커밋의 100/100점·조건 4개·가점 3개를 확인했습니다.

## 10단계 한 건 복구

서비스 notes의 복구 경로는 POST /api/restore/:noteId입니다. 로그인 사용자의 UUID와 비공개 사전 사본의 owner_id를 SQL RPC vault_restore_note에서 대조하고 ID·내용 SHA-256을 검증합니다. 요청에서 백업 본문/소유자를 받지 않습니다. 새 메모는 INSERT 시 처음 사본만 보관하며 수정·삭제 때 덮어쓰지 않습니다. 백업·복구 감사 테이블은 RLS와 PUBLIC/anon/authenticated 권한 회수를 적용하고 service_role에는 읽기/제한된 복구 함수 실행만 제공합니다. 한 트랜잭션에서 대상 한 건만 복원하고 해시 재검증 후 감사 기록에 추가하며 기존 이력은 지우지 않습니다.

backups/safe-policy.json은 커밋으로 고정한 공개 가능한 경로 정책 사본입니다. src/policy-recovery.mjs는 고정 SHA-256·프로젝트·버전을 확인하고 planPolicyRestore로 notes의 전/후 차이와 확인값을 반환합니다. applyPolicyRestore는 동일 차이의 확인값이 있어야 시험 정책만 새 판 번호로 적용하고 다른 서비스·감사 이력을 보존합니다. 운영 엔진 정책 쓰기는 미연결입니다. 복구 API는 현재 notes 정책이 사전 사본과 다르면 정책 복구가 필요하다고 거부합니다.

초기화: 본인 Supabase SQL Editor에서 sql/stage10.sql. DB 시험: sql/stage10-check.sql은 새 가상 B 메모만 생성해 변조/삭제 복원과 타인 거부를 확인하고 전체 트랜잭션을 ROLLBACK합니다. 기존 DB 메모를 시험 때문에 지우지 않습니다. 복구 뒤 npm run decider:test → npm run fixture:7 → npm run detect:test → node --test test/*.test.mjs → npm run build -- --local → 커밋 후 npm run bundle 순서로 정상 읽기, 소유자 A/B, 무인증/위조 토큰, 미등록 기기, 복합 이상, 구역 밖·공지 쓰기, 탐지 경계, 복구 오류를 재검증합니다. 실제 mTLS·운영 재인증·회수 집행은 미실행입니다.

### 복구 전 사본 재읽기와 검증

10단계 첫 심판 48점(S10_BACKUP_UNVERIFIED)을 근거로 재검토했습니다. 모듈 초기화 때 읽은 캐시를 사용하지 않고 모든 복구 직전에 사전 정책 파일을 다시 읽습니다. 사본이 없거나 검증 실패면 중단하며 복구 RPC를 호출하지 않습니다. GET /api/recovery-plan은 실제 사본을 다시 읽어 고정 SHA-256·프로젝트·정책 버전 검증을 하고 복원 버전 1, notes 변경 전/후 항목, 확인값을 보여 줍니다. 검증 실패 응답은 409·backupVerified false이며 운영 정책 쓰기는 없습니다. 실행 전에 이 결과의 버전과 변경 범위를 확인한 뒤 해당 사용자 인증으로 POST /api/restore/:noteId를 호출합니다. 이후 동일 사본을 복구 API에서 다시 검증하고 사전 DB 사본의 ID·소유자·내용 해시를 확인합니다. 새 회귀 시험 포함 29개와 빌드 통과. 10단계 재제출 실제 심판은 a4950fc7f63c9cdca11e490a857b845384d69574 커밋 100/100점·조건 5개·가점 3개를 확인했습니다.

## 11단계 접속 화면

/connect.html은 내 자료실 접속 화면입니다. 서버의 /api/device-status 결과를 표시하며 서버에서 최근 승인됐다고 확인한 경우에만 열기 버튼을 활성화하는 UI 모델을 사용합니다. 실제 반별 어댑터는 미제공이라 현재 서버는 connected false·approval unavailable을 반환하고 승인 요청 POST /api/device-approval은 503입니다. UI 자체로 권한을 바꾸지 않고 임의 설치/role/approved 값·낡은 상태·오프라인 상태는 열기를 허용하지 않습니다. 기기 승인 상태의 vault.connection.v1은 학생 UI 전용 내부 형식이며 운영 엔진 요청 aleph.decision.v1에 필드를 더하지 않습니다.

설치형 웹 화면 메타데이터와 정적 UI만 저장하는 service worker를 추가했습니다. 메모/API 응답/토큰/개인키는 캐시나 브라우저 저장소에 넣지 않습니다. 오프라인에는 안내만 보여 주고 보호 요청을 중지하며 재접속 때 서버 상태를 새로 확인합니다. 실제 네이티브 접속 도구·키 보관·서명·경로/본문 서명 검증은 ALEPH SDP 엔진 제공 범위이며 운영 연결/승인된 실제 기기 요청/변조 서명 시험은 미검증입니다. 로컬 전체 시험 32개·빌드 통과, 실제 심판은 제출 후 기록합니다. 기존 로그인·메모 CRUD·소유자 검사와 XDR는 보존합니다.

### 11단계 기본 진입점과 승인 전 화면

첫 심판 40점(S11_APPROVED_SCREEN_CLOSED, S11_DATA_BEFORE_APPROVAL)을 근거로 기본 주소 /를 승인 화면으로 변경했습니다. rel=manifest 설치 메타데이터는 기본 페이지에 연결되며 승인 전에는 로그인 폼·메모 목록·편집 화면이 없습니다. 기존 자료실 HTML과 로그인/CRUD 동작은 /vault.html에 보존했습니다. 이 첫 보완은 50점으로, S11_DATA_BEFORE_APPROVAL이 남았습니다. 화면 잠금만으로 운영 mTLS 집행 완료를 뜻하지 않습니다.

### 승인 전 자료 노출 재검토

기존 /vault.html은 로그인만으로 메모를 요청할 수 있었습니다. 이제 이 화면도 서버 승인 상태를 먼저 확인하며 승인 전에는 메모 요청을 보내지 않습니다. 응답이 도착하기 전 승인이 취소되거나 로그아웃·오프라인·페이지 이동이 발생하면 내용을 표시하지 않고 목록·편집기를 비웁니다. 탭 복귀와 주기적 상태 확인도 승인 상태를 다시 검사합니다.

메모 목록·단건·쓰기, 반 공지, 복원 API는 로그인 검증 다음에 src/protected-access.mjs의 서버 전용 검증을 매 요청마다 호출합니다. 브라우저의 approved/role/deviceRegistered나 헤더·쿼리로 승인을 부여하지 않습니다. 제공 어댑터가 없으면 503(device_verification_unavailable), 승인 거부면 403이며 저장소에 접근하지 않습니다. 현재 기본 어댑터는 미연결입니다. 따라서 실제 승인 사용자의 운영 CRUD는 연결 전에는 사용할 수 없습니다. 기존 CRUD·소유권·공지 역할·복원 로직은 보존했고, 서버 승인 검증을 주입한 로컬 시험에서 정상 동작을 확인했습니다. 이 시험은 운영 기기 승인 증거가 아닙니다.

실행: node --test test/*.test.mjs (36개 통과), node scripts/build-public.mjs --local. 배포 뒤 /vault.html을 직접 열어 승인 전 자료와 로그인 폼이 없는지 확인합니다. 실제 승인 정상 요청·서명 변조 검증에는 공식 어댑터 연결이 필요합니다. 심판 재제출 결과는 별도 기록합니다.

11단계 실제 재판정: a4b7722385e4af9b6cb107e307201c61fb15f3b2에서 100/100점, 조건 6개·가점 3개. 이 판정과 운영 어댑터 미연결 상태는 별도로 기록합니다.

## 12단계 탈환 작전실

/operations.html에서 GET /api/operations-status의 새 관측 결과를 읽습니다. 7건의 제한된 실제 HTTP 점검(공개 화면200, 무인증 메모/본인목록/공지쓰기/복원401, 정적자료404, 사본 검증200)과 4건의 판정/탐지 가상 시험을 구분합니다. 각 실행에는 기대 결과·실제 응답·관측자가 생성한 요청 ID·확인 시각이 있습니다. 배포 커밋은 Vercel의 서버 배포 메타데이터에서 읽습니다. 새 관측 실패 시 이전 성공 수치와 표를 비웁니다. 메모 제목/본문·토큰·실명·기기 키를 읽거나 표시하지 않습니다.

실제 승인 사용자 조회·타인 메모 거부·회수 후 재조회는 공식 연결/시험 세션이 없어 미실행이며 요청 ID·시각은 null입니다. data/attack-matrix.json에는 도감의 41종 시험 이름과 기대 조건을 적었지만 실행 기록을 만들지 않았습니다. 이 계획 파일의 passed 값을 입력해도 API는 성공 근거로 받지 않습니다. 게임 심판의 기존 승인 기록을 현재 운영 엔진의 41종 재현 완료로 확대하지 않습니다. 회수 수치는 미연결/null이고, 탐지 제안은 local_fixture로 표시합니다. 복구 버전은 실제 사본 검증 API에서 읽으며 운영 정책 쓰기는 없습니다.

첫 두 심판 접수는 UNV_RUN_ENVIRONMENT로 확인불가였습니다. [운영 측 공개 점검 표본](https://github.com/ChoiTimo/byteback-sample-pass/blob/main/src/attack-check.mjs)과 대조해 자기 점검/작전실 HTTP 요청의 관측 메타데이터를 alephEvidence의 caseId/requestKey로 맞췄습니다. 사례 ID는 반환한 실제 점검 ID에 연결하고 요청 키는 새 UUID로 생성합니다. 이 메타데이터를 HTTP 헤더·URL에 보내거나 신원/승인 근거로 사용하지 않습니다. 제출 묶음의 기존 attackId/expected/observed 3필드 계약은 유지합니다. 환경 오류의 원인을 이 차이라고 확정하지 않았습니다. 보완 뒤 회귀40개 통과, 실제 재제출 결과는 별도 확인합니다.

세 번째도 같은 확인불가였습니다. 재검토에서 작전실 endpoint 하나의 네트워크 실패가 자기 점검 전체를 예외로 중단하는 상황을 재현했습니다. src/bundle-checks.mjs는 독립 HTTP 점검을 함께 실행하며 요청과 본문 읽기 전체에5초 제한을 둡니다. AbortSignal을 무시하는 환경도 명시적 시간 제한으로 끝납니다. 실행 못한 항목은 observed의 not_run으로 남기고 다른 항목은 계속 관측합니다. HTTP응답이 있으면 그 상태를 남기며 응답/JSON을 읽지 못한 것을 공격 차단으로 기록하지 않습니다. 공개 로그인 설정을 읽지 못했을 때 원본 API는 실행 못함으로 남깁니다. 원본 API 주소가 다른 출처라면 설정 오류로 중단합니다. 정책·보호 API·미연결 승인 검증은 유지합니다. 이 재현을 실제 심판 환경 오류의 원인으로 확정하지 않고 재제출로 확인합니다.

ace0819 접수도 환경 오류였습니다. 공개 표본에 있는 npm test와 npm run check를 우리 저장소에서 실행하면 Missing script로 즉시 종료하는 차이를 재현했습니다. package.json에 표준 test/check 명령을 연결했습니다. npm ci 후 npm test는 비밀 설정이 필요 없는 로컬 빌드를 먼저 수행하고 기존 전체 회귀시험을 실행합니다. npm run check는 기존 bundle 명령과 같으며 커밋된 깨끗한 저장소와 ignored bundle-notes.json이 필요합니다. 제출 계약이나 시험 결과를 변경하지 않습니다. 심판이 이 명령을 호출했는지는 확인되지 않았으므로 환경 오류의 원인으로 단정하지 않습니다.

3c44d80 접수도 확인불가였습니다. 최신 공개 표본은 runAttackChecks(baseUrl)로 호출하지만 R5 진입점은 config객체만 받아, URL입력 때 점검을 시작하기 전에 구현되지 않은 단계라는 오류로 종료하는 차이를 재현했습니다. 이제 설정 객체와 URL 문자열을 모두 받습니다. URL 방식은 공개 aleph.config.json만 읽고 입력 URL의HTTPS·출처·경로 검증과 원본API 출처 검사도 유지합니다. .env/비밀키를 읽거나 운영 승인으로 사용하지 않습니다. 두 방식이 동일한20건을 실행하는 회귀시험을 추가했습니다. 심판의 실제 호출방식은 공개되지 않았으므로 원인 확정은 재판정이 필요합니다.

### 검사한 커밋에서 재현하기

학생이 만든 부분은 src/decider.mjs, src/detect.mjs, public 접속/작전실 화면, api 자료실/사본 검증/복원, SQL 보관·복원 절차, 자기 점검 코드입니다. 제공 엔진은 ALEPH SDP engine이며 기기 등록·키 보관·로그인과 기기 결합·요청 서명 확인·판정 집행·감사 보관을 맡습니다. 이 저장소에는 제공 엔진의 키·바이너리·설치 명령을 포장하지 않습니다.

1. 설치: 이 공개 저장소를 clone하고 확인할 심판 커밋으로 git checkout한 뒤 npm ci를 실행합니다(Node.js22 이상). 기존 프로젝트의 서버 비밀 설정은 공식 Vercel 설정 화면에 유지하며 Git에 넣지 않습니다. 새 DB라면 해당 단계의 sql 안내를 읽고 학습 전용 프로젝트에만 적용합니다. 현재 DB는 다시 초기화할 필요가 없습니다.
2. 실행: node --test test/*.test.mjs, npm run decider:test, npm run detect:test, node scripts/build-public.mjs --local. Vercel에 같은 커밋을 배포하고 /aleph.json의 저장소·커밋을 대조합니다. /에서 승인 상태, /operations.html에서 관측표를 엽니다. 승인 전 보호 요청은 거부되고, 검증 어댑터 미연결일 때 인증된 요청도503입니다. 정상 승인 CRUD는 공식 연결 후 별도 재시험합니다.
3. 점검: 변경을 커밋하고 ignored bundle-notes.json에 실제 구현과 막힌 점을 적은 뒤 npm run bundle. artifacts/submission.json은 실제 HEAD/원격과 새 자기 점검으로 생성하며 커밋하지 않습니다. 로컬 시험을 심판 또는 운영 승인으로 보고하지 않습니다.
4. 중지: Vercel의 기존 배포를 내리거나 프로젝트를 일시 중지하고, 제공 엔진이 연결돼 있다면 해당 자료실 허용 경로를 끕니다. DB·백업·감사 자료는 지우지 않습니다.
5. 복구: git status와 diff로 이번 변경을 확인하고 필요한 내용을 보존한 뒤 검사한 커밋을 별도 checkout해 재배포합니다. reset --hard를 사용하지 않습니다. 정책 사본 버전/해시/범위를 확인하고 필요할 때 복원할 메모 ID 하나만 지정합니다. 다른 행과 서비스 규칙·감사 기록은 보존합니다. 복구 뒤 위 정상·금지 시험과 bundle, 작전실 새 관측을 다시 실행합니다.
