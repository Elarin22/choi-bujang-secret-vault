# BYTE BACK 방어전 자료실

## 현재 상태: 5단계 저장점 (자료 요청을 서버 한곳으로)

- 화면(`public/index.html`)에서 Supabase Auth 이메일·비밀번호로 로그인·로그아웃하고 가상 메모를 추가·수정·삭제합니다.
- 서버 함수가 `Authorization: Bearer` 토큰을 `src/verify-login.mjs`로 검사합니다. 토큰이 없거나 가짜면 401과 JSON 오류 문구로 거부합니다.
- 소유자 검사: 서버가 확인한 사용자 ID와 DB의 `owner_id`를 비교합니다. URL·본문의 owner_id는 믿지 않고, 추가할 때는 확인된 ID로 저장합니다. 남의 메모 읽기·수정·삭제는 403, 없는 메모는 404이며, 수정에서 소유자를 바꾸려는 요청은 403입니다. 수정·삭제 쿼리에도 `owner_id` 조건을 한 번 더 붙입니다.
- 자료 API (`aleph.config.json`의 `allowedRoutes`와 같음)
  - `GET /api/notes` 내 메모 배열
  - `POST /api/notes` `{id?, title, body}` → `{id}`
  - `GET·PUT·DELETE /api/notes/:id` → `{id,title,body}` (PUT 본문은 `{title,body}`)
- 브라우저는 메모 자료를 Supabase에서 직접 부르지 않습니다. 읽기·추가·수정·삭제는 모두 `/api/notes` 서버 함수를 거치고, 브라우저의 Supabase 호출은 로그인(Auth)뿐입니다.
- DB: `notes` 테이블의 PUBLIC·anon·authenticated 직접 권한을 모두 회수했습니다(`supabase/stage5-revoke.sql`). RLS는 켜 둔 채이고, 서버 함수만 서버 전용 키로 접근합니다. 원본 자료 경로는 `aleph.config.json`의 `originalApiUrl`에 적었습니다.
- 서버 전용 키(`SUPABASE_SECRET_KEY`)는 서버에만 있고 브라우저 파일·응답·로그에 나오지 않습니다.
- 빌드는 허용 경로(`allowedRoutes`)가 들어간 `public/aleph.json`을 만들고, `vercel.json`은 보안 헤더(`X-Content-Type-Options: nosniff`)를 붙입니다.

## 보너스 xdr-01: 무차별 로그인 공격 탐지

가상 Wazuh 경보(`xdr/fixtures/brute-force.json`)에서 로그인 실패를 모아 기준을 넘으면 알리고, 아주 명확한 경우에만 그 주소의 거부 규칙을 만듭니다. 판정기(`src/decider.mjs`)는 고치지 않았습니다.

- `xdr/brute-force/read-alerts.mjs`: 경보에서 시각·출발 주소·계정·규칙 수준·설명(과 경보 번호)만 뽑고 비밀값처럼 보이는 값은 가립니다. 원본은 고치지 않습니다.
- `patterns.json`: MITRE ATT&CK T1110 근거 패턴 2개(같은 주소·같은 계정 실패 연속, 한 주소의 여러 계정 실패). 기준 숫자는 학습용 가정입니다.
- `decide.mjs`: `decide(alert)` → `{action, confidence, reason}`. 0.85 이상 block, 0.5 이상 alert, 그 아래 record. 기준을 넘은 경우는 바로 block, 애매한 경우만 Jev에게 확신도를 묻고, 응답이 없으면 alert입니다. Jev 주소는 `JEV_URL` 환경변수로 줍니다.
- `bridge.mjs`: block 후보만 만료 시각(기본 1시간)·근거 경보 번호가 붙은 거부 규칙(`deny-rules.json`)으로 만들고, 내부망·허용 목록 주소는 차단하지 않고 알림만 남깁니다. 알림은 `xdr/alerts.log`에 한 줄씩 쌓입니다.
- `gate.mjs`: 판정기에 확인 단계로 꽂을 수 있는 부품(`bruteForceStep`). 허용 결정은 만들지 않고 일치하는 거부 규칙만 알려 줍니다. 현재 판정 요청 계약에는 출발 주소가 없어서 아직 `src/decider.mjs`에는 연결하지 않았습니다.
- 실행: `npm run xdr:run -- brute-force` → `xdr/brute-force/result.json`(counts, 정상 이벤트 block 여부), `deny-rules.json`, `xdr/alerts.log` 갱신. 가상 경보 연습이며 심판 판정이나 실제 차단이 아닙니다.

## 알려진 약점 (아직 해결 안 됨)

- 서버 함수는 서버 전용 키(RLS를 우회하는 역할)로 DB를 읽기 때문에, 실제 방어선은 API의 소유자 검사입니다. 이 검사에 빈틈이 생기면 RLS가 막아 주지 못합니다.
- 화면의 로그인에는 공개용 publishable 키가 필요해서 `/api/config`가 이 키를 브라우저에 줍니다. 직접 권한을 회수했으므로 이 키로는 자료를 읽을 수 없지만, 키 자체는 브라우저에 보입니다.
- 옛 공개 커밋(예: 첫 커밋 f0e9f7d)과 옛 배포에는 과거 메모가 남아 있어 과거 노출은 해소되지 않았습니다.

## 환경변수 (Vercel 비밀 입력란에 직접 입력)

| 이름 | 설명 |
| --- | --- |
| `SUPABASE_URL` | 학습용 Supabase Project URL |
| `SUPABASE_SECRET_KEY` | 서버 전용 secret 키. 코드·Git·제출 묶음에 넣지 않음 |
| `SUPABASE_PUBLISHABLE_KEY` | 공개용 publishable 키 (`sb_publishable_…`) |

## 확인 절차

1. Supabase에서 `supabase/stage5-check.sql`을 `stage5-revoke.sql` 적용 전·후에 실행해 anon·authenticated의 권한이 모두 false로 바뀌고 service_role만 남는지 대조합니다.
2. B 계정으로 로그인한 창에서 A의 메모가 보이지 않고, A·B가 각자 자기 메모를 추가·수정·삭제할 수 있는지 확인합니다.
3. 시크릿 창에서 `/api/notes` → 401 + JSON, `/aleph.json` → 열림, `/data.json` → 404.
4. 공개 키로 원본 경로를 직접 부르면 권한 오류(401/403)이거나 빈 결과여야 합니다(`npm run bundle`의 직접 점검이 확인).
5. 저장소 검색: `git grep -n "실습용 가[상]"` → 결과 없음.

## 다시 실행하는 방법

- 시험: `npm run test:r5`
- 제출 묶음: `npm run bundle` (작업 폴더가 커밋된 상태여야 합니다)

규칙 문서: [AGENTS.md](AGENTS.md). 비밀번호·토큰·서버 전용 키·실제 학생 자료는 코드·Git·제출 묶음에 넣지 않습니다.
