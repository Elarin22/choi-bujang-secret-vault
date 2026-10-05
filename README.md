# BYTE BACK 방어전 자료실

## 현재 상태: 3단계 저장점 (진짜 로그인)

- 화면(`public/index.html`)에서 Supabase Auth 이메일·비밀번호로 로그인·로그아웃하고, 로그인하면 가상 메모를 추가·수정·삭제합니다. 로그인 실패 이유는 화면에 표시됩니다.
- 서버 함수가 요청의 `Authorization: Bearer` 토큰을 `src/verify-login.mjs`로 검사합니다. 토큰이 없거나 검사에 실패하면 자료 없이 401로 거부합니다. 브라우저가 보낸 userId·role은 쓰지 않고, 서버가 확인한 사용자 ID만 `owner_id`로 저장합니다.
- 자료 API (`aleph.config.json`의 `allowedRoutes`와 같음)
  - `GET /api/notes` 로그인 사용자의 메모 배열
  - `POST /api/notes` `{id?, title, body}` → `{id}` (id가 없으면 서버가 UUID 생성)
  - `GET·PUT·DELETE /api/notes/:id` 한 건 조회·수정·삭제 (지운 뒤 GET은 404)
- `notes` 테이블: RLS 켬, anon·authenticated 권한 회수, `owner_id uuid`(외래키 없음). 테이블 생성 SQL은 메모 문장이 들어 있어 저장소에 넣지 않았습니다.
- 서버 전용 키(`SUPABASE_SECRET_KEY`)는 서버 환경변수에만 있고 브라우저 파일·응답·로그에 나오지 않습니다.
- 저장소와 정적 파일에는 메모가 없고 `/data.json`은 404입니다.

## 알려진 약점 (아직 해결 안 됨)

- 로그인은 신원 확인일 뿐입니다. 소유자 검사가 없어서 로그인한 B가 A의 메모 id를 알면 읽고·고치고·지울 수 있습니다. 4단계 과제입니다.
- 옛 공개 커밋(예: 첫 커밋 f0e9f7d)과 옛 배포에는 과거 메모가 남아 있어 과거 노출은 해소되지 않았습니다.

## 환경변수 (Vercel 비밀 입력란에 직접 입력)

| 이름 | 설명 |
| --- | --- |
| `SUPABASE_URL` | 학습용 Supabase Project URL |
| `SUPABASE_SECRET_KEY` | 서버 전용 secret 키. 코드·Git·제출 묶음에 넣지 않음 |
| `SUPABASE_PUBLISHABLE_KEY` | 공개용 publishable 키 (`sb_publishable_…`). 화면 로그인에 쓰임 |

`aleph.config.json`의 `identityProvider`에는 검사에 쓰는 발급자 정보(`issuer`, `audience`, `jwksUrl`)를 적습니다. 비밀 키는 넣지 않습니다.

## 확인 절차

1. 저장소 최신 파일: `git grep -n "실습용 가[상]"` → 결과 없음이어야 합니다.
2. `curl.exe -s -o NUL -w "%{http_code}" https://<배포주소>/data.json` → `404`.
3. 시크릿 창에서 로그인 없이 `/api/notes` → 401 (자료 없음).
4. A 계정 로그인 뒤 메모 추가·수정·삭제 동작, 로그아웃하면 로그인 화면으로 돌아옴.

## 다시 실행하는 방법

- 시험: `npm run test:r5` (로그인 없는 요청 거부, 사용자 ID 서버 확정, CRUD 흐름 시험)
- 제출 묶음: `npm run bundle` (`publicAppUrl`·`identityProvider`가 실제 값이어야 하고 작업 폴더가 커밋된 상태여야 합니다)

## 배포 자동 처리

`vercel.json`은 `public`을 정적 결과물로, `api/`를 서버 함수로 배포하며 `aleph.config.json`을 함수에 포함합니다. 빌드는 `public/aleph.json`에 저장소·커밋·주소를 기록하고, `data.json`이 남아 있으면 실패합니다.

규칙 문서: [AGENTS.md](AGENTS.md). 비밀번호·토큰·서버 전용 키·실제 학생 자료는 코드·Git·제출 묶음에 넣지 않습니다.