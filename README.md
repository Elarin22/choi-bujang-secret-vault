# BYTE BACK 방어전 자료실

## 현재 상태: 2단계 저장점

- 화면(`public/index.html`)은 `/api/notes`를 호출해 가상 메모 네 건을 보여 줍니다.
- `api/notes.js`(Vercel 서버 함수)가 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`로 학습용 Supabase의 `notes` 테이블을 읽습니다. 키는 서버에만 있고 브라우저 파일·응답·로그에 나오지 않습니다.
- `notes` 테이블은 RLS를 켜고 anon·authenticated의 권한을 회수했습니다. `owner_id uuid` 칸이 있으며 외래키는 없습니다.
- 저장소와 정적 파일(`public/`)에는 메모가 없습니다. `/data.json`은 존재하지 않습니다(404).
- 테이블 생성 SQL은 메모 문장이 들어 있어 저장소에 넣지 않았습니다.

## 알려진 약점

- `/api/notes`는 로그인 없이 누구나 호출할 수 있는 공개 주소입니다. 접근 통제는 3단계 이후 과제입니다.
- 옛 공개 커밋과 옛 Vercel 배포에는 메모가 남아 있을 수 있습니다. 이 단계로 과거 노출이 해소됐다고 볼 수 없습니다.

## 확인 절차 (3단계 제작 3)

1. 최신 저장소 파일 검색: `git grep -n "실습용 가[상]"` → 결과가 없어야 합니다.
2. 배포된 정적 파일 검색: `curl -s https://<배포주소>/ https://<배포주소>/data.json | grep -c "실습용 가[상]"` → `0`이어야 합니다.
3. `curl -s -o /dev/null -w "%{http_code}" https://<배포주소>/data.json` → `404`.
4. 공개 API의 남은 약점 기록: `curl -s https://<배포주소>/api/notes` → 메모가 반환되면 접근 통제 전이라는 뜻입니다.

기록란
- 검색 결과(저장소·배포): 직접 실행 후 기록
- 공개 API 약점: 직접 실행 후 기록
- 옛 이력 한계: 옛 공개 커밋·옛 배포 URL에는 과거 메모가 남아 있을 수 있어 과거 노출은 해소되지 않았습니다.

## 다시 실행하는 방법

- 로컬 화면 빌드 확인: `npm run build -- --local`
- 시험: `npm run test:r5`
- 제출 묶음: `npm run bundle` (`aleph.config.json`의 `publicAppUrl`에 실제 `https://…vercel.app` 주소가 있어야 하고, 작업 폴더가 커밋된 상태여야 합니다)

## 배포 자동 처리

`vercel.json`은 `public`을 정적 결과물로 배포하고, `api/` 폴더는 서버 함수로 배포합니다. 빌드(`npm run build`)는 Vercel이 주는 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증해 `public/aleph.json`을 만듭니다. `public/data.json`이나 루트 `data.json`이 있으면 빌드가 실패합니다.