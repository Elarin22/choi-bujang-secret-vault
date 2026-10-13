# XDR-01 / XDR-02 / XDR-03 보너스 모듈

자료 출처: https://github.com/ChoiTimo/aleph-defense-starter 의 main 커밋 8a0927400ec0d0a8ff08146db773fec80fb6d216. 세 fixtures는 원본 그대로 복사했다. 2026-10-13 known-cve는 최신 origin/main 2cd777b452525b95e29f12f2c76d9190a594ec23과 파일 차이 없음도 확인했다. 모든 주소는 문서용 대역이며 계정과 경보는 가상이다. 나머지 세 보너스의 시험 자료는 이번 작업에 포함하지 않았다.

## 실행

```
npm run xdr:run -- brute-force
npm run xdr:run -- web-injection
npm run xdr:run -- known-cve
npm run xdr:test
npm run xdr:replay
```

XDR-01/02 제출용 decide.mjs는 npm run xdr:build로 decide-source.mjs와 patterns.json에서 생성한 단일 ES 모듈이다. 저장소의 다른 파일·Node 전용 모듈을 import하지 않아 파일 하나만 전달되는 격리 환경에서도 실행된다. 시험은 data: URL로 모듈을 독립 실행하고 모든 원본 경보의 결과가 로컬 실행과 일치하는지 확인한다. 실제 Jev를 연결할 호스트는 사용하는 decide.mjs의 setJevReviewer를 호출해야 하며, 설정하지 않으면 알림 fallback이다. XDR-03은 patterns.json과 동기화를 시험하는 상수를 decide.mjs에 직접 두며, 외부 reviewer 없이 순수 계산한다.

각 result.json은 공식 aleph.xdr.result.v1 계약을 따른다. 실행기는 실제 decide(alert)를 다시 호출하므로 저장된 결과를 정답으로 읽지 않는다. 경보 ID·계정·주소·정답 순서를 기준으로 행동을 하드코딩하지 않는다. read-alerts.mjs는 경보 수만큼 시각·출발 주소·가명 계정·수준·비밀값을 지운 설명의 다섯 필드를 반환한다. 알림 로그에는 설명 원문·계정·키·URL을 쓰지 않는다.

## 판단

patterns.json의 이름·조건·근거를 사용한다. MITRE T1110/T1110.003과 T1190은 공격 분류의 근거이며 건수와 수준 임계값은 이 학습 정책이다. 명확한 로그인 실패 집계 또는 계정 순회, 반복되는 주입 구조를 복합 근거로 검사한다. 수준 하나나 SQL/script 수업 단어 하나로 차단하지 않는다. 주입 문자열은 문자열로만 검사하며 실행하지 않는다.

확신도 0.85 이상 block, 0.5 이상 alert, 그 미만 record. 명확한 패턴과 정상 이벤트는 로컬 판단하며 애매한 이벤트만 Jev reviewer 인터페이스를 사용한다. 실제 Jev 공급자·URL·키·계약은 제공되지 않았고 현재 연결하지 않았다. unavailable·오류·비정상 confidence·1초 timeout은 alert로 처리한다. 테스트의 mock reviewer는 실제 Jev 응답과 구분한다. reviewer에 전달하는 자료는 패턴 이름·수준·건수뿐이다.

## 기존 판정기를 보존하는 deny overlay

scripts/xdr-run.mjs는 block 후보만 xdr/deny-rules.json에 기록하며 alert/record는 거부 규칙이 되지 않는다. 각 후보는 sourceIp, issuedAt, 15분 뒤 expiresAt, evidenceAlertId를 포함한다. 경보 시각을 기준으로 하므로 과거 시험 경보의 규칙은 실제 현재 시각에는 이미 만료됐다. 재생성 시 다른 모듈의 규칙을 보존하고 같은 경보의 알림은 중복하지 않는다. 파생 로그·규칙·replay 결과는 Git에서 제외한다.

xdr/ztna-overlay.mjs의 withXdr(baseDecide, rules)는 유효한 거부 후보가 일치할 때만 거부하고, 나머지는 기존 baseDecide에 그대로 위임한다. 확인되지 않은 sourceIp는 차단 근거로 사용하지 않는다. 브라우저가 제출한 IP나 X-Forwarded-For를 신뢰하는 연결은 만들지 않았다.

현재 docs/DECIDER_REQUEST.md의 18개 요청 필드에는 확인된 원본 IP가 없고 signals.source도 실경로에서는 none이다. 따라서 운영 엔진의 출발 주소 공급 계약과 xdr_blocked 이유 코드 등록 전에는 실제 ZTNA 경로에 연결됐다고 말하지 않는다. 6단계에서 src/decider.mjs에 기기 등록·자료실 읽기 정책을 추가했지만 XDR overlay는 아직 운영 경로에 연결하지 않았다. 모듈 시험의 정상 통과는 허용하는 시험용 기본 정책에 대한 결과이며 실제 기기 연결이나 운영 사용자 허용 증거가 아니다.

## 관찰한 로컬 결과

- brute-force: block 10, alert 9, record 9.
- web-injection: block 8, alert 9, record 9.
- known-cve: block 8, alert 8, record 8. 읽기 24줄, 정상 차단 0. respond.mjs가 실행기에 연결돼 block만 기존 만료형 overlay로 저장하며 로그에는 패턴 이름만 남긴다. 같은 경보 재실행 시 중복하지 않는다.
- known-cve 모의 연결: 공격 8건 거부, 정상·애매한 거부 0, 확인되지 않은 IP·만료 규칙은 기본 정책에 위임. 기존 거부 정책도 보존한다. npm test 전체 50개 통과. 기존 npm run xdr:replay는 첫 두 모듈용이고 known-cve 연결 재생은 test/known-cve.test.mjs에서 검증한다.
- 모의 overlay: 공격 18건 거부, 정상 거부 0, 애매한 경보 거부 0, 모든 관련 규칙 만료 후 거부 0.
- XDR 회귀시험은 독립 실행을 포함해 6개이며 통과했다. 2026-10-07 두 보너스 운영 심판 성공 및 합산 180/600점을 확인했다. 6단계 변경 뒤 기존 자료실·XDR·기기 정책 시험 총 17개가 통과했다.

## XDR-04 persistence

- 실행: `npm run xdr:run -- persistence`, 시험: `npm run xdr:test`
- 판단: MITRE T1543·T1053 근거. 서명 없음 + 평소 목록 밖 + 자동 시작 + 규칙 수준 10 이상이면 block, 기준 미만이나 확인 자료 부족은 alert, 목록에 있는 항목과 일반 저장은 record입니다. 설명 문장만으로는 차단하지 않습니다.
- 관찰: block 6, alert 5, record 5. 정상 항목 block 0건. 거부 후보는 xdr/deny-rules.json에 15분 만료로 기록되며 기존 known-cve 규칙을 보존합니다.
- 경로·서명 값·출발 주소는 reason에 쓰지 않습니다. 운영 ZTNA 연결 계약은 XDR-03과 같은 제약이 있습니다.
