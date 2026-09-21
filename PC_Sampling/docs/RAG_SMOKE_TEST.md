# 기존 인덱스로 하는 장치 없는 RAG 확인

968청크 색인 이후, SSD 캠페인 전에 검색·생성 연결을 확인하는 도구다.
NVMe/JTAG 명령을 실행하지 않고 퍼저 객체도 생성하지 않는다. 생성 결과는 보고서에만 저장한다.
기존 설정 파일과 인덱스를 수정하지 않는다. sudo는 필요 없다.

## 실행

인덱스가 있는 테스트 PC에서 저장소 루트 기준:

```bash
python3 PC_Sampling/tools/rag_smoke_test.py
```

기본 설정은 `PC_Sampling/fuzzer_config.json`, 인덱스는 설정의 경로다.
상대 인덱스 경로는 기존 검색기와 동일하게 `PC_Sampling/` 기준이다.
실행 순서는 검색만 → 생성만(검색 OFF) → 검색 포함 생성이다.
각 단계에 설정의 `timeout_sec` 예산이 따로 적용된다(기본 최대 300초씩).
한 단계 실패해도 나머지를 검사한다. 실행 중 단계 시작/종료를 표시한다.

경로나 질문을 지정하려면:

```bash
python3 PC_Sampling/tools/rag_smoke_test.py \
  --config PC_Sampling/fuzzer_config.json \
  --index-dir /실제/인덱스/루트 \
  --query "NVMe APST Set Features FID 0Ch idle time power state" \
  --timeout 120
```

`--index-dir`에는 버전 폴더가 아니라 `current` 파일이 있는 상위 폴더를 준다.
별도 단계: `--stage retrieval`, `--stage generation`, `--stage rag`.
인덱스가 없는 PC에서도 `--stage generation`은 실행할 수 있다.
프록시 환경은 기존 HTTP 클라이언트를 따른다. 직결 주소를 프록시에서 제외해야 하면:

```bash
no_proxy=192.168.10.1 python3 PC_Sampling/tools/rag_smoke_test.py
```

## 결과 확인

기본 보고서: `PC_Sampling/output/rag_smoke_<시각>/report.json`.
검색 제목·점수는 화면에도 출력한다. 보고서에는 검색 본문, 원본 생성 응답,
파싱 결과, 단계별 시간, 오류와 백엔드 진단을 저장한다.
내부 문서 본문이 포함되므로 보고서 공유 범위에 유의한다. 기본 output은 Git 제외 대상이다.
`--output`으로 지정하는 폴더는 새 경로여야 한다(기존 보고서 덮어쓰기 방지).

- 종료코드 0: 요청한 단계 모두 PASS.
- 종료코드 1: 단계 실패. 보고서의 error/diagnostics를 확인한다.
- 종료코드 2: 설정/인자/출력 경로 오류.
- 검색 PASS: 검색이 생략되지 않았고, 유한한 점수의 hit와 본문이 존재한다.
- 생성 PASS: 실제 v10.3 JSON 파서와 순수 응답 거부 검사 통과.
  잘림, 잘못된 task 컨테이너, JSON 파싱 실패는 FAIL이다. 정상 빈 seeds는 PASS이며
  item_counts로 구분한다.
- RAG PASS: 생성 검사에 더해 실제 검색 성공도 요구한다. 백엔드가 검색 실패 후
  문서 없이 생성을 계속해도 테스트는 FAIL로 기록한다.

연결 확인용 `new_group_seeds` 소형 프롬프트를 사용한다. 서버에 실제 task 스키마를
전달하며 `structured_output=true`, `freeform_retry=false`를 메모리 안에서만 강제한다.
모든 task, 캠페인 전체 프롬프트, 중첩 필드의 완전한 스키마 검증, 명령 의미 검증,
시드 채택, 커버리지 기여는 이 시험의 PASS가 보장하지 않는다.
검색 관련성은 보고서 본문을 읽어 확인해야 한다. 같은 질의의 OFF/ON 생성도 샘플링 결과가
달라질 수 있으므로 한 쌍만으로 RAG 효과를 확정하지 않는다.

revision이 없는 기존 인덱스도 설정이 revision을 요구하지 않으면 기존 정책대로 동작한다.
이 경우 실제 모델 revision 일치는 검증되지 않는다. 시험을 위해 임의 revision을 붙이거나
인덱스를 자동 재생성하지 않는다.

## 개발 검증

```bash
python3 -m unittest discover -s PC_Sampling/tests -p 'test_rag_smoke.py'
```

가짜 HTTP 서버·임시 인덱스로 실제 임베딩/생성 호출과 문서 첨부, 검색 실패 후 폴백의
실패 판정, 기존 파서의 잘림/컨테이너 검사, 보고서 및 종료코드를 검사한다.
실제 DGX/968청크 인덱스 검증은 인덱스가 있는 장비에서 별도로 수행해야 한다.

## 퍼저 연동 로그가 안 보일 때

v10.3의 초기 활성/비활성 메시지는 main 로그뿐 아니라 `llm/llm_*.log`에도
복원한다. 검색·vLLM 모듈도 `pcfuzz` 하위 로거를 사용해 두 파일에 기록한다.
워커 시작과 각 요청의 호출 시작(req_id/task)을 WARNING으로 출력한다.
초기 시딩에도 주기 요청과 같은 실제 설정·검색 질의 meta를 전달한다.

- `[LLM] 활성`: 모듈 로딩 완료. 서버 호출 성공을 뜻하지 않는다.
- `[LLM] 워커 시작`: `_load_seeds()` 이후 워커 기동까지 도달했다.
- `[LLM] 호출 시작`: 워커가 요청을 꺼냈다. 뒤이어 검색/생성이 진행된다.
- `[LLM/rag] 인덱스`: 검색을 실제로 시도하며 인덱스를 읽었다.
- `[LLM/funnel]`: 메인 실행 경로에서 주기 요청을 시도할 때 출력된다.

주기 요청은 독립 타이머가 아니라 명령 완료 처리 중 시간 간격을 확인한다.
장치 초기화/명령에서 멈추면 워커 시작이나 주기 통계에 도달하지 못할 수 있다.
초기 활성 메시지가 main 파일에도 전혀 없다면 실행 파일·실제 인자·현재 실행의
로그 파일을 확인해야 한다. 로깅 수정만으로 실제 요청이 없던 원인까지 확정하지 않는다.
