# PM9M1_HP v10.2 OS freeze — 2026-09-15

> 2026-09-17 재현에서는 SSH·키보드·감시 창이 살아 있는 상태에서 퍼저 PID의
> 커널 `kmem_cache_alloc` fault가 확인됐다. 이전 전체 프리즈와 구분하며,
> 최신 관측값과 미확정 가설은 [커널 fault 조사 인계](HANDOFF_PM9M1_HP_KERNEL_FAULT_20260917.md)를 먼저 볼 것.

## 1. Critical issues

현재 확인된 OS 전체 프리즈의 직접 원인은 없다. 현상은 6.8.12, PM9M1_HP,
639,200회 실행 후 입력 불가, 재부팅 필요. OS 디스크와 시험 SSD는 별도다.
마지막 커널 기록은 반복되던 NSID 불일치, 퍼저 기록은 StatCov이며 pstore는
없었다. 마지막 본체 VmRSS=233712 kB(약 228 MiB)만으로 시스템 전체/자식/
커널 메모리 고갈까지 배제할 수 없다. v9.8이 같은 환경에서 잘 동작한 사실은
버전 차이를 우선 조사할 근거이며, 커널·FW 원인 확정 또는 배제의 증거는 아니다.

HANDOFF_osfreeze_investigation.md는 P7/Cortex-R5 halt 조사이다. 현재 제품은
비침습 OpenOCD PCSR이므로 halt 가설·당시 커널 비교 결론을 그대로 적용하지
않는다. 문서의 netconsole/watchdog은 제안이며 실행 결과가 기록돼 있지 않다.
무음/taint 없음/AER 카운터 0만으로 메모리 손상이나 링크 문제를 배제하지 않는다.

## 2. Potential bugs / 버전 차이

- v10.0부터 공통 `_stop_sampling_checked`가 calibration/workload/PM 등에서도
  복구한다. v9.8보다 OpenOCD 재초기화·재연결 호출 위치가 많다. 실패 뒤
  Identify와 UFAS 덤프 경로도 기존 제품에 적용된다. 실제 호출 여부가 없으면
  이번 트리거로 단정할 수 없다. Identify 실패 전부를 FW hang으로 분류하는
  기존 판정도 과도하며 이 진단 작업에서 자동 변경하지 않았다.
- v10.0부터 기존 제품의 calibration도 정적 BB 단위로 평가한다. 안정성/
  corpus 선택 결과와 후속 실행 순서가 달라질 수 있다. 명령 생성 함수 변경과는
  별개이며, 사용자 보고의 동일한 명령 생성 조건을 부정하는 것이 아니다.
- v10.0의 LLM 요청은 실행수 기준에서 시간 기준으로 변경됐다. v10.2 learning은
  평가·관측·setup 보존·스냅샷 처리를 추가한다. 호스트 실행 타이밍/할당/시험
  순서 차이 후보지만 Python 처리 자체가 페이지 테이블을 쓴다는 뜻은 아니다.
- OpenOCD 실행의 stdout/stderr PIPE를 계속 drain하지 않는 구조가 있다. 출력이
  많으면 자식이 pipe write에서 막힐 수 있다. 이 구조와 start/stop/worker 수명
  관리 메서드는 v9.8에도 동일하다. 단독으로 OS 전체 프리즈를 설명하지 못하며
  버전 신규 버그로 주장하지 않는다. 감시의 자식 wchan으로 확인할 후보다.
- 통계 뒤 flush/fsync와 별도 프로세스 차트 생성은 v9.8에도 존재한다.
  `_generate_graphs_isolated`는 v9.8→v10.0 AST 동일; 진단 추가 전 v10.2 차이는
  메모리 기록 호출이다. StatCov가 마지막이라고 fsync/차트가 원인이라는 뜻은 아니다.
  639200은 10000회마다의 Identify/SMART 조회 시점이 아니다.
- PM9M1의 OpenOCD PC 읽기·초기화·diagnose는 최근 응답 프레이밍 수정 전까지
  v9.8과 AST 동일했다. BM9K1 RISC-V 인증/DM 경로는 이 제품에 선택되지 않는다.

## 3. Reliability improvements — 독립 진행 감시

같은 v10.2 파일에 `--freeze-watch`를 추가했다. 별도 파일/pip/커널 교체는 없다.
감시 모드는 config·seed·learning·J-Link import 전에 실행돼 장치를 열지 않는다.
기본 퍼징에서는 비활성이다. 활성화 시 main/샘플링 스레드의 단계 진입·종료,
실제 nvme-cli argv·Popen 전후·반환/timeout, 통계 fsync 전후를 로컬 비차단 UDP로
전달한다. 수신 확인 대기/로컬 파일 쓰기/무한 큐/장치 추가 조회는 하지 않는다.
메서드 wrapper가 sampler 원래 반환/예외를 보존한다. NVMe 전송 함수는 네 개의
`_freeze_emit` 호출을 제거하면 변경 전과 AST 동일함을 확인했다.

### 실행 — PuTTY 두 창

1. 감시 창: PuTTY의 **Session → Logging → All session output**을 선택하고
   **Windows PC에 저장할 로그 파일**을 지정하고 `Flush log file frequently`를 켠다. 연결된 창에서는 제목 표시줄의
   Change Settings로 설정할 수 있다. 가능하면 매 실행 다른 파일명을 쓴다.
2. 감시 창에서 퍼저 파일이 있는 디렉터리로 이동해 실행한다:

   ```bash
   sudo python3 pc_sampling_fuzzer_v10.2.py --freeze-watch
   ```

   `ready port=47471`이 보이면 준비 완료다. 감시 창은 켜둔다.
3. 원래 퍼저 창: 기존 실행 명령의 `sudo` 뒤에 `env PCFUZZ_FREEZE_TRACE=47471`을
   넣는다. 아래 `<기존 옵션>`은 실제 사용하던 옵션으로 바꾼다:

   ```bash
   sudo env PCFUZZ_FREEZE_TRACE=47471 python3 pc_sampling_fuzzer_v10.2.py <기존 옵션>
   ```

   감시 출력의 `received`가 증가해야 연결된 것이다. 환경변수를 빼면 감시 기능은
   비활성이다. 포트 충돌이면 감시 `--port 47472`와 환경변수 값을 함께 바꾼다.
   캠페인 하나마다 감시 창 프로세스도 다시 실행한다(다른 session은 섞지 않는다).

### 남는 것 / 해석 한계

- 1초마다 JSON 한 줄: 최근 12개 이벤트, 마지막 실제 argv, 현재 계측 단계,
  관측 공백 age_s, 받은 이벤트 수와 누락 수, 본체·직접 자식 RSS/상태/wchan,
  최대 32개 스레드 wchan, MemAvailable/SwapFree/Slab/SUnreclaim/PageTables.
- `nvme.before_popen`은 호스트의 실행 의도, `spawned`는 프로세스 생성 확인이다.
  FW 도달·DMA 완료 증거가 아니다. `returned`도 호스트 반환값이다.
- 감시 heartbeat는 계속 나오고 age_s만 커지면 감시 프로세스는 살아 있으나
  퍼저 이벤트가 멈춘 것이다. 의도적인 명령 대기도 포함하므로 age만으로 불량
  판정하지 않는다. 마지막 단계·자식 상태/wchan을 같이 본다. wchan이 0인 경우도 있다.
- `stats.fsync.enter`만 남으면 해당 지점에서의 대기를 의심할 근거다. UDP/SSH
  유실 가능성이 있어 그 자체로 원인 확정은 아니다. 명령은 기존대로 실행된다.
- heartbeat까지 끊겨도 OS 전체 정지의 단독 증거는 아니다. SSH/네트워크/감시
  출력 정지도 가능하다. 로컬 무입력 증상과 함께 해석한다.
- 전체 CPU/패브릭이 멈추면 감시도 멈춘다. 이미 Windows에 도착한 마지막 기록을
  보존하는 방법이며 커널 스택을 보장하는 방식은 아니다. 1초 출력 사이에는
  오래된 이벤트가 덮여 사라질 수 있다(전체 이력 저장 아님). UDP 누락도 가능하다.
- 진단은 타이밍을 조금 바꾼다. 이 모드에서 무재현이라고 수정 완료를 주장하지 않는다.
  재연결/reset/panic 유도, IOMMU 변경, PCIe 레지스터 폴링은 추가하지 않았다.

## 4. Suggested tests / 검증

실행한 자동 검증: 모의 정상 반환/원래 예외 보존, 송신 실패와 큰 패킷 유실,
/proc 읽기 상한, config 없는 디렉터리에서 감시 프로세스 독립 실행,
송신 중단 후에도 2회 이상 heartbeat와 관측 공백 증가. 전체 89개 테스트 통과.
실제 프리즈 및 PM9M1 장치는 미검증이다.

다음 실기에서는 같은 기존 옵션으로 이 감시만 활성화한다. 사용자가 명령 출력을
전부 옮겨 적을 필요는 없다. 프리즈 후 Windows 감시 로그 마지막 부분의
`phase`, `age_s`, 주요 `wchan`과 heartbeat 지속 여부를 우선 확인한다.
그 증거로 샘플러/명령/통계/learning/차트 중 어디를 대조할지 정한다.

PuTTY 로깅 설정 근거: https://the.earth.li/~sgtatham/putty/latest/htmldoc/Chapter4.html#config-logging
