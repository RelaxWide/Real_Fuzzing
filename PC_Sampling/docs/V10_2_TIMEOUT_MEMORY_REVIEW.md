# v10.2 timeout 이후 PC 모니터링 및 메모리 점검

## 1. Critical issues

보고된 OOM에서 `anon-rss:30947064kB`는 약 **29.5 GiB의 익명 상주 메모리**다.
`total-vm:111847588kB`(약 106.7 GiB)는 가상 주소공간이므로 실제 RAM 사용량과 같지 않다.
이 정도 RSS는 점검이 필요하지만, OOM으로 선택된 프로세스라는 사실만으로
전체 OOM의 유일한 원인이라고 판단할 수 없다. `python3`라는 이름만으로는
주 퍼저와 차트 렌더 자식도 구분되지 않는다. 실기 로그/heap 및 native allocation은 미확인이다.

확인한 코드 결함과 보고된 OOM의 원인 확정은 구분한다. 아래 무제한 출력 버퍼를
수정했지만 **이번 OOM을 재현하거나 해결을 실기 검증한 것은 아니다.**

## 2. Potential bugs

- **PC 모니터링 무한 반복:** timeout 후 `while not stop`이므로 PC를 못 읽어도
  Ctrl+C 전까지 끝나지 않았다. 성공/실패를 모두 포함해 총 20회로 제한했다.
  첫 관측은 즉시, 관측 사이 30초 대기, 20회째 뒤에는 대기하지 않는다.
  기존 sampler close와 SIGINT 복원 경로로 종료한다. 총 대기는 570초이며
  PC 읽기/재연결 시간이 별도로 더해진다. 네이티브 J-Link 호출 자체의 hang에
  대한 강제 벽시계 제한은 아니다.
- **JLink/UFAS 덤프 출력:** `communicate()`가 stdout/stderr 전체를 RAM에 누적했다.
  timeout 뒤에도 자식/하위 프로세스가 파이프를 유지하면 reader가 살아남을 수 있었다.
  stdout/stderr를 출력 폴더의 `JLINK_DUMP_<timestamp>.log`, `UFAS_<timestamp>.log`에
  직접 기록하도록 바꿨다. 대기 스레드는 프로세스 종료만 기다리고 출력은 보관하지 않는다.
  전체 출력은 이 별도 파일에 있으며 주 로그에 다시 합쳐 넣지 않는다.
- **RDDump 줄 버퍼:** PTY 경로의 줄바꿈 없는 출력은 `buf += data`로 계속 커졌고,
  PIPE fallback의 `readline()`도 동일한 위험이 있었다. 두 경로 모두 4 KiB 단위로 읽고
  8 KiB를 넘는 줄은 분할해서 즉시 기록한다. CR/LF와 마지막 미완성 줄도 처리한다.

### 새벽 Identify timeout의 의미

Linux 6.8.12의 Admin opcode `0x06`은 Identify, FW Commit은 `0x10`이다.
`I/O tag 20 (6014)`는 요청 tag와 16진 CID로, PID나 퍼저의 실행 순번이 아니다.
따라서 FAIL CMD의 `actual_opcode=0x10`이었다면 01:20:07에 만료된 요청은 그
FW Commit 요청 자체가 아니다. opcode override가 있었으면 실제 FAIL CMD부터 확인한다.

소스:
[Admin opcode 정의](https://github.com/gregkh/linux/blob/v6.8.12/include/linux/nvme.h),
[timeout 출력 및 Admin queue reset 경로](https://github.com/gregkh/linux/blob/v6.8.12/drivers/nvme/host/pci.c).

퍼저에는 시작/주기 장치정보 조회와 복구 확인용 `nvme id-ctrl`/`id-ns`가 있고,
덤프 도구나 다른 호스트 동작도 별도 요청을 낼 수 있다. 이 dmesg 한 줄에는
발행 주체나 CNS가 없어서 어느 Identify였는지는 특정할 수 없다.

퍼저의 명령 watchdog, nvme-cli의 passthru timeout, 커널 admin/io timeout은
서로 다르다. 현재 기본 설정은 커널 timeout을 2,592,000초(30일)로 늘리고,
timeout crash 종료 시 복원하지 않는다. 제품 override와 실제 실행 설정을 확인해야 한다.
21:56:42부터 01:20:07까지의 3시간 23분 25초를 특정 timeout 설정값으로 역산하거나,
그동안 같은 요청 하나가 대기했다고 단정할 수 없다. 이번 변경은 커널 설정을 바꾸지 않는다.

## 3. Reliability improvements

`process_memory.jsonl` 및 주 로그의 `[Memory]`에 다음을 추가했다.

- 시작, 기존 VMon 주기, timeout 진입, 각 덤프의 30초 대기마다, 덤프 완료,
  종료 차트 전후, PC 관측 각 회차 전후의 시각과 실행 횟수.
- 주 퍼저 PID 및 실행 중인 차트 자식 PID, `VmSize`, `VmRSS`, `RssAnon`,
  `VmHWM`(메모리 값은 kB), 스레드 수 `Threads`.
- corpus/state corpus와 성장·차트 history 컨테이너의 항목 수.

진단은 `/proc` 조회와 파일 기록만 수행하고 NVMe/J-Link 요청을 추가하지 않는다.
진단 이력을 RAM에 쌓지 않는다. 로그 파일은 디스크에 계속 기록되며 디스크 용량 상한을
새로 설정한 것은 아니다. 단계 사이의 순간 peak나 native allocation의 호출 위치까지
추적하지는 않는다.

추가 점검 결과:

- `cmd_traces`는 명령별 최근 200개, 기본 샘플 수는 window당 500개로 제한되어 있다.
  RISC-V window의 raw PC/observation 초기화도 존재한다. 사용자 설정에 따라 크기는 달라진다.
- LLM learning의 target/proposal/generator/recent 저장은 이미 상한이 있고,
  snapshot 저장에도 최소 간격이 있다.
- `_sa_cov_history`, `_cov_growth_hist`, `_csfuzz_history`, `_llm_boost_hist`는
  실행 중 계속 늘어나는 리스트다. 장기 캠페인에서는 증가 요인이지만
  메인 퍼징 루프를 나와 PC 모니터링만 하는 동안에는 추가되지 않는다.
  이번 수정에서 기존 전체 실행 이력을 잘라내지는 않았다.
- 주기 차트는 이전 자식이 실행 중이면 새 자식을 추가하지 않는다. 다만 데이터 복제와
  렌더링 peak가 있고, 종료 차트는 부모에서 실행되므로 해당 단계 RSS를 별도로 기록했다.
- PC 모니터링 루프 자체는 읽은 PC 이력을 저장하지 않는다. 그 구간에서 RSS가
  계속 오르면 남은 스레드나 J-Link DLL 등 native 메모리도 조사해야 한다.

실기에서 추가로 필요한 증거는 실행 파일 버전, OOM PID와 주 퍼저/차트 PID의 대응,
`[NVMe TIMEOUT]`·`FAIL CMD`·`[TimeoutCfg]`·덤프 시작/완료·`[MONITOR]` 시각이다.
새 버전에서는 `process_memory.jsonl`을 함께 보면 어느 단계에서 RSS가 커지는지 비교할 수 있다.

## 4. Suggested tests

장치 없이 56개 회귀 테스트 통과. 이번에 추가한 검증:

- 실패만 또는 성공만 나와도 정확히 20회, 대기는 19회.
- 시작 전 중단 및 회차 사이 Ctrl+C에 해당하는 이벤트 중단.
- 줄바꿈 없는 32 MiB 스트림 처리: Python 추적 메모리 peak 256 KiB 미만.
- CR/LF, 부분 줄, PTY EOF 및 실제 읽기 오류 구분.
- 일반 Python 자식의 stdout/stderr 전체가 파일에 기록되고 부모 PIPE가 없는지 확인.
- 실제 `/proc` 기반 현재 프로세스 PID/RSS JSONL 기록.

기존 sampler 클래스 및 기본 `_send_nvme_command`의 고정 AST 검사도 통과했다.
실제 SSD hang, J-Link DLL의 메모리 사용량, vendor dump 도구의 실행은 여기서 검증하지 않았다.
