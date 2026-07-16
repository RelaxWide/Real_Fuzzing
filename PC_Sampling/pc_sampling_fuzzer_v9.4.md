# pc_sampling_fuzzer v9.4

> per-version 규칙: `v9.4.py` = `v9.3.py` byte-copy + 아래 편집만. v9.3 이전 상세는 각 md.

## 한 줄 요약
v9.3 위에 — **halt PC 샘플러(pylink/J-Link)를 서브프로세스로 격리**해, JLinkARM DLL 이
halt hot-path 에서 파이썬 로그 콜백을 되불러 인터프리터 힙을 손상시키는 **SIGSEGV 를
자식 프로세스에 가둔다**(부모=퍼저는 생존·자동 재기동).

## 배경 (v9.3 에서 확정된 근본 원인)
- gdb 코어 스택: `JLINKARM_Halt → _ctypes(콜백 트램폴린) → PyObject_GetAttr` 에서 SIGSEGV.
  DLL 이 halt 중 등록된 파이썬 콜백(`_jlink_dll_msg`/pylink 기본 `logger.info`)을 되불러
  파이썬을 실행하다 힙을 손상. I/O 워크로드 버스트가 halt 노이즈("could not be halted")를
  폭증시켜 잠복 벡터를 발화(프리즈 아닌 힙손상 SIGSEGV).
- **in-process 로는 못 막음**(v9.3 실측): DLL 콜백 NULL 해제는 이 DLL 이 NULL 을 무시,
  콜백 제거는 pylink 기본 콜백으로 떨어져 오히려 악화. → 프로세스 격리가 유일 해법.

## 변경

### 1. `SubprocessHaltSampler` (부모 프록시, `OpenOCDPCSampler` 상속)
- 파이썬 부기(`current_trace`/`global_coverage`/카운터/`evaluate_coverage`/`load|save_coverage`/
  `_in_range`/`idle_pcs` 등)는 **부모가 상속분 그대로 보유** — IPC 없이 로컬. (fuzzer 의
  `self.sampler.<X>` 28종 표면 중 집합·부기는 전부 부모.)
- pylink 를 만지는 것만 자식에 위임: `connect/start_sampling/stop_sampling/read_stuck_pcs/`
  `_read_all_pcs/_reconnect/_reinit_target/_openocd_alive/diagnose/close/_terminate_proc/_stop_worker`.
- **자식 死 자동 재기동**: 파이프 EOF/오류 감지 → 자식 재기동 + 재연결 → 그 윈도우 샘플만
  손실, 퍼저는 계속. (SIGKILL 로 시뮬 검증: 재기동·pid 교체·빈 트레이스 반환 확인.)

### 2. `_sampler_server_main` (자식 진입점 `--sampler-server <cfg.pkl>`)
- 실제 `JLinkHaltSampler`(v9.3 그대로, **무변경**)를 소유·구동. pylink 콜백이 이 프로세스를
  죽여도 부모는 생존.
- IPC = 검증된 차트 격리와 동일한 **Popen(fork 아님 → 재부팅 위험 없음)** + stdin/stdout
  길이프리픽스(`>I`) pickle. config 는 **`__dict__` 평문 dict** 로 전달(클래스/모듈명 의존 회피).

### 3. 팩토리 / config / CLI
- `sampler_type=='jlink_halt'` → 기본 `SubprocessHaltSampler`(격리 ON).
- `FuzzConfig.jlink_subprocess: bool = True`. `--no-jlink-subprocess` 로 구(in-process, v9.3
  동일·크래시 위험) 동작.

## 검증 상태
- **하드웨어 없이 검증 완료(이 세션)**: FuzzConfig `__dict__` pickle, 자식 spawn, 6개 op
  프로토콜 왕복(connect/start/stop/read_stuck/alive/close), pylink 부재 시 graceful degrade,
  **자식 死→자동 재기동→퍼저 생존**, 부기 상속(set/evaluate_coverage). py_compile OK.
- **eval PC(하드웨어)에서 확인 필요**: ① `connect` 가 실제 J-Link 로 True 인지(자식 로그
  `output/.../.sampler_server.log`), ② PC 샘플이 실제로 수집돼 커버리지 증가하는지,
  ③ 예전 SIGSEGV 대신 `[Sampler/proc] 격리 샘플러 재기동` 로그만 뜨고 **퍼저는 안 죽는지**,
  ④ 성능(명령당 start/stop RPC 왕복) 수용 가능한지.

## 로그 (신규)
- `[Sampler/proc] 격리 샘플러 재기동(#N) — 이전 자식 死…` — 자식 크래시 생존 동작.
- 자식 stderr → `output/pc_sampling_v9.4.0/.sampler_server.log` (J-Link 연결/halt 진단).

## 되돌리기
- `--no-jlink-subprocess` → v9.3 in-process 경로(크래시 재현). 격리가 문제되면 즉시 우회 가능.

## 파일
- `pc_sampling_fuzzer_v9.4.py` — v9.3 byte-copy + 위.
- `fuzzer_config.json` — 무변경(격리는 기본 ON, config 키 불필요; `jlink_subprocess` 는
  코드 기본값). 필요 시 JSON 에 `jlink_subprocess:false` 추가로 끌 수 있음.
