# pc_sampling_fuzzer v9.4

## 한 줄 요약

현재 v9.3을 기준선으로 다시 만들고, `jlink_halt`의 JLinkARM DLL·pylink·ctypes callback을
영구 자식 프로세스에 격리했다. 부모 fuzzer와 NVMe 실행 경로는 native J-Link 코드를 전혀
호출하지 않으므로 sampler 자식에서 SIGSEGV/SIGBUS가 나도 부모 fuzz 세션은 유지된다.

## v9.3에서 유지한 것

- NVMe command 생성·mutation·corpus·coverage/state 회계
- POR/timeout 및 health monitor 흐름
- J-Link의 halt → PC read → Go 순서와 WFI 실패 처리
- idle universe 진단 및 halt 성공/실패·freeze 통계
- `isinstance(..., JLinkHaltSampler)`에 의존하는 기존 halt 전용 watchdog 분기
- v9.3에서 제거했던 `faulthandler` 상태

새 proxy는 `JLinkHaltSampler`를 상속하므로 기존 halt 전용 분기가 그대로 적용된다.

## 새 구조

### 부모: `SharedProcessJLinkHaltSampler`

- `current_trace`, `global_coverage`, coverage 평가와 저장은 부모가 계속 소유한다.
- 기본 `jlink_halt` factory가 이 proxy를 선택한다.
- 부모는 pylink를 import/생성하지 않는다. `_load_pylink()`는 실제 J-Link 연결을 수행하는
  프로세스에서만 호출된다.
- 시작/종료 hot path는 pipe RPC가 아니라 mmap 제어 필드만 변경한다.

### 자식: `--jlink-sampler-child <mmap-path>`

- `Popen`으로 새 Python 프로세스를 실행하며 fork를 사용하지 않는다.
- 실제 `JLinkHaltSampler`와 JLinkARM DLL callback은 자식만 소유한다.
- 하나의 sampling worker가 epoch 변경을 감지해 PC를 고정 크기 ring에 기록한다.
- connect/reconnect/diagnose용 PC read/close처럼 빈도가 낮은 제어만 framed pickle RPC를 쓴다.

### mmap epoch/ring

- 부모 쓰기: 요청 epoch, sampling enable/disable
- 자식 쓰기: ack epoch/state, heartbeat, write sequence, PC ring, halt 통계, 종료 사유
- 자식은 ring entry 전체를 쓴 뒤 `write_seq`를 publish한다.
- 부모는 stop ack를 받은 뒤 ring을 읽으므로 writer와 동시 접근하지 않는다.
- 기본 용량은 65,536 PC이며 초과하면 최신 항목을 보존하고 유실 수를 경고한다.

### mmap coverage 테이블 (global-saturation 조기종료용)

- ring 뒤에 open-address 해시 테이블(2^19 slot)을 두어 부모의 `global_coverage`를
  자식이 볼 수 있게 미러링한다. 자식 worker는 이 테이블(`coverage_contains`)로
  "이 window 에 전역 신규 PC 가 있었는가"를 판정해 `global_saturated` 조기종료를 낸다.
  in-process `_sampling_worker`의 `global_coverage_ref` 판정과 동일한 의미다.
- 부모만 쓴다. 첫 window 에서 초기 global_coverage(부팅/이전세션 로드분)를 1회 전체
  seed 하고, 이후 `stop_sampling`이 그 window 의 `current_trace` delta 만 push 한다.
  자식 재기동 시 새 mmap 이므로 다음 window 에서 다시 seed 한다.
- 3종 saturation 조기종료(global/idle-consecutive/idle-window)는 in-process 와 동일하게
  모두 `SATURATION_LIMIT>0` 하에서만 활성이다.

## native crash 처리

1. sampling 자식이 SIGSEGV/SIGBUS로 종료된다.
2. 부모는 `Popen.poll()`로 종료를 감지한다.
3. 해당 epoch에서 이미 확정된 ring PC만 회수하고 `openocd_error`를 설정한다.
4. 다음 sampling/reconnect 시 기존 mmap을 폐기하고 새 자식·새 mmap을 만든다.
5. 새 자식이 J-Link에 다시 연결되며 부모 fuzz process와 corpus는 유지된다.

이 변경은 native crash의 근본 원인을 JLinkARM 내부에서 수정하는 것이 아니라, 신뢰할 수 없는
native callback 경계를 fuzzer 프로세스 밖으로 옮겨 전체 fuzz 종료와 Python heap 손상을 막는다.

## CLI

기본 실행은 격리 모드다.

```bash
python3 PC_Sampling/pc_sampling_fuzzer_v9.4.py --product P9
```

v9.3 방식과 A/B가 필요할 때만 in-process로 되돌린다.

```bash
python3 PC_Sampling/pc_sampling_fuzzer_v9.4.py --product P9 --jlink-in-process
```

`--no-jlink`는 이전과 같이 `NullSampler`이며 새 child를 만들지 않는다.

## 검증 결과

하드웨어 없이 다음을 확인했다.

- `python3 -m py_compile` 통과
- 일반 `--help` 진입 및 신규 CLI 노출 확인
- epoch 시작 → PC ring 기록 → stop/max-sample ack → PC 회수 확인
- halt success/fail/freeze/total 공유 통계 확인
- child init/alive/close RPC lifecycle 확인
- child 강제 종료 후 PID가 바뀐 새 child 자동 생성 및 부모 생존 확인
- **global-saturation 조기종료가 mmap coverage 미러링을 통해 실제로 발화**하는지
  (window1=max_samples, window2=부모가 push 한 뒤 `global_saturated`로 조기종료) —
  fake sampler child 로 하드웨어 없이 검증
- 재기동 child 에서 샘플링 재개 및 idle universe 재전송 경로 확인
- `git diff --check` 통과

실제 J-Link 장비에서는 다음을 추가 확인해야 한다.

- P9 connect 및 PC register index 탐지
- 명령 수행 중 coverage 증가와 기존 대비 처리량
- WFI가 많은 구간의 halt 실패율 및 R5 resume 보장
- child를 실제 SIGSEGV/SIGBUS로 종료시킨 경우 재연결 후 다음 명령부터 coverage가 재개되는지

## 변경 파일

- `PC_Sampling/pc_sampling_fuzzer_v9.4.py`
- `PC_Sampling/pc_sampling_fuzzer_v9.4.md`

`fuzzer_config.json`은 변경하지 않았다. 코드 기본값으로 격리가 활성화된다.
