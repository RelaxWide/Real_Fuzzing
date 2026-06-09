# PC Sampling SSD Firmware Fuzzer v8.2

OpenOCD PCSR 비침습 샘플링 + `nvme-cli` passthru 기반 Coverage-Guided + State-Aware Fuzzer.

**v8.2 핵심: P9 profile 정리** — J-Link halt 에서 안 쓰는 OpenOCD/PCSR/UFAS 전용 키
(`openocd_config`/`tcl_prefix`/`pcsr_addrs`/`power_addr`/`power_mask`/`ufas_ini`)를 P9 에서 제거하고,
`main()` 의 profile 읽기를 `.get(기본값)` 으로 관용화해 제품이 N/A 키를 생략할 수 있게 했다.
**PM9M1/BM9H1 동작 불변** (config 해석 byte-identical).

**v8.1 핵심: P9(Cortex-R5) 전용 J-Link(pylink) halt 샘플러** — v8.0 OpenOCD-telnet halt 의
desync(빈 reg pc → resume 누락 → R5 wedge) 문제를 pylink 직접 제어 `JLinkHaltSampler` 로 대체.

v8.0 제품 일반화(`PRODUCT_PROFILES`), v7.x 기능 모두 유지. 상세는 각 버전 md 참조.

---

## v8.2 변경사항 (정리)

J-Link halt 샘플러(P9)는 OpenOCD 도 PCSR 도 UFAS 도 쓰지 않으므로 관련 profile 키가 죽은 값이었다.

- **P9 profile 에서 제거**: `openocd_config`, `tcl_prefix`, `pcsr_addrs`, `power_addr`, `power_mask`,
  `ufas_ini` (6개). 남은 키는 J-Link halt 가 실제로 쓰는 것만.
- **`main()` profile 읽기 `.get(기본값)` 관용화**: 위 키들을 `_profile[...]` 직접 접근 → `.get(...)`.
  `PRODUCT_CONFIGS` 하위호환 뷰의 `openocd_config` 도 `.get`. → 신규 J-Link 제품은 N/A 키 생략 가능.
- **부수**: `r5_pcsr.cfg` 는 이제 fuzzer 코드에서 참조 안 됨(P9 OpenOCD 미사용). 파일은 남겨둠
  (수동 진단/`--sampler halt` 강제 시 참고용). `OpenOCDHaltSampler` 는 `--sampler halt` 로 여전히
  선택 가능(범용 OpenOCD halt fallback) — 기본값으로 쓰는 제품 없음.

---

## 지원 제품

| 제품 | interface | core | coverage 샘플러 | UFAS | J-Link dump | 상태 |
|------|-----------|------|-----------------|------|-------------|------|
| **PM9M1** | SWD | 3 (R8) | OpenOCD PCSR (비침습) | ✅ | ✅ | 정상 |
| **BM9H1** | JTAG | 2 (R8) | OpenOCD PCSR (비침습) | ✅ | ✅ | 정상 |
| **P9** | SWD | R5 단일 | **J-Link halt (pylink)** | ❌ | ❌ | v8.1: `sampler_type='jlink_halt'`. `--product P9` 단독 동작. 튜닝: `P9_BRINGUP.md` |

```bash
sudo python3 pc_sampling_fuzzer_v8.1.py --product PM9M1 --nvme /dev/nvme0n1   # PCSR (변경 없음)
sudo python3 pc_sampling_fuzzer_v8.1.py --product P9    --nvme /dev/nvme0n1   # J-Link halt 자동
# pylink 필요: pip3 install pylink-square (install_fuzzer_deps.sh 에 포함)
```

---

## v8.1 변경사항

### 1. 배경 — OpenOCD telnet halt 의 desync 문제

P9 는 **DBGPCSR 미구현 + ETM 트레이스 핀 없음** → 비침습 PC 샘플링 불가. halt→PC→resume 가
유일한 방법이다. v8.0 의 `OpenOCDHaltSampler` 는 이를 OpenOCD telnet 으로 했는데:

- OpenOCD `halt` 는 코어가 멈출 때까지 내부적으로 최대 5초 폴링.
- 그런데 fuzzer 의 telnet 소켓 read 타임아웃은 **2초**(`_SOCK_TIMEOUT`).
- halt-ack 이 2초를 넘으면 `_telnet_cmd('halt')` 가 프롬프트 없이 빈 값 반환 → 이어진
  `reg pc` 가 desync 되어 `''` → 그 상태로 `resume` 이 들어가 **실제 실행 안 됨**
  → 단일 R5 컨트롤러 코어가 halt 로 굳음 → NVMe 명령이 무한 hang(커널 타임아웃 30일).

`--go-settle` 을 올려도(샘플 간격만 늘림) halt-ack 지연 자체는 안 줄어 해결 안 됨.

### 2. 해결 — `JLinkHaltSampler` (pylink 직접 제어)

`OpenOCDPCSampler` 를 상속하되 **연결 계층과 PC 읽기만 pylink 로 교체**. 샘플링 worker /
diagnose / 회계 / 저장 / 커버리지 평가 인프라는 그대로 상속(코드 재사용, 메인 루프 무변경).

| 동작 | 구현 |
|------|------|
| 연결 | `pylink.JLink(); open(); set_tif(SWD); exec_command("CORESIGHT_SetIndexAPBAPToUse=0"); connect("Cortex-R5", speed=4000)` |
| PC 읽기 | `JLINKARM_Halt → halted() 폴링(≤50ms) → ReadReg(PC) → JLINKARM_Go()`. 전부 블로킹 API → **telnet desync 원천 차단** |
| resume | 항상 `JLINKARM_Go()`. **`restart()` 절대 안 씀**(CPU 리셋 — 살아있는 SSD 손상 방지). go 실패 시 None 반환 |
| PC 레지스터 인덱스 | connect 시 `register_list()` 에서 R15/PC 자동 탐지. `--pc-reg-index` 로 강제 지정 가능 |
| 스레드 안전성 | pylink 단일 세션 → 모든 호출을 `_jlink_lock` 으로 직렬화(worker/메인 스레드 동시 접근 방지) |
| halt 상한 | halted() 폴링 ~50ms 상한 → 못 멈추면 None. 연속 실패는 base 의 `_CONSECUTIVE_FAIL_LIMIT(10)` → 복구 신호 |

DLL 함수(`_dll.JLINKARM_Halt/ReadReg/Go`)를 캐싱해 wrapper 오버헤드 회피(tight halt 루프 가속).

### 3. 제품/설정 와이어링

- **P9 profile**: `sampler_type` `'halt'` → **`'jlink_halt'`**. 신규 필드 `jlink_speed=4000`,
  `jlink_ap_index=0`, `pc_reg_index=None`(자동 탐지).
- **샘플러 선택**(`NVMeFuzzer.__init__`): `'jlink_halt'` → `JLinkHaltSampler` 분기 1개 추가.
- **CLI**: `--sampler` 에 `jlink_halt` 추가, `--pc-reg-index N`(PC 레지스터 인덱스 override) 추가.
- **`import pylink`**: try/except 가드 — pylink 없는 PM9M1/BM9H1 호스트는 무영향, P9 선택 시에만
  필요(미설치면 connect 에서 안내 메시지).

### 4. USB 점유 충돌 처리

P9 는 pylink 가 J-Link USB 를 **in-process 단독 점유**. JLinkExe 를 spawn 하거나 OpenOCD 가
USB 를 가졌다고 가정하는 경로를 sampler 경유로 우회(isinstance 가드 2곳):

- `_shutdown_openocd_for_jlink`: J-Link 샘플러면 early-return(OpenOCD 없음).
- 크래시 후 PC 모니터 루프: JLinkExe subprocess 대신 `sampler.read_stuck_pcs()`(pylink 핸들 경유).
- 크래시 stuck PC 읽기(`_reinit_target`/`read_stuck_pcs`)는 이미 sampler 메서드 경유 → 자동 처리.
- P9 profile 은 `enable_ufas=False`/`enable_jlink_dump=False` 라 덤프/UFAS 본체는 이미 skip.

### 5. 코드 영향 범위 (v8.0 → v8.1)

| 사이트 | 변경 |
|--------|------|
| `import pylink` (try/except) | 신규 (가드) |
| `FuzzConfig` | `jlink_speed`/`jlink_ap_index`/`pc_reg_index` 추가 |
| `PRODUCT_PROFILES['P9']` | `sampler_type='jlink_halt'` + 3 필드 |
| `JLinkHaltSampler` 클래스 | **신규** (~150줄). connect/_read_all_pcs/_openocd_alive/_reconnect/_reinit_target/close override + OpenOCD 메서드 no-op |
| `NVMeFuzzer.__init__` 샘플러 선택 | `'jlink_halt'` 분기 추가 |
| `_shutdown_openocd_for_jlink` | J-Link 샘플러 early-return 가드 |
| 크래시 PC 모니터 | J-Link 샘플러는 `read_stuck_pcs` 경유 |
| CLI `--sampler`/`--pc-reg-index` | choices 추가 / 신규 옵션 |
| `install_fuzzer_deps.sh` | `pylink-square` 추가 |

**PM9M1/BM9H1 동작 불변** — PCSR 경로(OpenOCDPCSampler) 코드는 손대지 않음.

---

## 검증

- `python3 -c "import ast; ast.parse(...)"` 문법 OK.
- `--help` 에 `--sampler {pcsr,halt,jlink_halt,null}` / `--pc-reg-index` 노출 확인.
- `--product P9` → `sampler_type='jlink_halt'`, `JLinkHaltSampler` 인스턴스화/`_pcsr_addrs=[0x80030000]`/
  invalid mask(SWD DPIDR) 확인. connect 전 `_openocd_alive()=False`, `_read_all_pcs()=None`(graceful).
- pylink 2.0.0 설치 확인.

평가 환경에서 할 일은 `P9_BRINGUP.md` 참조 (J-Link halt 실측: idle universe 수렴, NVMe timeout,
PC 레지스터 인덱스 확인).
