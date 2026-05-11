# PC Sampling SSD Firmware Fuzzer v5.3

J-Link Halt-Sample-Resume 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v5.3에서는 **idle 시간 최적화** — PCIe L-state settle 단축, diagnose() 가속, idle saturation window-ratio 감지, PS settle cap이 추가되었습니다.

---

## 목차

1. 요구사항
2. 빠른 시작
3. v5.3 변경사항 상세
4. 코드 상단 상수 설정
5. CLI 옵션
6. Power Combo 동작 원리
7. 명령어 목록
8. 출력 디렉터리 구조
9. 크래시 발생 후 처리
10. 정적 분석 커버리지 연동
11. 버전 이력 요약

---

## 요구사항

```
Python 3.9+
pylink-square       # pip install pylink-square
nvme-cli            # apt install nvme-cli
setpci              # apt install pciutils
J-Link V9 (JTAG)
```

실행 권한:
```bash
sudo python3 pc_sampling_fuzzer_v5.3.py [옵션]
```

---

## 빠른 시작

### 기본 실행

```bash
sudo python3 pc_sampling_fuzzer_v5.3.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --output ./output/run_base
```

### Power Combo 활성화

```bash
sudo python3 pc_sampling_fuzzer_v5.3.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --pm \
  --output ./output/run_pm
```

### SWD 불안정 환경에서 diagnose 안정화

v5.3 기본값(10ms)이 너무 짧아 NVMe 불안정이 발생하는 경우:
```bash
sudo python3 pc_sampling_fuzzer_v5.3.py \
  --device Cortex-R8 \
  --interface swd \
  --nvme /dev/nvme0 \
  --diagnose-sleep-ms 50 \
  --diagnose-stability 100 \
  --diagnose-max 5000 \
  --output ./output/run_swd
```

---

## v5.3 변경사항 상세

### [Opt] PCIe L-state settle time 단축 (throughput 98% 개선)

| 항목 | v5.2 | v5.3 | 근거 |
|------|------|------|------|
| `L1_SETTLE` | 5.0s | 0.05s (50ms) | PCIe L1 idle timer 수 μs + DLLP handshake 수 ms |
| `L1_2_SETTLE` | 2.0s | 0.05s (50ms) | CLKREQ# deassert → Tclkoff < 10ms |

L1.2+D3 combo 전환 시:
- v5.2: 5.0 + 2.0 + 5.0 + 2.0 = 14초 대기
- v5.3: 0.05 + 0.05 + 0.05 + 0.05 = 0.2초 대기 (**98% 단축**)

CLI `--l1-settle`, `--l1-2-settle` 옵션으로 실측 기반 조정 가능.

### [Opt] preflight settle 단축

| 항목 | v5.2 | v5.3 |
|------|------|------|
| `RESTORE_SETTLE` | 0.5s | 0.1s |
| `D3_RESTORE_SETTLE` | 1.5s | 0.5s |
| `D3_EXTRA` | 1.0s | 0.2s |

30개 combo preflight 총 시간: ~255초 → ~21초 (**92% 단축**).

### [Opt] diagnose() 샘플 간격 단축 및 변수화

| 항목 | v5.2 | v5.3 |
|------|------|------|
| 샘플 간격 | 50ms (하드코딩) | 10ms (변수: `DIAGNOSE_SAMPLE_MS`) |
| `DIAGNOSE_STABILITY` | 100 | 50 |
| `DIAGNOSE_MAX` | 5000 | 2000 |
| worst case 시간 | 5000×50ms = **250초** | 2000×10ms = **20초** |

- `--diagnose-sleep-ms MS` CLI 옵션으로 런타임 조정 가능
- SWD+레벨시프터 불안정 환경: `--diagnose-sleep-ms 50 --diagnose-stability 100 --diagnose-max 5000` 으로 v5.2 동작 완전 복원

### [Opt] idle saturation window-ratio 기반 조기 감지

기존 consecutive 카운터에 **window-ratio** 조건을 OR로 추가:

```
마지막 IDLE_WINDOW_SIZE(=30)개 PC 중
idle_pcs 해당 비율 ≥ IDLE_RATIO_THRESH(=80%)
→ idle_saturated 조기 종료
```

- consecutive 방식과 OR: 둘 중 하나 충족 시 즉시 종료
- 효과: idle PC가 산발적으로 끼어도(RTOS 인터럽트) 빠르게 감지 → 다음 명령으로 빨리 진행
- `--idle-window-size 0` 으로 비활성화 가능

### [Opt] PS settle 상한(cap) 적용

`PS_SETTLE_CAP_S = 1.0` 상수 추가.
`_init_ps_settle()` 에서 동적 계산된 값과 fallback 값 모두 cap으로 clamp.

| 항목 | v5.2 | v5.3 |
|------|------|------|
| PS4 fallback | 2.0s | min(2.0, 1.0) = **1.0s** |
| PS3 최소값 | 0.5s | min(0.5, 1.0) = 0.5s (변화 없음) |

`--ps-settle-cap 0` 으로 무제한(v5.2 동작) 복원 가능.

---

## 코드 상단 상수 설정

| 상수 | 기본값 | v5.2 대비 | 설명 |
|------|--------|-----------|------|
| `FW_ADDR_START` | `0x00000000` | — | 펌웨어 .text 시작 주소 |
| `FW_ADDR_END` | `0x00147FFF` | — | 펌웨어 .text 끝 주소 |
| `JLINK_DEVICE` | `'Cortex-R8'` | — | J-Link 타깃 |
| `JLINK_SPEED` | `4000` | — | JTAG 속도 (kHz) |
| `L1_SETTLE` | `0.05` | ↓ 5.0 | PCIe L1 settle (초) |
| `L1_2_SETTLE` | `0.05` | ↓ 2.0 | PCIe L1.2 추가 settle (초) |
| `DIAGNOSE_SAMPLE_MS` | `10` | 新 (기존 50ms) | diagnose() 샘플 간격 |
| `DIAGNOSE_STABILITY` | `50` | ↓ 100 | idle 수렴 연속 횟수 |
| `DIAGNOSE_MAX` | `2000` | ↓ 5000 | 최대 샘플 수 |
| `IDLE_WINDOW_SIZE` | `30` | 新 | window-ratio 윈도우 크기 |
| `IDLE_RATIO_THRESH` | `0.80` | 新 | idle 비율 임계값 |
| `PS_SETTLE_CAP_S` | `1.0` | 新 | PS settle 상한 (초) |
| `PM_ROTATE_INTERVAL` | `100` | — | PM/PCIe 전환 주기 |
| `D3_TIMEOUT_MULT` | `4` | — | D3hot timeout 배수 |

---

## CLI 옵션

### v5.3 신규 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--diagnose-sleep-ms MS` | `10` | diagnose() 샘플 간격 (ms). SWD 불안정 시 50으로 복원 |
| `--l1-settle SEC` | `0.05` | PCIe L1 진입 settle 대기 (초) |
| `--l1-2-settle SEC` | `0.05` | PCIe L1.2 추가 settle 대기 (초) |
| `--idle-window-size N` | `30` | window-ratio 윈도우 크기. 0=비활성화 |
| `--idle-ratio-thresh F` | `0.80` | idle 비율 임계값 (0.0~1.0) |
| `--ps-settle-cap SEC` | `1.0` | PS settle 상한 (초). 0=무제한 |

### 기존 주요 옵션 (v5.2 이전)

`--device`, `--nvme`, `--namespace`, `--addr-start`, `--addr-end`, `--output`, `--runtime`
`--pm`, `--interface` (auto/jtag/swd), `--pc-reg-index N`
`--samples` (500), `--interval` (0 us), `--go-settle` (0 ms)
`--saturation-limit` (10), `--global-saturation-limit` (20)
`--diagnose-stability` (50), `--diagnose-max` (2000)
`--calibration-runs` (3), `--no-deterministic`, `--no-mopt`
`--fw-bin`, `--fw-xfer`, `--fw-slot`
`--timeout GROUP MS`, `--passthru-timeout MS`, `--kernel-timeout SEC`
`--seed-dir`, `--resume-coverage`, `--commands`, `--all-commands`

---

## Power Combo 동작 원리

v5.2와 동일. `--pm` 활성화 시 30개 조합(PS0~4 × L0/L1/L1.2 × D0/D3) 랜덤 전환.

v5.3에서 달라진 점:
- L1/L1.2 settle 시간이 대폭 단축되어 throughput이 크게 향상됨
- preflight 30개 combo 검증 시간: ~4분 → ~21초

---

## 명령어 목록

v5.2와 동일. 기본: Identify, GetLogPage, GetFeatures, Read, Write.
확장(`--all-commands`): SetFeatures, FWDownload, FWCommit, FormatNVM, Sanitize, TelemetryHostInitiated, Flush, DatasetManagement, WriteZeroes, Compare, WriteUncorrectable, Verify, DeviceSelfTest, SecuritySend, SecurityReceive, GetLBAStatus.

---

## 출력 디렉터리 구조

```
output/pc_sampling_v5.3/
├── fuzzer_YYYYMMDD_HHMMSS.log
├── coverage.txt
├── corpus/
│   └── seed_NNNN.bin
├── crashes/
│   ├── crash_<cmd>_<opcode>_<md5>
│   ├── crash_<cmd>_<opcode>_<md5>.json
│   ├── crash_<cmd>_<opcode>_<md5>.dmesg.txt
│   ├── replay_<tag>.sh
│   └── replay_data_<tag>/
│       └── data_NNN.bin
└── graphs/
    ├── coverage_growth.png       (* Ghidra 연동 시)
    ├── firmware_map.png          (* Ghidra 연동 시)
    └── uncovered_funcs.png       (* Ghidra 연동 시)
```

---

## 크래시 발생 후 처리

v5.2와 동일:
1. stuck PC 읽기 (J-Link)
2. dmesg 캡처
3. FAIL CMD 상세 출력
4. crash 파일 저장
5. replay .sh 자동 생성 (setpci 포함)
6. UFAS 펌웨어 덤프 (`./ufas` 존재 시)
7. NVMe 드라이버 unbind

---

## 정적 분석 커버리지 연동

퍼저와 같은 디렉터리에 `basic_blocks.txt` / `functions.txt` 두면 자동 로드. v5.2와 동일.

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| v5.3 | **idle 시간 최적화**: L1_SETTLE 5.0→0.05s, L1_2_SETTLE 2.0→0.05s, DIAGNOSE_SAMPLE_MS=10ms(기존 50ms), DIAGNOSE_STABILITY 100→50, DIAGNOSE_MAX 5000→2000, idle window-ratio 조기 감지, PS settle cap=1.0s, preflight settle 단축 |
| v5.2 | Power Combo (NVMe PS + PCIe L/D-state 30개 조합), APST/Keep-Alive 자동 비활성화, replay .sh에 setpci 포함 |
| v5.1 | PM Rotation(`--pm`), Basic Block 커버리지(Ghidra), 시각화 그래프 3종, FAIL CMD 상세 출력, replay .sh 자동 생성, UFAS 덤프 |
| v5.0 | J-Link JTAG/SWD auto-detect, diagnose() 수렴 기반 idle 유니버스 수집 |
| v4.7 | FUA 비트 수정(CDW12[29]), 컨트롤러 범위 명령 NSID=0, `--fw-bin` |
| v4.6 | passthru timeout 분리, crash 시 nvme driver unbind |
| v4.5 | Calibration, Deterministic stage, MOpt mutation scheduling |
