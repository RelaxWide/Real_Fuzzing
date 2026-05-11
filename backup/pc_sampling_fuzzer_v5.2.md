# PC Sampling SSD Firmware Fuzzer v5.2

J-Link Halt-Sample-Resume 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v5.2에서는 **Power Combo** — NVMe PS + PCIe L-state(L0/L1/L1.2) + D-state(D0/D3) 동시 제어(30개 조합)가 추가되었습니다.

---

## 목차

1. 요구사항
2. 빠른 시작
3. 코드 상단 상수 설정
4. CLI 옵션
5. Power Combo 동작 원리
6. 명령어 목록
7. 출력 디렉터리 구조
8. 크래시 발생 후 처리
9. 정적 분석 커버리지 연동
10. 버전 이력 요약

---

## 요구사항

```
Python 3.9+
pylink-square       # pip install pylink-square
nvme-cli            # apt install nvme-cli
setpci              # apt install pciutils  (v5.2 PCIe 제어용)
J-Link V9 (JTAG)   # 펌웨어 PC 샘플링용
```

실행 권한:
```bash
sudo python3 pc_sampling_fuzzer_v5.2.py [옵션]
```

---

## 빠른 시작

### 기본 실행 (PM/PCIe 제어 비활성화)

```bash
sudo python3 pc_sampling_fuzzer_v5.2.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --output ./output/run_base
```

### Power Combo 활성화 (NVMe PS + PCIe L/D-state 동시 제어)

```bash
sudo python3 pc_sampling_fuzzer_v5.2.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --pm \
  --output ./output/run_pm
```

`--pm` 활성화 시 퍼저가 시작 전 `_detect_pcie_info()`로 PCIe BDF와 capability offset을 자동 탐지합니다.

### SWD 인터페이스

```bash
sudo python3 pc_sampling_fuzzer_v5.2.py \
  --device Cortex-R8 \
  --interface swd \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --output ./output/run_swd
```

### 이전 세션에서 재개

```bash
sudo python3 pc_sampling_fuzzer_v5.2.py \
  --resume-coverage ./output/run_pm/coverage.txt \
  --seed-dir ./output/run_pm/corpus \
  --output ./output/run2
```

---

## 코드 상단 상수 설정

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FW_ADDR_START` | `0x00000000` | 펌웨어 .text 섹션 시작 주소 |
| `FW_ADDR_END` | `0x00147FFF` | 펌웨어 .text 섹션 끝 주소 |
| `JLINK_DEVICE` | `'Cortex-R8'` | J-Link 타깃 디바이스명 |
| `JLINK_SPEED` | `4000` | JTAG 속도 (kHz) |
| `NVME_DEVICE` | `'/dev/nvme0'` | NVMe 캐릭터 디바이스 경로 |
| `NVME_NAMESPACE` | `1` | NVMe 네임스페이스 번호 |
| `MAX_SAMPLES_PER_RUN` | `500` | 명령어 1회당 최대 PC 샘플 수 |
| `TOTAL_RUNTIME_SEC` | `604800` | 총 퍼징 시간 (초, 기본 1주일) |
| `OUTPUT_DIR` | `'./output/pc_sampling_v5.2/'` | 결과 저장 경로 |
| `PM_ROTATE_INTERVAL` | `100` | PM/PCIe 상태 전환 주기 (명령 횟수) |
| `L1_SETTLE` | `5.0` | PCIe L1 진입 settle 대기 (초) |
| `L1_2_SETTLE` | `2.0` | PCIe L1.2 추가 settle 대기 (초) |
| `D3_TIMEOUT_MULT` | `4` | D3hot wake-up timeout 배수 |
| `DIAGNOSE_STABILITY` | `100` | idle 유니버스 수렴 조건 (연속 N회) |
| `DIAGNOSE_MAX` | `5000` | 수렴 전 최대 샘플 수 (worst case 4분) |

타임아웃은 `NVME_TIMEOUTS` 딕셔너리에서 설정 (command: 18,000ms, format/sanitize: 600,000ms, fw_commit: 120,000ms, telemetry/dsm/flush: 30,000ms).

---

## CLI 옵션

### 필수/주요

`--device`, `--nvme`, `--namespace`, `--addr-start`, `--addr-end`, `--output`, `--runtime`

### 명령어 선택

- (없음): 기본 안전 명령어 (Identify, GetLogPage, GetFeatures, Read, Write)
- `--commands A B C`: 명시적 선택
- `--all-commands`: 파괴적 명령어 포함 전체 활성화

### v5.1 PM Rotation / v5.2 Power Combo

- `--pm`: 활성화 (NVMe PS + PCIe L-state + D-state 동시 제어)

### 펌웨어 다운로드

`--fw-bin`, `--fw-xfer` (기본 32768), `--fw-slot` (기본 1)

### 타임아웃

`--timeout GROUP MS`, `--passthru-timeout MS` (기본 2592000000, 30일), `--kernel-timeout SEC` (기본 2592000, 30일)

### 샘플링

`--samples` (기본 500), `--interval` (기본 0 us), `--go-settle` (기본 0 ms), `--post-cmd-delay` (기본 0 ms), `--saturation-limit` (기본 10), `--global-saturation-limit` (기본 20)

### idle 유니버스 수렴

`--diagnose-stability` (기본 100), `--diagnose-max` (기본 5000)

### Mutation

`--random-gen-ratio` (0.2), `--opcode-mut-prob` (0.10), `--nsid-mut-prob` (0.10), `--admin-swap-prob` (0.05), `--datalen-mut-prob` (0.08), `--exclude-opcodes`, `--max-energy` (16.0)

### Calibration / Deterministic / MOpt

`--calibration-runs` (3), `--no-deterministic`, `--det-arith-max` (10), `--no-mopt`, `--mopt-pilot-period` (5000), `--mopt-core-period` (50000)

### 기타

`--speed` (4000 kHz), `--interface` (auto/jtag/swd), `--pc-reg-index N`, `--seed-dir`, `--resume-coverage`

---

## Power Combo 동작 원리

`--pm` 활성화 시 매 `PM_ROTATE_INTERVAL`(기본 100)번 명령마다 30개 조합 중 하나로 랜덤 전환합니다.

### 조합 구성 (30개)

| 축 | 값 |
|---|---|
| NVMe PS | PS0 ~ PS4 (5개) |
| PCIe L-state | L0, L1, L1.2 (3개) |
| PCIe D-state | D0, D3hot (2개) |

### 진입 순서

1. `_pm_set_state(ps)` — SetFeatures(FID=0x02) 전송
2. PS settle 대기 (`enlat + exlat` 기반 동적 계산, PS3 ≥ 0.5s, PS4 ≥ 2.0s)
3. `_set_pcie_l_state()` — LNKCTL ASPMC + L1SS CTL1 + DEVCTL2 설정
4. settle 대기 (L1: `L1_SETTLE=5.0s`, L1.2: `+L1_2_SETTLE=2.0s`)
5. `_set_pcie_d_state()` — PMCSR bits[1:0] 설정
6. D3+L1.x 재진입 후 추가 대기

### PCIe L1.2 진입 절차 (spec r5.0 §5.5.4.1 준수)

1. L1SS enable bits 비활성화 (양측)
2. ASPM 정책 → powersave
3. L1SSCTL1 enable bits 활성화 (RP 먼저)
4. LNKCTL ASPMC 활성화 (EP 먼저, RP 나중)
5. Clock PM (ECPM) 활성화

### timeout 배수

- PS1: ×16 / PS2: ×32 / D3hot: ×4 / PS3/PS4: 진입 전 operational PS(`_prev_op_ps`) 기준

### APST / Keep-Alive 자동 비활성화

`--pm` 활성화 시 퍼저 시작 전 자동으로 NVMe APST(FID=0x0C)와 Keep-Alive(FID=0x0F)를 비활성화합니다. 종료 시 자동 복원됩니다.

### Preflight 검증

퍼징 시작 전 전체 30개 조합을 순서대로 진입/복귀/NVMe 생존 테스트. 실패 조합이 있어도 fuzzing 계속 (경고만 출력).

---

## 명령어 목록

### 기본 (항상 활성, 비파괴)

| 이름 | Opcode | 타입 |
|------|--------|------|
| Identify | 0x06 | Admin |
| GetLogPage | 0x02 | Admin |
| GetFeatures | 0x0A | Admin |
| Read | 0x02 | IO |
| Write | 0x01 | IO |

### 확장 (`--all-commands` 또는 `--commands`)

| 이름 | Opcode | 타입 | 주의 |
|------|--------|------|------|
| SetFeatures | 0x09 | Admin | |
| FWDownload | 0x11 | Admin | `--fw-bin` 권장 |
| FWCommit | 0x10 | Admin | 펌웨어 재부팅 유발 가능 |
| FormatNVM | 0x80 | Admin | 미디어 초기화 |
| Sanitize | 0x84 | Admin | 전체 데이터 소거 |
| TelemetryHostInitiated | 0x02 | Admin | |
| Flush | 0x00 | IO | |
| DatasetManagement | 0x09 | IO | TRIM/Deallocate |
| WriteZeroes | 0x08 | IO | DEAC 지원 |
| Compare | 0x05 | IO | miscompare → error |
| WriteUncorrectable | 0x04 | IO | 에러 주입 |
| Verify | 0x0C | IO | CRC/PI 검증 |
| DeviceSelfTest | 0x14 | Admin | 백그라운드 실행 |
| SecuritySend | 0x81 | Admin | TCG/OPAL |
| SecurityReceive | 0x82 | Admin | TCG/OPAL |
| GetLBAStatus | 0x86 | Admin | 할당 상태 조회 |

---

## 출력 디렉터리 구조

```
output/pc_sampling_v5.2/
├── fuzzer_YYYYMMDD_HHMMSS.log
├── coverage.txt
├── corpus/
│   └── seed_NNNN.bin
├── crashes/
│   ├── crash_<cmd>_<opcode>_<md5>
│   ├── crash_<cmd>_<opcode>_<md5>.json
│   ├── crash_<cmd>_<opcode>_<md5>.dmesg.txt
│   ├── replay_<tag>.sh            (* setpci 명령 포함)
│   └── replay_data_<tag>/
│       └── data_NNN.bin
└── graphs/
    ├── command_comparison.png
    ├── edge_heatmap_2d.png
    ├── coverage_growth.png       (* Ghidra 연동 시)
    ├── firmware_map.png          (* Ghidra 연동 시)
    └── uncovered_funcs.png       (* Ghidra 연동 시)
```

---

## 크래시 발생 후 처리

1. stuck PC 읽기 (J-Link)
2. dmesg 캡처
3. **FAIL CMD 상세 출력** — cmd/opcode/device/nsid/cdw2~15/data_len/data hex/mutations
4. crash 파일 저장
5. **replay .sh 자동 생성** — 이전 100개 명령 + setpci 명령 포함, sudo bash 바로 실행 가능
6. **UFAS 펌웨어 덤프** (`./ufas` 존재 시 자동 실행)
7. NVMe 드라이버 unbind — SSD 펌웨어 상태 장기 보존

replay .sh 실행:
```bash
sudo bash ./crashes/replay_<tag>.sh
```

crash 유발 명령에서 1시간 blocking 유지 → crash state 보존 중. 분석 완료 후 Ctrl+C 종료.

드라이버 재바인딩:
```bash
echo '<BDF>' | sudo tee /sys/bus/pci/drivers/nvme/bind
```

---

## 정적 분석 커버리지 연동

퍼저와 같은 디렉터리에 `basic_blocks.txt` / `functions.txt` (Ghidra `ghidra_export.py` 생성)를 두면 자동 로드됩니다.

### 준비

1. Ghidra Script Manager에서 `ghidra_export.py` 실행
2. 생성된 `basic_blocks.txt`, `functions.txt`를 fuzzer 디렉터리에 복사
3. 퍼저 실행 — CLI 인자 불필요, 자동 탐지

### 출력

- 시작 시: `[StaticAnalysis] basic_blocks.txt: N개 BB`
- Stats마다: `[StatCov] BB: X.X% | funcs: N/M (Y.Y%)`
- 종료 시 그래프 3종: `coverage_growth.png`, `firmware_map.png`, `uncovered_funcs.png`

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| v5.2 | Power Combo (NVMe PS + PCIe L/D-state 30개 조합), `_detect_pcie_info()` BDF/cap 자동 탐지, `_set_pcie_l_state()` ASPM L1/L1.2 제어, `_set_pcie_d_state()` PMCSR D3hot, preflight 30개 combo 검증, replay .sh에 setpci 포함, APST/Keep-Alive 자동 비활성화 |
| v5.1 | PM Rotation(`--pm`), Basic Block 커버리지(Ghidra), 시각화 그래프 3종, FAIL CMD 상세 출력, replay .sh 자동 생성, UFAS 덤프, idle_pcs addr_range 필터 제거, DIAGNOSE_STABILITY 100, DIAGNOSE_MAX 5000 |
| v5.0 | J-Link JTAG/SWD auto-detect, `--pc-reg-index`, `diagnose()` 수렴 기반 idle 유니버스 수집 |
| v4.7 | FUA 비트 수정(CDW12[29]), 컨트롤러 범위 명령 NSID=0, Sanitize 시드 제거, `--fw-bin` |
| v4.6 | io-passthru → namespace device, passthru timeout 분리, crash 시 nvme driver unbind |
| v4.5 | Calibration, Deterministic stage, MOpt mutation scheduling |
| v4.4 | Opcode→name 역방향 테이블, Heatmap 크기 제한, dmesg 캡처 |
| v4.3 | Corpus culling, J-Link heartbeat, 랜덤 생성 비율, 확장 mutation 확률 |
| v4.2 | subprocess + 샘플링 연동, 글로벌 포화 판정, idle PC 감지 |
| v4.1 | CDW2~CDW15 시드 필드, NVMe 스펙 기반 초기 시드 자동 생성 |
| v4.0 | unique PC 기반 coverage signal, CFG/히트맵, AFLfast Power Schedule |
