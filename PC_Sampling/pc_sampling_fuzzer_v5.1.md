# PC Sampling SSD Firmware Fuzzer v5.1

J-Link Halt-Sample-Resume 방식으로 커버리지를 수집하고,
`nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v5.1에서는 **PM Rotation(`--pm`)**, **정적 분석 커버리지 연동(Ghidra)**, **시각화 그래프 3종**, **crash 재현 TC 자동 생성**, **UFAS 펌웨어 덤프** 등이 추가되었습니다.

---

## 목차

1. [요구사항](#요구사항)
2. [빠른 시작](#빠른-시작)
3. [코드 상단 상수 설정](#코드-상단-상수-설정)
4. [CLI 옵션](#cli-옵션)
5. [명령어 목록](#명령어-목록)
6. [출력 디렉터리 구조](#출력-디렉터리-구조)
7. [크래시 발생 후 처리](#크래시-발생-후-처리)
8. [정적 분석 커버리지 연동](#정적-분석-커버리지-연동)
9. [seed_replay_test.sh](#seed_replay_testsh)
10. [버전 이력 요약](#버전-이력-요약)

---

## 요구사항

```
Python 3.9+
pylink-square       # pip install pylink-square
nvme-cli            # apt install nvme-cli
J-Link V9 (JTAG)   # 펌웨어 PC 샘플링용
```

실행 권한:
```bash
# nvme-cli는 root 권한 필요
sudo python3 pc_sampling_fuzzer_v5.1.py [옵션]
```

---

## 빠른 시작

### 기본 실행 (PM Rotation 비활성화)

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --output ./output/run_base
```

### PM Rotation 활성화

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --pm \
  --output ./output/run_pm
```

`PM_ROTATE_INTERVAL = 100` 상수로 전환 주기 조정 (코드 상단).

---

### SWD 인터페이스

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
  --device Cortex-R8 \
  --interface swd \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --saturation-limit 0 \
  --global-saturation-limit 20 \
  --output ./output/run_swd
```

---

### 이전 세션에서 재개 (커버리지 이어받기)

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
  --resume-coverage ./output/run_pm/coverage.txt \
  --seed-dir ./output/run_pm/corpus \
  --output ./output/run2
```

---

## PM Rotation 동작 원리

매 `PM_ROTATE_INTERVAL`(기본 100)번 명령마다 Power State를 랜덤으로 전환합니다.

```
[100회 명령 실행]
  NVMe command × 100 (현재 PS 상태에서 실행)

[100번째 명령 완료 후 — executions % 100 == 0 경계]
  1. random.randint(0, 4) → next_ps 결정  (같은 PS 재진입 허용)
  2. SetFeatures(FID=0x02, CDW11=next_ps) 전송  ← _pm_set_state()
  3. [Stats] 출력 (새 PS 상태 반영)

[이후 100회 명령: next_ps 상태에서 실행]
  ...
```

### PS별 동작

| PS | 종류 | timeout_mult | 명령 제한 |
|----|------|-------------|-----------|
| PS0 | Operational (active) | ×1 | 제한 없음 |
| PS1 | Operational (low-power) | ×16 | 제한 없음 |
| PS2 | Operational (low-power) | ×32 | 제한 없음 |
| PS3 | Non-operational | `_prev_op_ps` 기준 | 제한 없음 (IO 포함) |
| PS4 | Non-operational (deep) | `_prev_op_ps` 기준 | 제한 없음 (IO 포함) |

- `timeout_mult`: subprocess 감지 timeout 배수 (PS1/PS2의 wake-up latency 대응)
- PS3/PS4의 `timeout_mult`는 진입 전 마지막 operational PS(`_prev_op_ps`, PS0~2) 기준
  예: PS1(×16) → PS3 진입 시 → PS3에서도 ×16 적용
- PS3/PS4에서 IO 명령도 그대로 전송 (명령 타입 필터 없음)
- `_pm_set_state()` 소요 시간이 `[PM]` 로그에 함께 출력됨
- PM 전송 실패 시 `→ FAIL(rc=N)` 출력, 퍼징 흐름에 영향 없음
- 세션 종료 summary: PS별 `실행 N회 (X%), 진입 N회` 통계 출력

---

## 코드 상단 상수 설정

퍼저 실행 전 코드 상단 `USER CONFIGURATION` 섹션을 환경에 맞게 수정해야 합니다.

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FW_ADDR_START` | `0x00000000` | 펌웨어 .text 섹션 시작 주소 (Ghidra에서 확인) |
| `FW_ADDR_END`   | `0x00147FFF` | 펌웨어 .text 섹션 끝 주소 |
| `JLINK_DEVICE`  | `'Cortex-R8'` | J-Link 타깃 디바이스명 |
| `JLINK_SPEED`   | `12000` | JTAG 속도 (kHz) |
| `NVME_DEVICE`   | `'/dev/nvme0'` | NVMe 캐릭터 디바이스 경로 |
| `NVME_NAMESPACE`| `1` | NVMe 네임스페이스 번호 |
| `MAX_SAMPLES_PER_RUN` | `500` | 명령어 1회당 최대 PC 샘플 수 |
| `TOTAL_RUNTIME_SEC`   | `604800` | 총 퍼징 시간 (초, 기본 1주일) |
| `OUTPUT_DIR`    | `'./output/pc_sampling_v5.1/'` | 결과 저장 경로 |
| `PM_ROTATE_INTERVAL` | `100` | PM Rotation 주기 (`--pm` 활성화 시, N회 명령마다 PS 랜덤 전환) |

타임아웃은 코드 내 `NVME_TIMEOUTS` 딕셔너리에서 설정:

```python
NVME_TIMEOUTS = {
    'command':   18_000,    # 일반 명령어 (ms)
    'format':    600_000,   # FormatNVM
    'sanitize':  600_000,   # Sanitize
    'fw_commit': 120_000,   # FWCommit
    'telemetry': 30_000,    # TelemetryHostInitiated
    'dsm':       30_000,    # DatasetManagement
    'flush':     30_000,    # Flush
}
```

---

## CLI 옵션

### 필수/주요 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--device NAME` | `Cortex-R8` | J-Link 타깃 디바이스명 |
| `--nvme PATH` | `/dev/nvme0` | NVMe 디바이스 경로 |
| `--namespace N` | `1` | NVMe 네임스페이스 번호 |
| `--addr-start HEX` | `0x00000000` | 펌웨어 .text 시작 주소 |
| `--addr-end HEX` | `0x00147FFF` | 펌웨어 .text 끝 주소 |
| `--output DIR` | `./output/...` | 결과 저장 디렉터리 |
| `--runtime SEC` | `604800` | 총 퍼징 시간 (초) |

### 명령어 선택 옵션

| 옵션 | 설명 |
|------|------|
| *(없음)* | 기본 안전 명령어만: `Identify`, `GetLogPage`, `GetFeatures`, `Read`, `Write` |
| `--commands A B C` | 명시적으로 명령어 선택 |
| `--all-commands` | 파괴적 명령어 포함 전체 활성화 |

### v5.1 PM Rotation 옵션

| 옵션 | 설명 |
|------|------|
| `--pm` | PM Rotation 활성화 — 매 `PM_ROTATE_INTERVAL`(기본 100)회마다 PS0~4 중 랜덤 전환 |

### 펌웨어 다운로드 옵션 (v4.7)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--fw-bin PATH` | `None` | 펌웨어 바이너리 경로. 없으면 더미 1KB 시드 사용 |
| `--fw-xfer BYTES` | `32768` | FWDownload 청크 크기 |
| `--fw-slot N` | `1` | FWCommit 슬롯 번호 (1~7) |

### 타임아웃 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--timeout GROUP MS` | (각 그룹 기본값) | 그룹별 timeout 오버라이드 |
| `--passthru-timeout MS` | `2592000000` (30일) | nvme-cli `--timeout` 값 |
| `--kernel-timeout SEC` | `2592000` (30일) | nvme_core 모듈 타임아웃 |

### 샘플링 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--samples N` | `500` | 명령어 1회당 최대 PC 샘플 수 |
| `--interval US` | `0` | 샘플 간격 (마이크로초) |
| `--post-cmd-delay MS` | `0` | 명령 완료 후 추가 tail 샘플링 시간 |
| `--saturation-limit N` | `10` | per-run 수렴 감지 임계값. SWD에서는 `0` 권장 |
| `--global-saturation-limit N` | `20` | global 커버리지 대비 수렴 감지 임계값 |

### Mutation 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--random-gen-ratio R` | `0.2` | 완전 랜덤 입력 생성 비율 |
| `--opcode-mut-prob P` | `0.10` | Opcode 무작위 교체 확률 |
| `--nsid-mut-prob P` | `0.10` | Namespace ID 무작위 교체 확률 |
| `--admin-swap-prob P` | `0.05` | Admin↔IO 교차 전송 확률 |
| `--datalen-mut-prob P` | `0.08` | data_len↔CDW 의도적 불일치 확률 |
| `--exclude-opcodes HEX` | `''` | 제외할 opcode (쉼표 구분) |
| `--max-energy F` | `16.0` | Power Schedule 최대 에너지 |

### Calibration / Deterministic / MOpt 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--calibration-runs N` | `3` | 초기 시드당 calibration 반복 횟수 |
| `--no-deterministic` | `False` | Deterministic stage 비활성화 |
| `--det-arith-max N` | `10` | Deterministic arithmetic delta 최대값 |
| `--no-mopt` | `False` | MOpt mutation scheduling 비활성화 |
| `--mopt-pilot-period N` | `5000` | MOpt pilot 단계 실행 횟수 |
| `--mopt-core-period N` | `50000` | MOpt core 단계 실행 횟수 |

### 기타 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--speed KHZ` | `12000` | JTAG 속도 |
| `--seed-dir DIR` | `None` | 이전 corpus 디렉터리 |
| `--resume-coverage FILE` | `None` | 이전 세션 coverage.txt 경로 |

---

## 명령어 목록

### 기본 명령어 (항상 활성, 비파괴)

| 이름 | Opcode | 타입 | 설명 |
|------|--------|------|------|
| `Identify` | `0x06` | Admin | 장치/네임스페이스 정보 조회 |
| `GetLogPage` | `0x02` | Admin | 로그 페이지 조회 |
| `GetFeatures` | `0x0A` | Admin | 기능 조회 |
| `Read` | `0x02` | IO | 데이터 읽기 |
| `Write` | `0x01` | IO | 데이터 쓰기 |

### 확장 명령어 (`--all-commands` 또는 `--commands`로 활성화)

| 이름 | Opcode | 타입 | timeout_group | 주의 |
|------|--------|------|---------------|------|
| `SetFeatures` | `0x09` | Admin | command | PM injection에서도 내부적으로 사용 |
| `FWDownload` | `0x11` | Admin | command | `--fw-bin` 권장 |
| `FWCommit` | `0x10` | Admin | fw_commit | 펌웨어 재부팅 유발 가능 |
| `FormatNVM` | `0x80` | Admin | format | ⚠️ 미디어 초기화 |
| `Sanitize` | `0x84` | Admin | sanitize | ⚠️ 전체 데이터 소거 |
| `TelemetryHostInitiated` | `0x02` | Admin | telemetry | |
| `Flush` | `0x00` | IO | flush | |
| `DatasetManagement` | `0x09` | IO | dsm | TRIM/Deallocate |

---

## 출력 디렉터리 구조

```
output/pc_sampling_v5.1/
├── fuzzer_YYYYMMDD_HHMMSS.log   # 실행 로그
├── coverage.txt                  # 발견된 PC 주소 목록 (resume용)
├── corpus/
│   ├── seed_0000.bin
│   └── ...
├── crashes/
│   ├── crash_<cmd>_<opcode>_<md5>          # crash 입력 바이너리
│   ├── crash_<cmd>_<opcode>_<md5>.json     # 메타데이터 (stuck PC, dmesg 등)
│   ├── crash_<cmd>_<opcode>_<md5>.dmesg.txt
│   ├── replay_<tag>.sh                     # 재현 TC 스크립트 (직접 실행 가능)
│   └── replay_data_<tag>/
│       ├── data_023.bin                    # write 명령의 실제 페이로드
│       └── ...
└── graphs/
    ├── command_comparison.png              # 명령어별 PCs / Edges / Executions 비교
    ├── <cmd>_cfg.dot / .png               # 명령어별 PC flow CFG
    ├── edge_heatmap_2d.png                # 2D edge 히트맵
    ├── coverage_growth.png                # BB_cov% / funcs_cov% 성장 곡선 *
    ├── firmware_map.png                   # 펌웨어 함수 공간 커버리지 맵 *
    └── uncovered_funcs.png                # 미커버 함수 Top-30 막대 차트 *

* basic_blocks.txt / functions.txt 로드 시에만 생성
```

---

## 크래시 발생 후 처리

timeout crash 감지 시 다음 순서로 자동 처리됩니다:

```
1. stuck PC 읽기 (J-Link)
2. dmesg 캡처
3. FAIL CMD 상세 출력         ← 실패 명령 전체 파라미터 로그 출력
4. crash 파일 저장
5. replay .sh 생성            ← 이전 100개 명령 재현 스크립트 자동 생성
6. UFAS 펌웨어 덤프           ← ./ufas 실행 파일이 있을 때만
7. SSD 상태 보존 (resume 유지)
```

### FAIL CMD 출력 예시

```
================================================================
  !! FAIL CMD !!
  cmd       : Write (IO)
  opcode    : 0x01
  device    : /dev/nvme0n1
  nsid      : 1 (default)
  cdw2      : 0x00000000
  cdw3      : 0x00000000
  cdw10     : 0x00000000
  cdw11     : 0x00000000
  cdw12     : 0x0000001f
  cdw13     : 0x00000000
  cdw14     : 0x00000000
  cdw15     : 0x00000000
  data_len  : 16384 bytes
  data(hex) : deadbeef01020304...
================================================================
```

### replay .sh 생성

crash 발생 시 `crashes/replay_<tag>.sh`가 자동으로 생성됩니다.
최근 100개 명령어(NVMe + PM 전환 포함)를 순서대로 재현합니다.
마지막 항목(crash를 유발한 명령)은 `<- CRASH CMD` 주석으로 표기됩니다.

```bash
# 재현 실행 (어느 디렉토리에서 실행해도 동작)
sudo bash ./output/pc_sampling_v5.1/crashes/replay_<tag>.sh
```

실행 시 각 명령어마다 다음 형식으로 출력됩니다:

```
>>> [005/47] Write
    sudo nvme io-passthru /dev/nvme0n1 --opcode=0x1 --namespace-id=1 ... -w
    rc=0
>>> [006/47] SetFeatures  <- CRASH CMD
    sudo nvme admin-passthru /dev/nvme0 --opcode=0x9 ...
    rc=1
Replay complete.
```

- response buffer(hex dump)는 `/dev/null`로 억제 — 터미널 출력 최소화
- `set +e` 사용 — 중간에 rc≠0인 명령이 있어도 전체 시퀀스 끝까지 실행
- write 명령의 실제 페이로드는 `replay_data_<tag>/data_NNN.bin`으로 함께 저장 (절대경로)

### replay .sh 타임아웃 및 crash state 보존

재현 스크립트는 두 레이어로 crash state를 보존합니다:

| 레이어 | 설정 | 값 | 효과 |
|--------|------|-----|------|
| nvme-cli `--timeout` | 각 명령 | 3,600,000ms (1시간) | crash 명령에서 nvme-cli blocking 유지 → 커널 abort 방지 |
| nvme_core 커널 타임아웃 | 스크립트 헤더 | 2,592,000초 (30일) | 커널 abort/reset_controller 트리거 방지 |

- 정상 응답하는 명령은 즉시 완료 — 스크립트 막히지 않음
- crash 유발 명령에서 스크립트가 blocking 상태로 멈춤 = **crash state 보존 중**
- 분석 완료 후 **Ctrl+C**로 스크립트 종료

### UFAS 펌웨어 덤프

fuzzer와 같은 디렉터리에 `ufas` 실행 파일을 두면 crash 시 자동으로 덤프를 실행합니다.

```
sudo ./ufas <PCIe_bus> 1 <YYYYMMDD>_UFAS_Dump.bin --ini=A815.ini
```

PCIe bus 번호는 `/sys/class/nvme/<ctrl>/address` sysfs에서 자동 탐지하며, 실패 시 `lspci` fallback을 사용합니다.

### JTAG으로 펌웨어 상태 분석

```bash
(gdb) monitor halt
(gdb) info registers pc
(gdb) backtrace
```

### 분석 완료 후 드라이버 재바인드

```bash
lspci | grep -i nvme
echo '0000:02:00.0' | sudo tee /sys/bus/pci/drivers/nvme/bind
```

---

## 정적 분석 커버리지 연동

Ghidra로 펌웨어 바이너리를 분석한 결과를 퍼저에 연동하면 **전체 코드 대비 Basic Block 커버리지 비율**과 **미탐색 함수 목록**을 실시간으로 확인할 수 있습니다.

### 커버리지 단위: Basic Block

PC 샘플링은 확률적이기 때문에 instruction 단위로 집계하면 실행된 블록도 일부 instruction만 포착되어 커버리지가 과소평가됩니다.
Basic Block 단위로 측정하면 블록 내 어느 instruction이든 1회라도 샘플되면 해당 BB 전체를 "실행됨"으로 판단하므로 더 정확합니다.

| 방식 | 특성 |
|------|------|
| Instruction (구) | 샘플 부족 시 과소평가, 노이즈 큼 |
| Basic Block (현) | BB 내 1 샘플 = BB 전체 커버, AFL/libFuzzer 표준 단위 |

### 1단계: Ghidra 분석 파일 추출

Ghidra에서 펌웨어 바이너리 Analyze 완료 후:

```
Ghidra → Window → Script Manager → ghidra_export.py → Run
```

`/tmp/ghidra_export/` 에 두 파일이 생성됩니다:

| 파일 | 내용 |
|------|------|
| `basic_blocks.txt` | BB 목록 (`0xSTART 0xEND` 형식, END는 exclusive) |
| `functions.txt` | 함수 목록 (`entry size name` 형식) |

예상 BB 수: ARM Cortex-R8 기준 100K~300K (Aggressive Instruction Finder 실행 후).

> **Note**: 구 버전의 `code_addrs.txt`는 더 이상 사용하지 않습니다.

### 2단계: 퍼저 디렉토리에 복사

```bash
cp /tmp/ghidra_export/basic_blocks.txt /path/to/pc_sampling_fuzzer_v5.1.py의_디렉토리/
cp /tmp/ghidra_export/functions.txt    /path/to/pc_sampling_fuzzer_v5.1.py의_디렉토리/
```

퍼저 실행 시 자동으로 탐지 · 로드됩니다. CLI 인자 불필요.

### 3단계: 실행 시 출력 변화

**시작 시**:
```
[StaticAnalysis] basic_blocks.txt: 142,500개 BB (0x00000000 ~ 0x00148000)
[StaticAnalysis] functions.txt: 1,521개 함수
StaticAnalysis: basic_blocks=142,500, funcs=1,521
```

**[Stats] 출력마다**:
```
[Stats] exec: 1,000 | pcs: 8,432 | ...
[StatCov] BB: 8.2% (11,685/142,500) | funcs: 187/1,521 (12.3%)
```

**종료 Summary**:
```
BB Coverage      : 8.20% (11,685 / 142,500 basic blocks)
Func Coverage    : 12.29% (187 / 1,521 functions)
```

**종료 시 그래프 3종 자동 생성** (`graphs/`):

| 파일 | 내용 |
|------|------|
| `coverage_growth.png` | 실행 횟수 대비 BB_cov% / funcs_cov% 성장 곡선 |
| `firmware_map.png` | 펌웨어 전체 함수 격자 맵 (초록=커버, 회색=미커버) |
| `uncovered_funcs.png` | 미커버 함수 Top-30 크기 내림차순 막대 차트 |

파일이 없으면 모든 정적 분석 기능이 비활성화되고 기존 동작만 수행합니다.

---

## seed_replay_test.sh

퍼저 초기 시드를 실제 NVMe 명령어로 실행해 동작을 검증하는 스크립트입니다.

```bash
sudo ./seed_replay_test.sh /dev/nvme0 [FW.bin] [fw_xfer_size] [fw_slot]
```

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v5.1** | PM Rotation(`--pm`, 랜덤 PS0~4, 매 100회), PS3/PS4 IO 필터 제거 + `_prev_op_ps` 기준 timeout, Basic Block 커버리지(Ghidra `basic_blocks.txt`), 시각화 그래프 3종, FAIL CMD 상세 출력, replay .sh 자동 생성(1시간 timeout·커널 abort 방지·crash state 보존), UFAS 덤프, idle_pcs addr_range 필터 제거 |
| **v5.0** | `diagnose()` halt 빈도 감소, `_wait_nvme_live()` 실제 응답 확인, `GoEx(0,0)` 전면 교체, SMART-DIAG 코드 정리 |
| **v4.7** | FUA 비트 수정 (CDW12[14]→[29]), 컨트롤러 범위 명령 NSID=0, `--fw-bin/--fw-xfer/--fw-slot` 추가 |
| **v4.6** | io-passthru → namespace device, passthru timeout 분리, 크래시 시 nvme 드라이버 unbind |
| **v4.5** | Calibration, Deterministic stage, MOpt mutation scheduling |
| **v4.4** | Opcode→name 역방향 테이블, Heatmap 크기 제한, timeout 시 dmesg 캡처 |
| **v4.3** | Corpus culling, J-Link heartbeat, 랜덤 생성 비율, 확장 mutation 확률 |
| **v4.2** | subprocess + 샘플링 연동, 글로벌 기준 포화 판정, idle PC 감지 |
| **v4.1** | CDW2~CDW15 시드 필드, NVMe 스펙 기반 초기 시드 자동 생성 |
| **v4.0** | unique PC 기반 coverage signal, CFG/히트맵, AFLfast Power Schedule |
