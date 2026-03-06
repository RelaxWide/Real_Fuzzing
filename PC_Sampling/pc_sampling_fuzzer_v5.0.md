# PC Sampling SSD Firmware Fuzzer v5.0

J-Link Halt-Sample-Resume 방식으로 커버리지를 수집하고,
`nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v5.0은 다중 SSD 제품 지원에 초점을 맞춘 버전입니다.
JTAG/SWD 자동 전환, PC 레지스터 인덱스 자동/수동 탐지,
SWD 환경에서의 idle 감지 재설계가 핵심 변경입니다.

---

## 목차

1. [v5.0 변경사항](#v50-변경사항)
2. [요구사항](#요구사항)
3. [빠른 시작](#빠른-시작)
4. [코드 상단 상수 설정](#코드-상단-상수-설정)
5. [CLI 옵션](#cli-옵션)
6. [명령어 목록](#명령어-목록)
7. [출력 디렉터리 구조](#출력-디렉터리-구조)
8. [크래시 발생 후 처리](#크래시-발생-후-처리)
9. [새 SSD 제품 포팅 절차](#새-ssd-제품-포팅-절차)
10. [seed_replay_test.sh](#seed_replay_testsh)
11. [버전 이력 요약](#버전-이력-요약)

---

## v5.0 변경사항

### [Feature] `--interface auto/jtag/swd` — J-Link 인터페이스 자동 탐지

**배경**: 제품마다 J-Link 연결 인터페이스가 다를 수 있음 (JTAG 전용 / SWD 전용 / 양쪽 지원).

**기존**: `FuzzConfig.interface`가 `JTAG`으로 하드코딩.
SWD 전용 제품에서 연결 실패.

**변경**:
- `--interface auto` (기본값): JTAG 연결 시도 → 실패 시 SWD로 자동 전환
- `--interface jtag` / `--interface swd`: 강제 지정
- `FuzzConfig.interface`: `int` → `Optional[int]` (None = auto)

```bash
# auto (기본값) — 대부분의 경우 이것으로 충분
sudo python3 pc_sampling_fuzzer_v5.0.py --device Cortex-R8 ...

# SWD만 지원하는 제품
sudo python3 pc_sampling_fuzzer_v5.0.py --device Cortex-R8 --interface swd ...
```

---

### [Feature] `--pc-reg-index N` — PC 레지스터 인덱스 수동 지정

**배경**: ARM 아키텍처별로 J-Link 레지스터 인덱스 체계가 다름.

| CPU | 인터페이스 | PC 인덱스 |
|-----|-----------|-----------|
| Cortex-R8 | JTAG/SWD | 9 |
| Cortex-M4/M7 | SWD | 15 |
| Cortex-A | JTAG | 자동 탐지 |

**변경**:
- `_find_pc_register_index()` 탐색 패턴 강화: `R15`, `PC`, `EPC`, `MEPC`, `SEPC`
- 탐지 실패 시 `--pc-reg-index N`으로 강제 지정
- `jlink_reg_diag.py`로 올바른 인덱스 확인 후 지정

```bash
# 자동 탐지 실패 시
sudo python3 pc_sampling_fuzzer_v5.0.py --pc-reg-index 9 ...
```

---

### [Redesign] `diagnose()` — 수렴 기반 idle 유니버스 수집

**배경**: SWD에서 debug halt가 WFI를 깨워 idle 중 20+개 PC가 관찰됨.

**기존 문제**:
```
고정 20회 샘플 → 빈도 임계값(30%) 체크 → 단일 idle_pc 설정
SWD에서: 20+개 PC가 고르게 등장 → 어느 PC도 30% 미달 → idle_pc = None
→ idle saturation 완전 비작동
```

**새 방식 — adaptive 수렴 샘플링**:
```
새 PC가 나올 때마다 idle_pcs에 추가
새 PC 없이 DIAGNOSE_STABILITY(50)회 연속 → 수렴 완료
최대 DIAGNOSE_MAX(1000)회 상한
수집된 모든 unique PC (범위 내) = idle 유니버스
```

**결과**:
| 인터페이스 | 수렴 시점 | idle_pcs 크기 |
|-----------|----------|---------------|
| JTAG | 수십 샘플 | 1~2개 (WFI 고정) |
| SWD | 수백 샘플 | 20+개 (인터럽트 포함) |

두 경우 모두 idle 유니버스가 완성되면 퍼징 중 idle 감지 정확도 동일.

---

### [BugFix] `_sampling_worker()` — idle 유니버스 기반 감지

**배경**: idle_pcs가 구성되더라도 샘플링 워커가 단일 idle_pc와만 비교하던 문제.

**기존**: `if pc == idle_pc` → SWD에서 idle_pc=None → 조기종료 불가
**변경**: `if pc in idle_pcs` → idle 유니버스 집합 기반 비교

**정확성 보장**:
- NVMe 커맨드 처리 코드는 idle 유니버스 밖에 있음 (커맨드 핸들러, DMA 코드 등은 idle 시 미실행)
- 처리 중: idle 유니버스 밖 PC 등장 → `consecutive_idle` 리셋 → 조기종료 없음
- idle 복귀 후: 유니버스 내 PC만 연속 → `sat_limit` 도달 → 조기종료

---

### [BugFix] `connect()` JTAG auto — halt 후 CPU resume 누락

**증상**: JTAG auto-detect 경로에서 퍼저 시작 직후 `_log_smart()` 10초 타임아웃.
nvme-cli를 수동으로 실행하면 정상 동작하는데 퍼저에서만 발생.

**원인**:
```
connect() JTAG auto 경로:
  jlink.halt()          ← JTAG 연결 검증을 위해 CPU halt
  halted() polling 확인 ← halt 상태 확정
  _probe_pc_register_index()
  return True           ← ★ CPU가 여전히 halt 상태로 반환!
↓
_log_smart() 호출 시 SSD 펌웨어가 멈춰있어 NVMe 명령을 처리 못함 → 10초 타임아웃
```

**수정**: JTAG 검증 완료 후 즉시 `jlink.go()` 호출하여 CPU resume.

---

### [BugFix] `_go_func` — raw `JLINKARM_Go` → `jlink.go()`

**원인**: `_go_func = jlink._dll.JLINKARM_Go` (raw ctypes DLL 호출).
ctypes 기본 설정(인자 타입 미지정)으로 호출 시 silently fail 가능.
`jlink.go()` (pylink 고수준 래퍼)는 내부적으로 `JLINKARM_GoEx(0, 0)` 사용.

**수정**: `self._go_func = self.jlink.go`
`_read_pc()`, `read_stuck_pcs()` 양쪽 모두 `_go_func()` 무인자 호출이므로 호환.

---

### [BugFix] `diagnose()` — `None` 샘플이 수렴 카운터 미반영

**증상**: idle 유니버스 수집이 항상 DIAGNOSE_MAX(1000)회까지 실행됨.

**원인**: `_read_pc()` 실패 시 반환되는 `None`이 수렴 카운터(`consecutive_no_new`)를
증가시키지 않아 수렴 조건에 영향을 미치지 못함.

**수정**: `None` 또는 기존 PC 재등장 모두 수렴 카운터 증가.

```python
# 수정 전 (버그)
if pc is not None:
    if pc not in idle_universe:
        consecutive_no_new = 0
    else:
        consecutive_no_new += 1
# None이면 카운터 변동 없음 → 수렴 불가

# 수정 후
if pc is not None and pc not in idle_universe:
    idle_universe.add(pc)
    consecutive_no_new = 0
else:
    consecutive_no_new += 1  # None + 기존 PC 재등장 모두 카운터 증가
```

---

### [BugFix] `_calibrate_seed()` RC_TIMEOUT — crash 처리 없이 루프 탈출

**증상**: Calibration 중 timeout이 발생해도 `_timeout_crash` 플래그가 세워지지 않아
메인 루프 직전의 `if self._timeout_crash: return` 체크가 dead code로 동작.

**수정**: `_handle_timeout_crash()` 메서드 추출 (main loop와 공용).
RC_TIMEOUT 시 calibration에서도 stuck PC 분석 → dmesg 캡처 → crash 저장 → 플래그 설정 → `break`.

---

## 요구사항

```
Python 3.9+
pylink-square       # pip install pylink-square
nvme-cli            # apt install nvme-cli
J-Link V9 (JTAG/SWD)
```

실행 권한:
```bash
sudo python3 pc_sampling_fuzzer_v5.0.py [옵션]
```

---

## 빠른 시작

### 기본 실행 (auto 인터페이스, 안전 명령어만)

```bash
sudo python3 pc_sampling_fuzzer_v5.0.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --output ./output/run1
```

`--interface auto`가 기본값이므로 JTAG/SWD를 자동 감지합니다.

---

### SWD 전용 제품

```bash
sudo python3 pc_sampling_fuzzer_v5.0.py \
  --device Cortex-R8 \
  --interface swd \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --output ./output/run_swd
```

> SWD 환경에서 idle 유니버스 수집에 수백 샘플이 필요할 수 있습니다.
> 퍼저 시작 시 `[Diagnose]` 로그에서 수렴 과정을 확인할 수 있습니다.

---

### 펌웨어 포함 전체 명령어

코드 상단 user setting에서 파일명을 지정합니다:

```python
# pc_sampling_fuzzer_v5.0.py 상단
FW_BIN_FILENAME = 'FW.bin'   # .py와 같은 디렉터리에 위치
```

```bash
sudo python3 pc_sampling_fuzzer_v5.0.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --all-commands \
  --fw-xfer 32768 \
  --fw-slot 1 \
  --output ./output/run_fw
```

---

### 이전 세션 재개

```bash
sudo python3 pc_sampling_fuzzer_v5.0.py \
  --resume-coverage ./output/run1/coverage.txt \
  --seed-dir ./output/run1/corpus \
  --output ./output/run2
```

---

## 코드 상단 상수 설정

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FW_ADDR_START` | `0x00000000` | 펌웨어 .text 시작 주소 |
| `FW_ADDR_END`   | `0x00147FFF` | 펌웨어 .text 끝 주소 |
| `JLINK_DEVICE`  | `'Cortex-R8'` | J-Link 타깃 디바이스명 |
| `JLINK_SPEED`   | `12000` | JTAG/SWD 속도 (kHz) |
| `NVME_DEVICE`   | `'/dev/nvme0'` | NVMe 캐릭터 디바이스 경로 |
| `NVME_NAMESPACE`| `1` | NVMe 네임스페이스 번호 |
| `FW_BIN_FILENAME`   | `None` | FWDownload 시드용 펌웨어 파일명 (`.py`와 같은 디렉터리). `None`이면 더미 1KB 시드 |
| `DIAGNOSE_STABILITY` | `50` | idle 유니버스 수렴 조건: 새 PC 없이 연속 N회 |
| `DIAGNOSE_MAX`  | `1000` | idle 유니버스 수집 최대 샘플 수 |
| `SATURATION_LIMIT` | `10` | idle 유니버스 내 PC 연속 N회 → 조기종료 |
| `MAX_SAMPLES_PER_RUN` | `500` | 명령어 1회당 최대 PC 샘플 수 |
| `TOTAL_RUNTIME_SEC`   | `604800` | 총 퍼징 시간 (초, 기본 1주일) |

타임아웃 (코드 내 `NVME_TIMEOUTS` 딕셔너리):

```python
NVME_TIMEOUTS = {
    'command':   18_000,    # 일반 명령어 (ms)
    'format':    600_000,   # FormatNVM
    'fw_commit': 120_000,   # FWCommit
    'telemetry': 30_000,    # TelemetryHostInitiated
    ...
}
```

---

## CLI 옵션

### J-Link / 연결 옵션 (v5.0 신규/변경)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--device NAME` | `Cortex-R8` | J-Link 타깃 디바이스명 |
| `--interface [auto\|jtag\|swd]` | `auto` | **[v5.0]** 인터페이스 선택. auto=JTAG 시도 후 실패 시 SWD 자동 전환 |
| `--speed KHZ` | `12000` | JTAG/SWD 속도 |
| `--pc-reg-index N` | `None` | **[v5.0]** PC 레지스터 인덱스 강제 지정 (자동 탐지 실패 시) |

### idle 유니버스 옵션 (v5.0 신규)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--diagnose-stability N` | `50` | 새 idle PC 없이 N회 연속이면 수렴 완료. SWD에서 긴 주기 인터럽트가 있으면 크게 설정 |
| `--diagnose-max N` | `1000` | idle 유니버스 수집 최대 샘플 수 (상한) |

### NVMe 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--nvme PATH` | `/dev/nvme0` | NVMe 디바이스 경로 |
| `--namespace N` | `1` | NVMe 네임스페이스 번호 |
| *(없음)* | — | 기본 안전 명령어: `Identify`, `GetLogPage`, `GetFeatures`, `Read`, `Write` |
| `--commands A B` | — | 명령어 명시 선택 |
| `--all-commands` | — | 파괴적 명령어 포함 전체 활성화 |
| `--fw-bin PATH` | `FW_BIN_FILENAME` 기반 자동 | 펌웨어 바이너리 경로. 기본값은 코드 상단 `FW_BIN_FILENAME`에서 결정 |
| `--fw-xfer BYTES` | `32768` | FWDownload 청크 크기 |
| `--fw-slot N` | `1` | FWCommit 슬롯 번호 |

### 타임아웃 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--timeout GROUP MS` | — | 그룹별 timeout 설정. 예: `--timeout command 8000` |
| `--passthru-timeout MS` | `2592000000` (30일) | nvme-cli `--timeout`. 크게 설정 = 커널 reset 방지 |
| `--kernel-timeout SEC` | `2592000` (30일) | nvme_core `admin/io_timeout`. 퍼저 시작 시 `/sys/module/nvme_core/parameters/`에 기록 |

### 샘플링 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--samples N` | `500` | 명령어 1회당 최대 PC 샘플 수 |
| `--saturation-limit N` | `10` | idle 유니버스 내 PC 연속 N회 → 조기종료 (0=비활성화) |
| `--global-saturation-limit N` | `20` | 새 global PC 없이 N회 연속 → 조기종료 |
| `--interval US` | `20000` | 샘플 간격 (µs). 0은 NVMe 타임아웃 유발 (CPU 실행 시간 부족). 5ms 미만 → 컨트롤러 불안정. 여전히 타임아웃 시 50000으로 올리세요. |
| `--post-cmd-delay MS` | `0` | 명령 완료 후 tail 샘플링 시간 |

### Mutation / Power Schedule 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--random-gen-ratio R` | `0.2` | 완전 랜덤 입력 비율 |
| `--opcode-mut-prob P` | `0.10` | Opcode 무작위 교체 확률 |
| `--nsid-mut-prob P` | `0.10` | NSID 교체 확률 |
| `--admin-swap-prob P` | `0.05` | Admin↔IO 교차 전송 확률 |
| `--datalen-mut-prob P` | `0.08` | data_len 불일치 확률 |
| `--exclude-opcodes HEX` | `''` | 퍼징 제외 opcode (쉼표 구분) |
| `--max-energy F` | `16.0` | Power Schedule 최대 에너지 |

### Calibration / Deterministic / MOpt 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--calibration-runs N` | `3` | 초기 시드당 calibration 반복 횟수 |
| `--no-deterministic` | — | Deterministic stage 비활성화 |
| `--no-mopt` | — | MOpt mutation scheduling 비활성화 |

### 기타

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--output DIR` | `./output/...` | 결과 저장 디렉터리 |
| `--runtime SEC` | `604800` | 총 퍼징 시간 |
| `--seed-dir DIR` | `None` | 이전 corpus 로드 |
| `--resume-coverage FILE` | `None` | 이전 coverage.txt (커버리지 이어받기) |
| `--addr-start HEX` | `0x00000000` | 펌웨어 .text 시작 |
| `--addr-end HEX` | `0x00147FFF` | 펌웨어 .text 끝 |

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

#### Admin

| 이름 | Opcode | 주의 |
|------|--------|------|
| `SetFeatures` | `0x09` | FID 16종 시드 |
| `FWDownload` | `0x11` | `FW_BIN_FILENAME` 설정 권장 |
| `FWCommit` | `0x10` | CA 7종 시드, 재부팅 유발 가능 |
| `FormatNVM` | `0x80` | ⚠️ 미디어 초기화, SES 3종 시드 |
| `Sanitize` | `0x84` | ⚠️ 전체 데이터 소거 |
| `TelemetryHostInitiated` | `0x02` | Create=0/1 시드 |
| `DeviceSelfTest` | `0x14` | STC 6종 시드, 즉시 반환 |
| `SecuritySend` | `0x81` | TCG/OPAL/IEEE1667, SECP 7종 시드 |
| `SecurityReceive` | `0x82` | TCG/OPAL/IEEE1667, SECP 7종 시드 |
| `GetLBAStatus` | `0x86` | ATYPE 3종 시드 |

#### IO

| 이름 | Opcode | 주의 |
|------|--------|------|
| `Flush` | `0x00` | |
| `DatasetManagement` | `0x09` | TRIM/Deallocate, 7종 시드 |
| `WriteZeroes` | `0x08` | DMA 없음, DEAC/FUA 시드 포함 |
| `Compare` | `0x05` | 비교 불일치 시 에러 반환 |
| `WriteUncorrectable` | `0x04` | 에러 주입 (LBA uncorrectable 마킹) |
| `Verify` | `0x0C` | CRC/PI 검증, PRINFO 시드 포함 |

---

## 출력 디렉터리 구조

```
output/pc_sampling_v5.0/
├── fuzzer_YYYYMMDD_HHMMSS.log
├── coverage.txt
├── corpus/
│   ├── seed_0000.bin
│   └── ...
├── crashes/
│   ├── crash_<md5>.json
│   ├── crash_<md5>.bin
│   └── crash_<md5>.dmesg.txt
├── cfg/
│   └── cfg_<cmd>.dot
└── heatmap_<timestamp>.png
```

---

## 크래시 발생 후 처리

퍼저는 크래시(timeout) 감지 즉시 NVMe 드라이버를 unbind해 SSD 상태를 보존합니다.

```bash
# 1. 크래시 확인
ls ./output/pc_sampling_v5.0/crashes/
cat ./output/pc_sampling_v5.0/crashes/crash_<md5>.json

# 2. JTAG/SWD로 펌웨어 분석
(gdb) monitor halt
(gdb) info registers pc

# 3. 분석 완료 후 드라이버 재바인드
lspci | grep -i nvme
echo '0000:02:00.0' | sudo tee /sys/bus/pci/drivers/nvme/bind

# 4. SSD가 복귀 안 할 경우 GDB로 강제 리셋
(gdb) monitor reset run
```

> **주의**: nvme-cli ctrl reset으로는 CPU 하드웨어 리셋이 되지 않습니다.
> `monitor reset run` (GDB/JTAG)이 필요합니다.

---

## 새 SSD 제품 포팅 절차

### 1단계: PC 레지스터 인덱스 확인

```bash
python3 jlink_reg_diag.py --device <CPU명> --interface auto
```

TEST 1에서 `<-- PC (auto-detect)` 표시된 index 번호 확인.
표시가 없으면 TEST 4 전체에서 펌웨어 주소 범위 안의 값을 가진 index를 찾아서 `--pc-reg-index N`으로 지정.

### 2단계: idle 유니버스 수렴 확인

```bash
# 퍼저 시작 후 diagnose 로그 확인
sudo python3 pc_sampling_fuzzer_v5.0.py --device <CPU명> ... 2>&1 | grep Diagnose
```

출력 예:
```
[Diagnose] idle 유니버스 수렴 완료: 23개 PC, 347회 샘플 (새 PC 없이 50회 연속)
[Diagnose] idle_pcs = 23개 (범위 내), 대표 PC = 0x5dd4
```

`idle_pcs`가 구성되면 idle 감지 자동 활성화.

### 3단계: 주소 범위 설정

Ghidra로 펌웨어 .text 섹션 범위 확인 후:
```bash
--addr-start 0x00000000 --addr-end 0x00147FFF
```

### 4단계: seed_replay_test.sh 검증

```bash
sudo ./seed_replay_test.sh /dev/nvme0 FW.bin 32768 1
```

모든 시드가 rc=0으로 통과하는지 확인.

---

## seed_replay_test.sh

퍼저 초기 시드를 실제 NVMe 명령어로 실행해 동작을 검증하는 스크립트.

```bash
./seed_replay_test.sh /dev/nvme0 [FW.bin] [fw_xfer] [fw_slot]
```

| # | 명령어 | 설명 |
|---|--------|------|
| 0 | Identify (Namespace) | CNS=0x00 |
| 1 | Identify (Controller) | CNS=0x01 NSID=0 |
| 2 | GetLogPage Error | LID=0x01 NSID=0 |
| 3 | GetLogPage SMART | LID=0x02 NSID=0 |
| 4 | GetLogPage FW Slot | LID=0x03 |
| 5~11 | GetFeatures (FID=1~7) | |
| 12 | Read LBA 0 (1 block) | |
| 13 | Read LBA 0 FUA | CDW12[29]=1 |
| 14 | Read LBA 0 (256 blocks) | 128KB |
| 15 | Write LBA 0 (1 block) | |
| 16 | Write LBA 0 FUA | CDW12[29]=1 |
| 17 | Write LBA 0 (256 blocks) | 128KB |
| 18 | TelemetryHostInitiated | LID=0x07 NSID=0 |
| 19 | SetFeatures (VWC) | FID=0x06 |
| 20 | FormatNVM (SES=0) | 비파괴 |
| 21 | FWDownload | `nvme fw-download -f FW.bin -x 32768` |
| 22 | FWCommit | `nvme fw-commit -s 1 -a 1` |
| 23 | DatasetManagement | TRIM (AD=1) |
| 24 | Flush | |

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v5.0 (latest)** | `_go_with_retry()`: `JLINKARM_Go()` 반환값 체크 + 재시도 (SWD NVMe DMA 중 클럭 게이팅으로 인한 Go() 실패 복구) — `_read_pc()` / `_ensure_running()` 모두 적용 |
| **v5.0** | `--interface auto/jtag/swd` (JTAG→SWD 자동 전환), `--pc-reg-index`, `diagnose()` 수렴 기반 idle 유니버스 수집, idle 유니버스 기반 `_sampling_worker()`; `FW_BIN_FILENAME` user setting; NVMe 2.0 전체 명령어 확장 (WriteZeroes/Compare/WriteUncorrectable/Verify/DeviceSelfTest/SecuritySend/SecurityReceive/GetLBAStatus 추가); Identify CNS·GetLogPage LID·GetFeatures FID·SetFeatures·FWCommit CA·FormatNVM SES 시드 전면 확장; CDW12 PRINFO/LR/FUA·CDW13 DSPEC·CDW14 ILBRT·CDW15 LBAT/LBATM E2E 보호 시드 추가; **`SAMPLE_INTERVAL_US` 기본값 0→20000µs** (0 사용 시 NVMe 커맨드 타임아웃 발생 확인) <br>**BugFix**: JTAG auto halt 후 CPU resume 누락 → `jlink.go()` 추가; `_go_func` raw DLL → `jlink.go()`; `diagnose()` None 샘플 수렴 미반영; calibration RC_TIMEOUT crash 처리 없음; resume DLL `JLINKARM_GoEx(0,0)` → `JLINKARM_Go()` (GoEx에서 퍼저 오동작 확인) |
| **v4.7** | FUA 비트 수정 (CDW12[14]→[29]), 컨트롤러 범위 NSID=0, Sanitize 제거, `--fw-bin/--fw-xfer/--fw-slot`, critical 버그 2건 수정 |
| **v4.6** | io-passthru → namespace device, passthru timeout 분리, 크래시 시 nvme 드라이버 unbind |
| **v4.5** | Calibration, Deterministic stage, MOpt mutation scheduling |
| **v4.4** | Opcode→name 역방향 테이블, Heatmap 크기 제한, dmesg 캡처 |
| **v4.3** | Corpus culling, J-Link heartbeat, 랜덤 생성 비율, 확장 mutation 확률 |
| **v4.2** | subprocess + 샘플링 연동, 글로벌 기준 포화 판정, idle PC 감지 |
| **v4.1** | CDW2~CDW15 시드 필드, NVMe 스펙 기반 초기 시드 자동 생성 |
| **v4.0** | unique PC 기반 coverage signal, CFG/히트맵, AFLfast Power Schedule |
