# PC Sampling SSD Firmware Fuzzer v5.4

J-Link Halt-Sample-Resume 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v5.4에서는 **SetFeatures 기본 명령 승격**, **LBA 크기 자동 감지**, **버그 수정 4종**, **calibration 가시성 개선**, **APST 재활성화 버그 수정** 등이 추가되었습니다.

---

## 목차

1. 요구사항
2. 빠른 시작
3. v5.4 변경사항 상세
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
J-Link V9 (JTAG/SWD)
```

실행 권한:
```bash
sudo python3 pc_sampling_fuzzer_v5.4.py [옵션]
```

---

## 빠른 시작

### 기본 실행

```bash
sudo python3 pc_sampling_fuzzer_v5.4.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x003B7FFF \
  --output ./output/run_base
```

### LBA 크기 수동 지정 (자동 감지 실패 시)

```bash
sudo python3 pc_sampling_fuzzer_v5.4.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --lba-size 4096 \
  --output ./output/run_4k
```

### 특정 명령어 제외

```bash
sudo python3 pc_sampling_fuzzer_v5.4.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --exclude-opcodes 0x0C,0x05 \
  --output ./output/run_excl
```

### Power Combo 활성화

```bash
sudo python3 pc_sampling_fuzzer_v5.4.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --pm \
  --output ./output/run_pm
```

---

## v5.4 변경사항 상세

### [Fix] APST/KeepAlive calibration 후 재비활성화 (속도 1/5 버그)

**증상:** v5.4 초기 버전에서 exec/s가 이전 대비 약 1/5로 저하됨.

**원인:**
1. preflight에서 `_apst_disable()` 호출 → APST OFF
2. calibration 중 `Set APST: 1s→PS3, 10s→PS4` 시드가 `nsid_override=0`으로 정상 실행(rc=0) → **APST 재활성화**
3. 이전 버전에서는 해당 시드가 NSID=1로 전송되어 rc=15(Feature Not Namespace Specific)로 실패했으나, SetFeatures NSID 수정 이후 실제로 적용됨
4. main loop 진입 시 APST 활성 상태 → sampling thread가 ~1초 실행되는 동안 NVMe 컨트롤러가 PS3 진입 → 다음 명령에 wake-up latency 추가

**수정:** calibration 완료 직후 `_apst_disable()` / `_keepalive_disable()` 재호출.

```
preflight   → _apst_disable()       ← 원래 있던 호출
calibration → SetFeatures APST 시드  ← APST 재활성화 (문제)
calibration 완료 → _apst_disable()  ← 재비활성화 (수정)
main loop   → APST OFF 상태 유지
```

---

### [Fix] SetFeatures 시드 NSID 수정 (rc=15 해결)

컨트롤러 범위(controller-scoped) FID에 `nsid_override=0` 적용. NSID=1로 전송 시 펌웨어가 rc=15(Feature Not Namespace Specific)로 거부하던 문제 수정.

| FID | 기능 | 수정 전 NSID | 수정 후 NSID |
|-----|------|------------|------------|
| 0x01 | Arbitration | 1 | 0 |
| 0x02 | Power Management | 1 | 0 |
| 0x04 | Temperature Threshold | 1 | 0 |
| 0x06~0x12 (0x05 제외) | APST, HMB, KeepAlive 등 | 1 | 0 |

FID=0x05 (Error Recovery)는 namespace-scoped이므로 NSID=1 유지.

---

### [Feature] SetFeatures 기본 명령 승격 + I/O 가중치

**SetFeatures가 `NVME_COMMANDS_DEFAULT`에 추가됨** (이전: `--all-commands` 또는 `--commands`로만 활성화).

기본 명령 구성:

| 명령 | 타입 | weight |
|------|------|--------|
| Identify | Admin | 1 |
| GetLogPage | Admin | 1 |
| GetFeatures | Admin | 1 |
| SetFeatures | Admin | 1 |
| Read | IO | 2 |
| Write | IO | 2 |

I/O 명령(Read, Write)에 `weight=2` 적용 → Admin 4개 : I/O 2개×2 = 1:1 비율.

---

### [Feature] SetFeatures 시드 확장

새로 추가된 SetFeatures 시드:

| FID | 설명 | 시드 수 |
|-----|------|--------|
| 0x0C APST | disabled / enabled(ITP=0) / 1s→PS3·10s→PS4 | 3 |
| 0x0D HMB | disabled / MR=1 | 2 |
| 0x0F Keep Alive Timer | 0(disabled) / 5000ms / max(error) | 3 |
| 0x11 Non-Op PS Config | NOPPME=0 / NOPPME=1 | 2 |
| 0x12 Read Recovery | Level 0 / Level 15 | 2 |
| 0x02 Power State | PS1 / PS2 / PS3 추가 (PS0/PS4는 기존) | 3 |

---

### [Feature] LBA 크기 자동 감지

시작 시 `blockdev --getss /dev/nvme0n1`으로 LBA 크기를 자동 감지.

```
[Pre-flight] LBA size 자동 감지: 4096B
```

- Read/Write/Compare 시드의 data_len 계산에 반영: `(nlb+1) × lba_size`
- 512B 고정이던 하드코딩 제거 → 4096B LBA 장치에서 rc=129 오류 해소
- `--lba-size N` 옵션으로 수동 지정 가능 (0=자동)
- Write 시드 data가 data_len보다 짧으면 0 패딩

---

### [Feature] Calibration 진행 로그 ([Cal X/Y])

calibration 중 시드별 결과를 실시간으로 출력:

```
[Cal  1/47] Read                 cdw10=0x00000000  stab= 94%  pcs= 1823  rc=0
[Cal  2/47] Write                cdw10=0x00000000  stab= 91%  pcs= 2041  rc=0
[Cal  9/47] SetFeatures          cdw10=0x00000001  stab= 87%  pcs=  512  rc=0
[Cal 12/47] SetFeatures          cdw10=0x0000000f  stab=  0%  pcs=    0  rc=15 ← FAIL
```

calibration 완료 시 요약 한 줄 출력:
```
[Calibration] Done — Seeds: 47  |  Global PCs: 12453  |  Avg stability: 88.3%
```

---

### [Feature] FWDownload 1 exec 처리

`--fw-bin` 사용 시 전체 청크를 하나의 exec으로 통합.

- 이전: 청크 수만큼 corpus seed 생성 → 각각 개별 exec으로 카운트
- 이후: corpus에 대표 seed 1개만 추가 → main loop에서 전체 청크 순서대로 전송 → exec +1
- 청크 중 TIMEOUT/ERROR 발생 시 즉시 중단

---

### [Feature] --exclude-opcodes calibration 적용

`--exclude-opcodes 0xOO,...` 로 지정한 opcode가 calibration 단계에서도 제외됨.

- 이전: mutation 단계에서만 적용
- 이후: `_generate_default_seeds()` 및 `_load_seeds()`에서도 필터링

동작하지 않는 명령어(rc≠0 고정)를 미리 제외하여 calibration 시간 단축.

---

### [Fix] BUG-1: window-ratio idle saturation 구현

v5.3 changelog에 명시되었으나 실제 코드에 미구현 상태였던 window-ratio 조기 종료 구현.

- `_recent_idle_count` running count로 O(1) 유지 (sum() 반복 호출 제거)
- 정수 임계값 `_idle_win_thresh = int(IDLE_WINDOW_SIZE × IDLE_RATIO_THRESH) = 24` 사전 계산
- 조건: 최근 30샘플 중 24개(80%) 이상이 idle → `idle_saturated` 조기 종료

---

### [Fix] BUG-2: stop_sampling() join timeout 경고

```python
def stop_sampling(self) -> int:
    ...
    self.sample_thread.join(timeout=2.0)
    if self.sample_thread.is_alive():
        log.warning("[Sampler] stop_sampling() 2.0s join timeout — thread still alive")
```

J-Link 응답 지연으로 join이 타임아웃될 경우 로그로 즉시 가시화.

---

### [Fix] BUG-3: Deterministic stage CDW 0 필드 skip 완화

```python
# 이전: 0이면 모든 CDW 필드 skip
if original == 0:
    continue

# 이후: cdw13~cdw15만 skip (cdw10/11/12는 0이어도 탐색)
if original == 0 and field_name in ('cdw13', 'cdw14', 'cdw15'):
    continue
```

Read LBA=0(`cdw10=0`), 1-block(`cdw12=0`) 시드의 deterministic 변형이 누락되던 문제 수정.

---

### [Fix] BUG-4: SetFeatures PS1/PS2/PS3 시드 추가

```python
dict(cdw10=0x02, cdw11=0x00000001, description="Set Power State 1"),
dict(cdw10=0x02, cdw11=0x00000002, description="Set Power State 2"),
dict(cdw10=0x02, cdw11=0x00000003, description="Set Power State 3 (NOPS)"),
```

이전: PS0, PS4만 존재. 중간 PS(1/2/3)의 전력 전이 루틴 미탐색.

---

### [Fix] FormatNVM / Sanitize 시드 최소화

파괴적 동작을 유발하는 시드 제거.

**FormatNVM** (7개 → 1개):
- 제거: SES=1(user data erase), SES=2(cryptographic erase), LBAF=1/2, PI 변형
- 유지: `cdw10=0x0000` (LBAF=0, SES=0 — 포맷 코드 경로 탐색, 미디어 소거 없음)

**Sanitize** (0개 → 1개):
- 추가: `cdw10=0x04` SANACT=4 (Exit Failure Mode — sanitize failure 상태 해제, 비파괴)
- 미추가: SANACT=1/2/3 (Block Erase / Overwrite / Crypto Erase — 즉시 전체 소거)

---

### [Refactor] Calibration 결과 테이블 제거

[Cal X/Y] 진행 로그가 있으므로 별도 Results 테이블 불필요. 완료 요약 한 줄로 대체.

---

### [Config] FW_ADDR_END, JLINK_SPEED 기본값 수정

| 상수 | v5.3 | v5.4 |
|------|------|------|
| `FW_ADDR_END` | `0x00147FFF` | `0x003B7FFF` |
| `JLINK_SPEED` | `4000` | `4000` |

> JLINK_SPEED를 12000으로 올리면 PCIe NVMe 명령 타임아웃이 증가하는 현상이 관찰됨.
> SWD 클럭이 빠를수록 레벨시프터/신호 무결성 문제 → NVMe DMA 간섭 가능성.
> USB 레이턴시(~2ms)가 샘플링 속도를 지배하므로 4000kHz에서도 샘플링 품질 차이 없음.

---

## 코드 상단 상수 설정

| 상수 | 기본값 | v5.3 대비 | 설명 |
|------|--------|-----------|------|
| `FW_ADDR_START` | `0x00000000` | — | 펌웨어 .text 시작 주소 |
| `FW_ADDR_END` | `0x003B7FFF` | ↑ 0x00147FFF | 펌웨어 .text 끝 주소 |
| `JLINK_DEVICE` | `'Cortex-R8'` | — | J-Link 타깃 |
| `JLINK_SPEED` | `4000` | — | JTAG 속도 (kHz) |
| `L1_SETTLE` | `0.05` | — | PCIe L1 settle (초) |
| `L1_2_SETTLE` | `0.05` | — | PCIe L1.2 추가 settle (초) |
| `IDLE_WINDOW_SIZE` | `30` | — | window-ratio 윈도우 크기 |
| `IDLE_RATIO_THRESH` | `0.80` | — | idle 비율 임계값 |
| `SATURATION_LIMIT` | `10` | — | 연속 idle 카운터 임계값 |
| `GLOBAL_SATURATION_LIMIT` | `20` | — | 연속 알려진 PC 임계값 |
| `MAX_SAMPLES_PER_RUN` | `500` | — | 실행당 최대 샘플 수 |
| `CALIBRATION_RUNS` | `3` | — | 시드당 calibration 반복 횟수 |
| `DETERMINISTIC_ENABLED` | `True` | — | deterministic stage 활성화 |
| `EXCLUDED_OPCODES` | `[]` | — | 제외할 opcode 목록 (코드 내 직접 지정) |
| `FW_BIN_FILENAME` | `None` | — | FWDownload용 펌웨어 파일명 |

---

## CLI 옵션

### v5.4 신규 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--lba-size N` | `0` | NVMe LBA 크기(바이트). 0=자동 감지(blockdev --getss) |
| `--exclude-opcodes A,B,...` | — | 제외할 opcode (hex 또는 dec). calibration/mutation 모두 적용 |

### 기존 주요 옵션 (v5.3 이전)

```
--device DEVICE          J-Link 타깃 디바이스 (기본: Cortex-R8)
--nvme DEVICE            NVMe 장치 경로 (기본: /dev/nvme0)
--namespace N            NVMe 네임스페이스 ID (기본: 1)
--addr-start HEX         펌웨어 .text 시작 주소
--addr-end HEX           펌웨어 .text 끝 주소
--output DIR             출력 디렉터리
--runtime SEC            퍼징 총 실행 시간 (기본: 604800 = 1주)
--pm                     Power Combo 활성화 (NVMe PS + PCIe L/D-state)
--interface auto|jtag|swd  J-Link 인터페이스 (기본: auto)
--pc-reg-index N         PC 레지스터 인덱스 수동 지정
--samples N              실행당 최대 샘플 수 (기본: 500)
--interval US            샘플 간격 µs (기본: 0 = 최대 밀도)
--go-settle MS           Go() 후 CPU 최소 실행 보장 ms (기본: 0)
--saturation-limit N     연속 idle 카운터 임계값 (기본: 10)
--global-saturation-limit N  연속 알려진 PC 임계값 (기본: 20)
--diagnose-sleep-ms MS   diagnose() 샘플 간격 ms (기본: 10)
--diagnose-stability N   idle 수렴 연속 횟수 (기본: 50)
--diagnose-max N         최대 샘플 수 (기본: 2000)
--calibration-runs N     시드당 calibration 반복 횟수 (기본: 3)
--no-det                 deterministic stage 비활성화
--no-mopt                MOpt mutation scheduling 비활성화
--fw-bin PATH            FWDownload용 펌웨어 바이너리 경로
--fw-xfer BYTES          FWDownload 청크 크기 (기본: 32768)
--fw-slot N              FWCommit 슬롯 번호 (기본: 1)
--timeout GROUP MS       명령 그룹별 타임아웃 설정 (예: command 18000)
--passthru-timeout MS    nvme-cli --timeout 값 (기본: 30일)
--kernel-timeout SEC     nvme_core 모듈 타임아웃 (기본: 30일)
--seed-dir DIR           초기 시드 디렉터리
--resume-coverage FILE   이전 coverage.txt 경로
--commands CMD ...       활성화할 명령어 목록
--all-commands           위험 명령어 포함 전체 활성화
--l1-settle SEC          PCIe L1 settle 대기 (기본: 0.05)
--l1-2-settle SEC        PCIe L1.2 추가 settle 대기 (기본: 0.05)
--idle-window-size N     window-ratio 윈도우 크기 (기본: 30)
--idle-ratio-thresh F    idle 비율 임계값 (기본: 0.80)
--ps-settle-cap SEC      PS settle 상한 (기본: 1.0)
--bb-addrs FILE          Ghidra basic_blocks.txt 경로 (자동 탐지)
--func-addrs FILE        Ghidra functions.txt 경로 (자동 탐지)
```

---

## Power Combo 동작 원리

`--pm` 활성화 시 30개 조합(PS0~4 × L0/L1/L1.2 × D0/D3hot) 랜덤 전환.

- `PM_ROTATE_INTERVAL`(기본 100)회 exec마다 combo 전환
- Non-Operational 상태(PS3/4, D3hot) 진입 시 NVMe 명령 전 강제 복귀
- PM coverage는 global_coverage에만 반영 (corpus 오염 방지)
- preflight: 30개 combo 모두 검증 (~21초)

v5.4에서 달라진 점:
- calibration 후 APST 재비활성화로 자율 PS 전환 간섭 제거

---

## 명령어 목록

### 기본 명령어 (`NVME_COMMANDS_DEFAULT`)

| 명령 | Opcode | 비고 |
|------|--------|------|
| Identify | 0x06 | — |
| GetLogPage | 0x02 | — |
| GetFeatures | 0x0A | — |
| SetFeatures | 0x09 | **v5.4 신규 (기본 승격)** |
| Read | 0x02 (IO) | weight=2 |
| Write | 0x01 (IO) | weight=2 |

### 확장 명령어 (`--all-commands` 또는 `--commands`로 활성화)

FWDownload, FWCommit, FormatNVM\*, Sanitize\*, TelemetryHostInitiated, Flush,
DatasetManagement, WriteZeroes, Compare, WriteUncorrectable, Verify,
DeviceSelfTest, SecuritySend, SecurityReceive, GetLBAStatus

\* FormatNVM: SES=0(비파괴) 1개만. Sanitize: SANACT=4(Exit Failure) 1개만.

---

## 출력 디렉터리 구조

```
output/pc_sampling_v5.4/
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

1. stuck PC 읽기 (J-Link)
2. dmesg 캡처
3. FAIL CMD 상세 출력 (cmd/opcode/nsid/cdw2~15/data/mutations)
4. crash 파일 저장 (.bin / .json / .dmesg.txt)
5. replay .sh 자동 생성 (setpci 포함, sudo bash로 즉시 재현 가능)
6. UFAS 펌웨어 덤프 (`./ufas` 존재 시)
7. NVMe 드라이버 unbind (`/sys/bus/pci/drivers/nvme/unbind`)

재연결:
```bash
echo '<BDF>' > /sys/bus/pci/drivers/nvme/bind
```

---

## 정적 분석 커버리지 연동

퍼저와 같은 디렉터리에 `basic_blocks.txt` / `functions.txt` (Ghidra `ghidra_export.py` 생성)를 두면 자동 로드.

```
[StatCov] BB: 12.3% (4567/37120) | funcs: 234/1820 (12.9%)
```

그래프 3종 자동 생성:
- `coverage_growth.png` : BB_cov% / funcs_cov% 성장 곡선
- `firmware_map.png` : 함수 공간 전체 맵 (커버=초록 / 미커버=회색)
- `uncovered_funcs.png` : 미커버 함수 Top-30 막대 차트

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| v5.4 | **SetFeatures 기본 승격**, **APST calibration 재활성화 버그 수정(1/5 속도 저하)**, SetFeatures NSID 수정(rc=15), LBA 자동 감지, calibration [Cal] 진행 로그, FWDownload 1-exec, --exclude-opcodes calibration 적용, BUG-1~4 수정(window-ratio/stop_sampling/det-stage/PS시드), FormatNVM/Sanitize 시드 최소화, FW_ADDR_END=0x003B7FFF |
| v5.3 | **idle 시간 최적화**: L1_SETTLE 5.0→0.05s, L1_2_SETTLE 2.0→0.05s, DIAGNOSE_SAMPLE_MS=10ms, DIAGNOSE_STABILITY 100→50, DIAGNOSE_MAX 5000→2000, idle window-ratio 조기 감지, PS settle cap=1.0s, preflight settle 단축 |
| v5.2 | Power Combo (NVMe PS + PCIe L/D-state 30개 조합), APST/Keep-Alive 자동 비활성화, replay .sh에 setpci 포함 |
| v5.1 | PM Rotation(`--pm`), Basic Block 커버리지(Ghidra), 시각화 그래프 3종, FAIL CMD 상세 출력, replay .sh 자동 생성, UFAS 덤프 |
| v5.0 | J-Link JTAG/SWD auto-detect, diagnose() 수렴 기반 idle 유니버스 수집 |
| v4.7 | FUA 비트 수정(CDW12[29]), 컨트롤러 범위 명령 NSID=0, `--fw-bin` |
| v4.6 | passthru timeout 분리, crash 시 nvme driver unbind |
| v4.5 | Calibration, Deterministic stage, MOpt mutation scheduling |
