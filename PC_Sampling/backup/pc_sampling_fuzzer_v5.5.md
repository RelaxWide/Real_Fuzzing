# PC Sampling SSD Firmware Fuzzer v5.5

J-Link Halt-Sample-Resume 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v5.5에서는 **시드 템플릿 분리(nvme_seeds.py)**, **불필요 CLI 인자 정리**, **FWDownload 기본 청크 크기 32KB 수정** 등 코드 구조 리팩토링이 이루어졌습니다.

---

## 목차

1. 요구사항
2. 빠른 시작
3. v5.5 변경사항 상세
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
Python 3.8+
pylink-square       # pip install pylink-square
nvme-cli            # apt install nvme-cli
setpci              # apt install pciutils
J-Link V9 (JTAG/SWD)
```

실행 권한:
```bash
sudo python3 pc_sampling_fuzzer_v5.5.py [옵션]
```

파일 구성:
```
PC_Sampling/
├── pc_sampling_fuzzer_v5.5.py   # 메인 퍼저
└── nvme_seeds.py                # NVMe 명령 시드 템플릿
```

---

## 빠른 시작

### 기본 실행

```bash
sudo python3 pc_sampling_fuzzer_v5.5.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x003B7FFF \
  --output ./output/run_base
```

### LBA 크기 수동 지정 (자동 감지 실패 시)

```bash
sudo python3 pc_sampling_fuzzer_v5.5.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --lba-size 4096 \
  --output ./output/run_4k
```

### 특정 명령어 제외

```bash
sudo python3 pc_sampling_fuzzer_v5.5.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --exclude-opcodes 0x0C,0x05 \
  --output ./output/run_excl
```

### Power Combo 활성화

```bash
sudo python3 pc_sampling_fuzzer_v5.5.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --pm \
  --output ./output/run_pm
```

---

## v5.5 변경사항 상세

### [Refactor] 시드 템플릿 분리 (nvme_seeds.py)

기존 `_generate_default_seeds()` 내부의 `SEED_TEMPLATES` 딕셔너리(~500줄)를 별도 모듈 `nvme_seeds.py`로 추출.

- 메인 스크립트에서는 `from nvme_seeds import SEED_TEMPLATES as _DEFAULT_SEED_TEMPLATES`로 import
- 시드 수정·추가 시 `nvme_seeds.py`만 편집하면 되어 유지보수성 향상
- Python 3.8 호환 (타입 어노테이션 제거, `from __future__ import annotations` 불필요)

**nvme_seeds.py 구조:**
```
nvme_seeds.py
├── 모듈 상단 CDW 비트 상수 (_FUA, _LR, _PRACT, ...)
├── SEED_TEMPLATES dict
│   ├── "Identify": [...]
│   ├── "Read": [...]
│   ├── "Write": [...]
│   ├── "SetFeatures": [...]
│   ├── "FWDownload": [dict(cdw10=0x1FFF, cdw11=0, data=b'\x00'*32768)]
│   └── ...
```

---

### [Refactor] CLI 인자 제거 — 하드코딩 상수 대체

사용 빈도가 낮고 기본값 이외로 조정할 필요가 없는 인자들을 제거하고 스크립트 상단 상수로 고정.

| 제거된 CLI 인자 | 대체 상수 |
|----------------|-----------|
| `--saturation-limit N` | `SATURATION_LIMIT = 10` |
| `--global-saturation-limit N` | `GLOBAL_SATURATION_LIMIT = 20` |
| `--l1-settle SEC` | `L1_SETTLE = 0.05` |
| `--l1-2-settle SEC` | `L1_2_SETTLE = 0.05` |
| `--idle-window-size N` | `IDLE_WINDOW_SIZE = 30` |
| `--idle-ratio-thresh F` | `IDLE_RATIO_THRESH = 0.80` |
| `--ps-settle-cap SEC` | `PS_SETTLE_CAP_S = 1.0` |
| `--mut-prob ...` | MOpt 내부 `MUT_WEIGHTS` 상수 |
| `--max-energy N` | `MAX_ENERGY` 상수 |
| `--no-det` | 제거 (deterministic stage 상시 활성화) |
| `--no-mopt` | 제거 (MOpt scheduling 상시 활성화) |
| `--bb-addrs FILE` | 제거 (자동 탐지 유지) |
| `--func-addrs FILE` | 제거 (자동 탐지 유지) |

조정이 필요한 경우 스크립트 상단 상수 블록을 직접 수정.

---

### [Fix] FWDownload 기본 청크 크기 1KB → 32KB

`--fw-xfer` 기본값 및 더미 시드를 `--fw-bin` 미사용 시에도 32KB로 통일.

| 항목 | v5.4 | v5.5 |
|------|------|------|
| `--fw-xfer` 기본값 | 1024 | 32768 |
| 더미 시드 data 크기 | 1024B | 32768B |
| 더미 시드 NUMD (cdw10) | `0x00FF` | `0x1FFF` |

`NUMD = (bytes ÷ 4) - 1` → 32768B → `0x1FFF`

`nvme_seeds.py` FWDownload 항목도 동일하게 적용:
```python
"FWDownload": [
    dict(cdw10=0x1FFF, cdw11=0, data=b'\x00' * 32768),
],
```

---

## 코드 상단 상수 설정

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FW_ADDR_START` | `0x00000000` | 펌웨어 .text 시작 주소 |
| `FW_ADDR_END` | `0x003B7FFF` | 펌웨어 .text 끝 주소 |
| `JLINK_DEVICE` | `'Cortex-R8'` | J-Link 타깃 |
| `JLINK_SPEED` | `4000` | JTAG 속도 (kHz) |
| `L1_SETTLE` | `0.05` | PCIe L1 settle (초) |
| `L1_2_SETTLE` | `0.05` | PCIe L1.2 추가 settle (초) |
| `IDLE_WINDOW_SIZE` | `30` | window-ratio 윈도우 크기 |
| `IDLE_RATIO_THRESH` | `0.80` | idle 비율 임계값 |
| `SATURATION_LIMIT` | `10` | 연속 idle 카운터 임계값 |
| `GLOBAL_SATURATION_LIMIT` | `20` | 연속 알려진 PC 임계값 |
| `PS_SETTLE_CAP_S` | `1.0` | PS settle 상한 (초) |
| `MAX_SAMPLES_PER_RUN` | `500` | 실행당 최대 샘플 수 |
| `CALIBRATION_RUNS` | `3` | 시드당 calibration 반복 횟수 |
| `FW_BIN_FILENAME` | `None` | FWDownload용 펌웨어 파일명 |

값 변경 시 스크립트 상단 상수 블록을 직접 수정.

---

## CLI 옵션

```
--device DEVICE          J-Link 타깃 디바이스 (기본: Cortex-R8)
--nvme DEVICE            NVMe 장치 경로 (기본: /dev/nvme0)
--namespace N            NVMe 네임스페이스 ID (기본: 1)
--lba-size N             NVMe LBA 크기(바이트). 0=자동 감지(blockdev --getss) (기본: 0)
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
--diagnose-sleep-ms MS   diagnose() 샘플 간격 ms (기본: 10)
--diagnose-stability N   idle 수렴 연속 횟수 (기본: 50)
--diagnose-max N         최대 샘플 수 (기본: 2000)
--calibration-runs N     시드당 calibration 반복 횟수 (기본: 3)
--exclude-opcodes A,B,...  제외할 opcode (hex/dec). calibration/mutation 모두 적용
--random-gen-ratio F     랜덤 생성 비율 (기본: 0.1)
--admin-swap-prob F      admin↔IO 교체 확률 (기본: 0.05)
--fw-bin PATH            FWDownload용 펌웨어 바이너리 경로
--fw-xfer BYTES          FWDownload 청크 크기 (기본: 32768)
--fw-slot N              FWCommit 슬롯 번호 (기본: 1)
--passthru-timeout MS    nvme-cli --timeout 값 (기본: 30일)
--kernel-timeout SEC     nvme_core 모듈 타임아웃 (기본: 30일)
--timeout GROUP MS       명령 그룹별 타임아웃 설정 (예: command 18000)
--post-cmd-delay MS      명령 후 추가 대기 (기본: 0)
--seed-dir DIR           초기 시드 디렉터리
--resume-coverage FILE   이전 coverage.txt 경로
--commands CMD ...       활성화할 명령어 목록
--all-commands           위험 명령어 포함 전체 활성화
--speed KHZ              JTAG 속도 (기본: 4000)
```

> v5.4 대비 제거된 인자: `--saturation-limit`, `--global-saturation-limit`,
> `--l1-settle`, `--l1-2-settle`, `--idle-window-size`, `--idle-ratio-thresh`,
> `--ps-settle-cap`, `--no-det`, `--no-mopt`, `--bb-addrs`, `--func-addrs`
>
> 해당 값들은 스크립트 상단 상수로 직접 조정.

---

## Power Combo 동작 원리

`--pm` 활성화 시 30개 조합(PS0~4 × L0/L1/L1.2 × D0/D3hot) 랜덤 전환.

- `PM_ROTATE_INTERVAL`(기본 100)회 exec마다 combo 전환
- Non-Operational 상태(PS3/4, D3hot) 진입 시 NVMe 명령 전 강제 복귀
- PM coverage는 global_coverage에만 반영 (corpus 오염 방지)
- preflight: 30개 combo 모두 검증 (~21초)
- calibration 완료 후 APST 재비활성화로 자율 PS 전환 간섭 제거

---

## 명령어 목록

### 기본 명령어 (`NVME_COMMANDS_DEFAULT`)

| 명령 | Opcode | 비고 |
|------|--------|------|
| Identify | 0x06 | — |
| GetLogPage | 0x02 | — |
| GetFeatures | 0x0A | — |
| SetFeatures | 0x09 | weight=1 |
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
output/pc_sampling_v5.5/
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
| v5.5 | **시드 템플릿 분리(nvme_seeds.py)**, **CLI 인자 정리**(saturation-limit/l1-settle/idle-window/ps-settle-cap/mut-prob/no-det/no-mopt 제거 → 상수 고정), **FWDownload 32KB 기본값** |
| v5.4 | **SetFeatures 기본 승격**, **APST calibration 재활성화 버그 수정(1/5 속도 저하)**, SetFeatures NSID 수정(rc=15), LBA 자동 감지, calibration [Cal] 진행 로그, FWDownload 1-exec, --exclude-opcodes calibration 적용, BUG-1~4 수정, FormatNVM/Sanitize 시드 최소화 |
| v5.3 | **idle 시간 최적화**: L1_SETTLE 5.0→0.05s, L1_2_SETTLE 2.0→0.05s, DIAGNOSE_SAMPLE_MS=10ms, idle window-ratio 조기 감지, PS settle cap=1.0s, preflight settle 단축 |
| v5.2 | Power Combo (NVMe PS + PCIe L/D-state 30개 조합), APST/Keep-Alive 자동 비활성화, replay .sh에 setpci 포함 |
| v5.1 | PM Rotation(`--pm`), Basic Block 커버리지(Ghidra), 시각화 그래프 3종, FAIL CMD 상세 출력, replay .sh 자동 생성, UFAS 덤프 |
| v5.0 | J-Link JTAG/SWD auto-detect, diagnose() 수렴 기반 idle 유니버스 수집 |
| v4.7 | FUA 비트 수정(CDW12[29]), 컨트롤러 범위 명령 NSID=0, `--fw-bin` |
| v4.6 | passthru timeout 분리, crash 시 nvme driver unbind |
| v4.5 | Calibration, Deterministic stage, MOpt mutation scheduling |
