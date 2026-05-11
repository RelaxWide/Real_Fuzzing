# PC Sampling SSD Firmware Fuzzer v5.6

J-Link Halt-Sample-Resume 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v5.6에서는 **시각화 산출물 전면 개선** — coverage_growth 이중 X축, command_comparison RC 오류율 추가, uncovered_funcs 부분 커버 구분, 1D 히트맵 컬러바, mutation_chart 신규 차트, 주기적 그래프 자동 갱신.

---

## 목차

1. 요구사항
2. 빠른 시작
3. v5.6 변경사항 상세
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

## v5.6 변경사항 상세

### [Viz] coverage_growth.png — wall-clock time 이중 X축

기존 X축(executions) 위에 **elapsed time(분/시간) 상단 축**을 추가.

- `_sa_cov_history`의 `elapsed_s` 필드를 선형 보간하여 눈금 생성
- 총 경과 시간이 1시간 미만이면 분(min), 이상이면 시간(hr) 단위 자동 선택
- 실행 속도 변화(예: Power Combo 전환으로 인한 속도 저하)를 시각적으로 파악 가능

---

### [Viz] command_comparison.png — RC 오류율 4번째 subplot 추가

3-panel → **4-panel** (edges / PCs / executions / **RC error rate %**).

- 각 명령어의 `rc_stats` 에서 `rc != 0` 비율을 계산
- 막대 색상: 오류율 0% = 초록, 50%+ = 빨강 (RGB 그라디언트)
- `RC_TIMEOUT` / `RC_ERROR`(내부 에러)는 rc_stats에 포함되지 않으므로 NVMe 프로토콜 오류만 반영

---

### [Viz] uncovered_funcs.png — 부분 커버 함수 구분

미커버 Top-25(빨강) + 부분 커버 Top-25(주황) 혼합 차트.

| 분류 | 조건 | 색상 |
|------|------|------|
| Not entered | 함수 entry가 `_sa_entered_funcs`에 없음 | 빨강 `#e05a5a` |
| Partial coverage | 진입됨 + BB 커버율 < 100% | 주황 `#e09a30` |

- BB 데이터 없이 `functions.txt`만 있는 경우: 진입된 함수를 모두 Partial로 표시
- 막대 레이블에 BB 커버율 `[xx% BB]` 표시
- 구분선으로 두 카테고리 시각 분리

---

### [Viz] coverage_heatmap_1d.png — 컬러바 추가

각 히트맵 strip에 **개별 컬러바** 추가 → 절대적 PC hit 수 값 해석 가능.

- 컬러바 레이블: "PC hits/bin"
- 제목에 bin 크기(bytes)와 환산 instruction 수(`bin_size / 4`) 명시
- 행 높이 1.4인치로 증가 (strip 가독성 향상)

---

### [Viz] mutation_chart.png — 신규 차트

`graphs/mutation_chart.png`에 3-panel 차트 자동 생성.

| Panel | 내용 |
|-------|------|
| 1 | MOpt operator 효율 (`finds/uses` ratio), 효율 내림차순, RdYlGn 색상 |
| 2 | MOpt operator 사용 횟수 vs 발견 횟수 (log scale 이중 막대) |
| 3 | 입력 소스 분포(corpus_mutated / random_gen) + mutation 유형(opcode/nsid/swap/datalen) |

---

### [Viz] 주기적 그래프 갱신

메인 루프에서 `GRAPH_REFRESH_INTERVAL`(기본 5000) 실행마다 차트 자동 갱신.

- 갱신 대상: `command_comparison`, `coverage_growth`, 히트맵, `mutation_chart`
- 갱신 제외: graphviz CFG(`.dot`/`.png`) — 렌더링 비용이 크므로 종료 시에만 실행
- 갱신 실패 시 WARNING 로그만 출력하고 퍼징 계속

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `GRAPH_REFRESH_INTERVAL` | `5000` | 주기 갱신 간격 (executions 단위) |

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
| `GRAPH_REFRESH_INTERVAL` | `5000` | 주기 그래프 갱신 간격 (executions 단위) |

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
output/pc_sampling_v5.6/
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
    ├── command_comparison.png    ← 4종 subplot (edges/PCs/traces/RC오류율)
    ├── mutation_chart.png        ← MOpt 효율 + 입력 소스 분포  [신규]
    ├── coverage_heatmap_1d.png   ← 1D 커버리지 히트맵 (컬러바 포함)
    ├── edge_heatmap_2d.png       ← 2D edge 히트맵
    ├── {cmd}_cfg.dot/.png        ← 명령어별 CFG
    ├── coverage_growth.png       (* Ghidra 연동 시, 이중 X축)
    ├── firmware_map.png          (* Ghidra 연동 시)
    └── uncovered_funcs.png       (* Ghidra 연동 시, 부분 커버 구분)
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

그래프 3종 자동 생성 (v5.6 개선):
- `coverage_growth.png` : BB_cov% / funcs_cov% 성장 곡선 + **상단 wall-clock time 이중 X축**
- `firmware_map.png` : 함수 공간 전체 맵 (커버=초록 / 미커버=회색)
- `uncovered_funcs.png` : **미커버(빨강) + 부분 커버(주황, BB 커버율 표시)** 함수 Top-25 × 2

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| v5.6 | **시각화 개선**: coverage_growth 이중 X축(wall-clock), command_comparison RC 오류율 4번째 subplot, uncovered_funcs 부분커버 구분, 1D 히트맵 컬러바, mutation_chart 신규, 주기적 갱신(GRAPH_REFRESH_INTERVAL=5000) |
| v5.5 | **시드 템플릿 분리(nvme_seeds.py)**, **CLI 인자 정리**(saturation-limit/l1-settle/idle-window/ps-settle-cap/mut-prob/no-det/no-mopt 제거 → 상수 고정), **FWDownload 32KB 기본값** |
| v5.4 | **SetFeatures 기본 승격**, **APST calibration 재활성화 버그 수정(1/5 속도 저하)**, SetFeatures NSID 수정(rc=15), LBA 자동 감지, calibration [Cal] 진행 로그, FWDownload 1-exec, --exclude-opcodes calibration 적용, BUG-1~4 수정, FormatNVM/Sanitize 시드 최소화 |
| v5.3 | **idle 시간 최적화**: L1_SETTLE 5.0→0.05s, L1_2_SETTLE 2.0→0.05s, DIAGNOSE_SAMPLE_MS=10ms, idle window-ratio 조기 감지, PS settle cap=1.0s, preflight settle 단축 |
| v5.2 | Power Combo (NVMe PS + PCIe L/D-state 30개 조합), APST/Keep-Alive 자동 비활성화, replay .sh에 setpci 포함 |
| v5.1 | PM Rotation(`--pm`), Basic Block 커버리지(Ghidra), 시각화 그래프 3종, FAIL CMD 상세 출력, replay .sh 자동 생성, UFAS 덤프 |
| v5.0 | J-Link JTAG/SWD auto-detect, diagnose() 수렴 기반 idle 유니버스 수집 |
| v4.7 | FUA 비트 수정(CDW12[29]), 컨트롤러 범위 명령 NSID=0, `--fw-bin` |
| v4.6 | passthru timeout 분리, crash 시 nvme driver unbind |
| v4.5 | Calibration, Deterministic stage, MOpt mutation scheduling |
