# PC Sampling Fuzzer v3.1 - Release Notes

SSD 펌웨어 대상 Coverage-Guided Fuzzer. J-Link V9의 Halt-Sample-Resume 방식으로 Cortex-R8 CPU의 PC를 수집하고, NVMe CLI를 통해 퍼징 입력을 전달한다.

## v3.1 변경사항

### 1. 커버리지 자동 저장 기능 추가

이전 버전에서는 커버리지가 로그에만 출력되어 세션 종료 후 데이터를 잃었다. v3.1에서는:

- **주기적 저장**: `--save-interval` (기본 100회) 실행마다 자동 저장
- **종료 시 저장**: 정상 종료/Ctrl+C 모두 최종 상태 저장
- **저장 파일**:
  - `coverage.txt`: 발견된 모든 unique PC (hex 형식, 줄별)
  - `stats.json`: 전체 통계 (JSON)

```bash
# 50회마다 저장
sudo python3 pc_sampling_fuzzer_v3.1.py --save-interval 50
```

### 2. JSON 통계 파일

`stats.json` 예시:
```json
{
  "version": "3.1",
  "executions": 1000,
  "corpus_size": 45,
  "crashes": 2,
  "coverage_unique_pcs": 387,
  "total_samples": 15000,
  "interesting_inputs": 45,
  "elapsed_seconds": 120.5,
  "exec_per_sec": 8.3,
  "command_stats": {
    "Identify": {"exec": 200, "interesting": 10},
    "Read": {"exec": 300, "interesting": 15}
  },
  "rc_stats": {
    "Identify": {"0": 180, "1": 20},
    "Read": {"0": 295, "1": 5}
  }
}
```

### 3. 버전 표시 수정

로그 출력에서 버전이 정확히 표시됨:
```
============================================================
 PC Sampling SSD Fuzzer v3.1
============================================================
```

### 4. Resume 기능 개선

저장된 `coverage.txt`를 다음 세션에서 로드 가능:
```bash
# 이전 세션 커버리지 이어서 시작
sudo python3 pc_sampling_fuzzer_v3.1.py \
    --resume-coverage ./output/pc_sampling_v3.1/coverage.txt
```

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                        NVMeFuzzer                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Corpus     │  │   Mutator    │  │   Stats Collector    │  │
│  │ (입력 저장)   │  │ (변이 생성)   │  │  (coverage.txt,     │  │
│  │              │  │              │  │   stats.json)        │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│         └────────┬────────┘                      │              │
│                  ▼                               │              │
│  ┌───────────────────────────────┐              │              │
│  │      _send_nvme_command()     │◄─────────────┘              │
│  │  (nvme CLI → SSD 펌웨어)       │                             │
│  └───────────────┬───────────────┘                             │
└──────────────────│─────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                     JLinkPCSampler                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Halt → Read PC → Resume (DLL 직접 호출)                  │  │
│  │  • _halt_func()                                          │  │
│  │  • _read_reg_func(pc_reg_index)                          │  │
│  │  • _go_func()                                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ global_cov   │  │ current_trace│  │   save_coverage()    │  │
│  │ (누적 PC)     │  │ (현재 실행)   │  │  (파일 저장)          │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                    J-Link V9 (JTAG)                             │
│                         │                                       │
│                         ▼                                       │
│              ┌─────────────────────┐                           │
│              │   Cortex-R8 CPU     │                           │
│              │   (SSD Controller)  │                           │
│              └─────────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## 출력 구조

```
./output/pc_sampling_v3.1/
├── coverage.txt                 # [v3.1] 발견된 모든 unique PC (hex)
├── stats.json                   # [v3.1] JSON 형식 전체 통계
├── fuzzer_20260206_120000.log   # 실행마다 새 로그 파일
├── fuzzer_20260206_130000.log
└── crashes/                     # 크래시/타임아웃 입력
    ├── crash_Identify_0x6_a1b2c3d4e5f6
    └── crash_Identify_0x6_a1b2c3d4e5f6.json
```

## 설정 파라미터

| 파라미터 | 기본값 | 설명 |
|----------|--------|------|
| `FW_ADDR_START/END` | `0x0` - `0x147FFF` | 펌웨어 .text 영역. 범위 밖 PC는 필터링 |
| `JLINK_DEVICE` | `Cortex-R8` | J-Link 타겟 디바이스 |
| `JLINK_SPEED` | `12000` | JTAG 속도 (kHz) |
| `MAX_SAMPLES_PER_RUN` | `500` | 1회 실행당 최대 PC 샘플 수 (상한) |
| `SATURATION_LIMIT` | `10` | 연속 N회 새 PC 없으면 조기 종료 |
| `SAMPLE_INTERVAL_US` | `0` | 샘플 간 대기 (0 = 최대 속도) |
| `TOTAL_RUNTIME_SEC` | `3600` | 총 퍼징 시간 (초) |
| `SAVE_INTERVAL` | `100` | [v3.1] N회 실행마다 커버리지/통계 저장 |

## CLI 옵션

```bash
# 전체 옵션 확인
python3 pc_sampling_fuzzer_v3.1.py --help

# 기본 실행
sudo python3 pc_sampling_fuzzer_v3.1.py

# 특정 커맨드만 퍼징
sudo python3 pc_sampling_fuzzer_v3.1.py --commands Identify GetFeatures Read

# 주소 범위 지정
sudo python3 pc_sampling_fuzzer_v3.1.py --addr-start 0x1000 --addr-end 0x50000

# 이전 커버리지 이어서 시작
sudo python3 pc_sampling_fuzzer_v3.1.py \
    --resume-coverage ./output/pc_sampling_v3.1/coverage.txt

# 저장 주기 변경 (50회마다)
sudo python3 pc_sampling_fuzzer_v3.1.py --save-interval 50

# 장시간 퍼징 (2시간)
sudo python3 pc_sampling_fuzzer_v3.1.py --runtime 7200 --save-interval 200
```

## v3.0 → v3.1 마이그레이션

1. 기존 `pc_sampling_fuzzer_v3.py` 대신 `pc_sampling_fuzzer_v3.1.py` 사용
2. 출력 디렉토리가 `./output/pc_sampling_v3/` → `./output/pc_sampling_v3.1/`로 변경됨
3. 새로 추가된 `--save-interval` 옵션으로 저장 주기 조절 가능

## 파일 목록

| 파일 | 설명 |
|------|------|
| `pc_sampling_fuzzer_v3.1.py` | [v3.1] 메인 퍼저 (커버리지 자동 저장) |
| `pc_sampling_fuzzer_v3.py` | [v3.0] 이전 버전 |
| `pc_sampling_fuzzer_v2.py` | [v2.0] 레거시 버전 |
| `jlink_reg_diag.py` | J-Link 레지스터 읽기 진단 스크립트 |
| `sampling_density_test.py` | 샘플링 밀도 테스트 스크립트 |
| `fuzzer_v3.md` | v3 개발 노트 |
| `fuzzer_v3.1.md` | 이 문서 |

## 알려진 제한사항

| 제한 | 원인 | 개선 방향 |
|------|------|-----------|
| `_read_pc()` USB RTT | halt+read+resume = 3회 USB 트랜잭션 (~50-100ms/샘플). DLL 캐싱으로 wrapper 오버헤드는 제거했으나 USB Full-Speed 물리적 한계 | J-Link Pro/Ultra+ (USB Hi-Speed) 또는 ETM trace 필요 |
| `subprocess.Popen` | 매 실행마다 nvme CLI 프로세스 fork | python-nvme 또는 ctypes ioctl로 직접 호출 |
