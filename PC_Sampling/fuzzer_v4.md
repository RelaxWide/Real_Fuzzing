# PC Sampling Fuzzer v4 - Release Notes

SSD 펌웨어 대상 Coverage-Guided Fuzzer. J-Link V9의 Halt-Sample-Resume 방식으로 Cortex-R8 CPU의 PC를 수집하고, NVMe CLI를 통해 퍼징 입력을 전달한다.

## v4 변경사항

### 1. Sampled Edge 커버리지

v3.1까지는 unique PC(주소)만 수집했다. v4에서는 **(prev_pc, cur_pc) 튜플**을 edge로 저장한다.

**장점**:
- 같은 PC라도 **어디서 왔는지** 구분 가능
- caller context 정보 추가
- 더 세밀한 경로 구분

**제약**:
- 정확한 CFG edge가 아닌 "샘플링된 연속 PC 쌍"
- 샘플링 간격으로 인해 중간 PC 누락 가능

```python
# v3.1: unique PC만
self.global_coverage: Set[int] = set()

# v4: (prev, cur) edge 튜플
self.global_edges: Set[Tuple[int, int]] = set()
```

### 2. Power Schedule (AFLfast explore)

v3.1의 `random.choice(corpus)` 대신, **에너지 기반 가중치 선택**을 사용한다.

**AFLfast 연구 결과**:
- AFL 대비 7배 빠른 취약점 발견
- 24시간 내 AFL이 못 찾은 CVE 3개 추가 발견

**알고리즘**:
```
energy(seed) = min(MAX_ENERGY, 2^(log2(total_execs / exec_count(seed))))
```

- 적게 실행된 시드 → 높은 에너지 → 더 자주 선택
- 새 시드 → 최대 에너지 (16.0)

```python
# v3.1
base_data, cmd = random.choice(self.corpus)

# v4
seed = self._select_seed()  # 에너지 기반 가중치 선택
```

### 3. Seed 데이터 구조

시드별 메타데이터를 추적한다.

```python
@dataclass
class Seed:
    data: bytes
    cmd: NVMeCommand
    exec_count: int = 0     # 선택된 횟수
    found_at: int = 0       # 발견 시점
    new_edges: int = 0      # 발견한 새 edge 수
    energy: float = 1.0     # 계산된 에너지
```

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                        NVMeFuzzer v4                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Corpus     │  │   Mutator    │  │   Power Schedule     │  │
│  │ (Seed 리스트) │  │ (변이 생성)   │  │  (에너지 기반 선택)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│         └────────┬────────┴──────────────────────┘              │
│                  ▼                                              │
│  ┌───────────────────────────────┐                              │
│  │      _send_nvme_command()     │                              │
│  │  (nvme CLI → SSD 펌웨어)       │                              │
│  └───────────────┬───────────────┘                              │
└──────────────────│──────────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                     JLinkPCSampler v4                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Halt → Read PC → Resume (DLL 직접 호출)                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ global_edges │  │current_edges │  │   prev_pc (연속성)    │  │
│  │ (누적 edge)   │  │ (현재 실행)   │  │                      │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 출력 구조

```
./output/pc_sampling_v4/
├── fuzzer_20260206_120000.log   # 실행마다 새 로그 파일
├── fuzzer_20260206_130000.log
└── crashes/                     # 크래시/타임아웃 입력
    ├── crash_Identify_0x6_a1b2c3d4e5f6
    └── crash_Identify_0x6_a1b2c3d4e5f6.json
```

## 설정 파라미터

| 파라미터 | 기본값 | 설명 |
|----------|--------|------|
| `FW_ADDR_START/END` | `0x0` - `0x147FFF` | 펌웨어 .text 영역 |
| `JLINK_DEVICE` | `Cortex-R8` | J-Link 타겟 디바이스 |
| `JLINK_SPEED` | `12000` | JTAG 속도 (kHz) |
| `MAX_SAMPLES_PER_RUN` | `500` | 1회 실행당 최대 샘플 수 |
| `SATURATION_LIMIT` | `10` | 연속 N회 새 edge 없으면 조기 종료 |
| `SAMPLE_INTERVAL_US` | `0` | 샘플 간 대기 (0 = 최대 속도) |
| `TOTAL_RUNTIME_SEC` | `3600` | 총 퍼징 시간 (초) |
| `MAX_ENERGY` | `16.0` | [v4] Power Schedule 최대 에너지 |

## CLI 옵션

```bash
# 전체 옵션 확인
python3 pc_sampling_fuzzer_v4.py --help

# 기본 실행
sudo python3 pc_sampling_fuzzer_v4.py

# 특정 커맨드만 퍼징
sudo python3 pc_sampling_fuzzer_v4.py --commands Identify GetFeatures Read

# 주소 범위 지정
sudo python3 pc_sampling_fuzzer_v4.py --addr-start 0x1000 --addr-end 0x50000

# Power Schedule 에너지 조정
sudo python3 pc_sampling_fuzzer_v4.py --max-energy 32.0

# 장시간 퍼징 (2시간)
sudo python3 pc_sampling_fuzzer_v4.py --runtime 7200
```

## 로그 출력 변경

v4에서는 edge 정보가 추가로 출력된다:

```
exec=100 cmd=Identify raw_samples=14 edges=12 out_of_range=2 new_edges=3
         global_edges=156 global_pcs=89 last_new_at=5 stop=saturated
```

| 필드 | 설명 |
|------|------|
| `edges` | 이번 실행에서 수집된 unique edge 수 |
| `new_edges` | 이번 실행에서 새로 발견된 edge 수 |
| `global_edges` | 전체 누적 edge 수 |
| `global_pcs` | 전체 누적 PC 수 (비교용) |

## v3.1 → v4 마이그레이션

1. `pc_sampling_fuzzer_v3.1.py` 대신 `pc_sampling_fuzzer_v4.py` 사용
2. 출력 디렉토리: `./output/pc_sampling_v3.1/` → `./output/pc_sampling_v4/`
3. 새 CLI 옵션: `--max-energy` (Power Schedule 조정)
4. `--save-interval` 옵션 제거 (v3.1 전용)

## 파일 목록

| 파일 | 설명 |
|------|------|
| `pc_sampling_fuzzer_v4.py` | [v4] 메인 퍼저 (Sampled Edge + Power Schedule) |
| `pc_sampling_fuzzer_v3.1.py` | [v3.1] 이전 버전 (커버리지 자동 저장) |
| `pc_sampling_fuzzer_v3.py` | [v3.0] 레거시 버전 |
| `jlink_reg_diag.py` | J-Link 레지스터 읽기 진단 스크립트 |
| `fuzzer_v4.md` | 이 문서 |
| `fuzzer_v3.1.md` | v3.1 문서 |
| `fuzzer_v3.md` | v3 개발 노트 |

## 알려진 제한사항

| 제한 | 원인 | 개선 방향 |
|------|------|-----------|
| Sampled Edge ≠ CFG Edge | 샘플링 간격으로 중간 PC 누락 | ETM trace 또는 더 빠른 J-Link |
| 확률적 커버리지 | 샘플링 기반 | 구조적 한계, 개선 불가 |
| USB RTT 병목 | J-Link V9 = USB Full-Speed | J-Link Pro/Ultra+ (USB Hi-Speed) |
| subprocess 오버헤드 | nvme CLI 프로세스 fork | python-nvme ioctl 직접 호출 |

## 참고 자료

- [AFLfast Paper (TSE'18)](https://mboehme.github.io/paper/TSE18.pdf)
- [AFL++ Power Schedules](https://aflplus.plus/docs/power_schedules/)
- [Edge Coverage 연구 (USENIX'19)](https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf)
