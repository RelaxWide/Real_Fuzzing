# PC Sampling Fuzzer v4.2 - Release Notes

SSD 펌웨어 대상 Coverage-Guided Fuzzer. J-Link V9의 Halt-Sample-Resume 방식으로 Cortex-R8 CPU의 PC를 수집하고, **ioctl 직접 호출**로 NVMe 퍼징 입력을 전달한다.

## v4.1 → v4.2 변경사항

### 1. subprocess → ioctl 직접 호출

v4.1까지는 매 실행마다 `subprocess.Popen("nvme admin-passthru ...")`로 프로세스를 생성했다. v4.2에서는 `fcntl.ioctl()`로 NVMe passthru 명령을 커널에 직접 전달한다.

**변경 전 (v4.1)**:
```python
process = subprocess.Popen(
    ['nvme', 'admin-passthru', '/dev/nvme0', '--opcode=0x06', ...],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)
stdout, stderr = process.communicate(timeout=...)
```

**변경 후 (v4.2)**:
```python
# NVMe 디바이스 fd를 한 번만 열어 유지
self._nvme_fd = os.open('/dev/nvme0', os.O_RDWR)

# struct nvme_passthru_cmd 직접 패킹
cmd_buf = struct.pack('BBH I I I Q Q I I I I I I I I I I',
    opcode, flags, rsvd1, nsid, cdw2, cdw3,
    metadata, data_addr, metadata_len, data_len,
    cdw10, cdw11, cdw12, cdw13, cdw14, cdw15,
    timeout_ms, result)

rc = fcntl.ioctl(self._nvme_fd, NVME_IOCTL_ADMIN_CMD, cmd_buf)
```

**성능 효과**:
- fork()/exec() 오버헤드 제거 (~3-10ms/회)
- 프로세스 생성/파이프 I/O/파일 쓰기 제거
- NVMe 디바이스 열기/닫기 1회로 감소

### 2. 글로벌 기준 포화 판정

v4.1의 포화 판정은 `current_edges` (이번 실행 내에서 처음 보는 edge)를 기준으로 했다. 이미 `global_edges`에 있는 edge를 다시 발견해도 "새로운" 것으로 카운트되어 **실제 커버리지 기여 없이 샘플링 시간을 낭비**했다.

v4.2에서는 `global_edges` 대비 새로운 edge가 있는지 확인한다.

```python
# v4.1: 로컬 기준 (이번 실행에서 처음 보면 "새로움")
cur_unique_edges = len(self.current_edges)
if cur_unique_edges > prev_unique_edges:
    since_last_new = 0

# v4.2: 글로벌 기준 (전체 세션에서 처음 보면 "새로움")
if edge not in global_edges_ref:
    since_last_global_new = 0
```

### 3. idle PC 감지 및 조기 중단

`diagnose()` 20회 PC 읽기에서 가장 빈도 높은 PC를 **idle PC**로 자동 감지한다 (30% 이상 빈도 시).

**조기 중단 조건 (OR)**:
| 조건 | 임계값 | 의미 |
|------|--------|------|
| 글로벌 새 edge 없음 | 연속 20회 | 전체 세션 기준 커버리지 포화 |
| idle PC 유지 | 연속 10회 (sat_limit) | SSD가 idle loop에 있음 |

둘 중 하나만 만족하면 해당 실행의 샘플링을 조기 중단한다.

```python
if since_last_global_new >= 20:
    break  # 글로벌 포화
if idle_pc is not None and consecutive_idle >= sat_limit:
    break  # idle 상태
```

### 4. prev_pc sentinel 값

v4.1에서 `prev_pc = 0`이었는데, `FW_ADDR_START = 0x00000000`이면 0이 유효 주소 범위 안에 있어 **가짜 edge `(0, 첫번째_실제_PC)`가 global_edges에 오염**되는 문제가 있었다.

v4.2에서는 `prev_pc = 0xFFFFFFFF` (sentinel)로 초기화하고, 첫 in-range PC에서는 edge를 생성하지 않는다.

### 5. Admin 명령어 응답 버퍼 지원

v4.1에서 `needs_data=False`인 Admin 명령어(Identify, GetLogPage, GetFeatures)에 데이터 버퍼를 제공하지 않아 **커널이 EINVAL을 반환하며 모든 Admin 명령이 실패**했다.

v4.2에서는 명령별 응답 크기를 지정한다:

| 명령어 | 응답 크기 |
|--------|-----------|
| Identify | 4096 B |
| GetLogPage | 4096 B |
| GetFeatures | 4096 B |
| Read (IO) | min((NLB+1)*512, 2MB) |

### 6. Read 명령 버퍼 크기 제한

CDW mutation이 `cdw12`를 `0xFFFFFFFF`로 설정하면 `(0xFFFFFFFF+1)*512 = 2TB` 버퍼 할당을 시도하여 MemoryError가 발생했다.

v4.2에서는:
- `cdw12 & 0xFFFF`로 NLB 필드만 추출 (NVMe 스펙: CDW12[15:0])
- `MAX_DATA_BUF = 2MB` 상한 적용

### 7. coverage/edge 저장 및 resume 지원

v4.1에서는 퍼징 종료 시 `coverage.txt`, `coverage_edges.txt`를 저장하지 않아 `--resume-coverage` 옵션이 동작하지 않았다.

v4.2에서는:
- 종료 시 `coverage.txt` (PC 목록) + `coverage_edges.txt` (edge 목록) 자동 저장
- resume 시 PC와 **edge 모두** 로드하여 글로벌 포화 판정이 정확하게 동작

```
output/pc_sampling_v4/
├── coverage.txt           # hex PC, 한 줄에 하나
├── coverage_edges.txt     # hex_prev,hex_cur 한 줄에 하나
├── corpus/
├── crashes/
├── graphs/
└── fuzzer_YYYYMMDD_HHMMSS.log
```

### 8. stop_sampling 이중 호출 제거

v4.1에서 `_send_nvme_command()` 내부와 메인 루프에서 `stop_sampling()`을 이중 호출하고 있었다. v4.2에서는 `_send_nvme_command()`에서 `start_sampling()`만 하고, `stop_sampling()`은 메인 루프에서만 호출한다.

### 9. `_read_pc()` CPU halt 복구 보장

v4.1에서 `_halt_func()` 성공 후 `_read_reg_func()` 예외 시 `_go_func()`가 호출되지 않아 **SSD CPU(Cortex-R8)가 halt 상태로 방치**되는 문제가 있었다. CPU가 halt되면 NVMe 명령 처리 불가 → 이후 모든 ioctl 타임아웃 → 퍼저 실질 데드락.

v4.2에서는 `finally` 블록으로 `_go_func()`를 **항상 호출**하여 CPU resume을 보장한다.

```python
# v4.1: halt 후 예외 시 CPU 영구 halt
def _read_pc(self):
    try:
        self._halt_func()
        pc = self._read_reg_func(self._pc_reg_index)
        self._go_func()       # ← 예외 시 실행 안 됨
        return pc
    except Exception:
        return None            # ← CPU halt 상태 방치

# v4.2: finally로 항상 resume 보장
def _read_pc(self):
    try:
        self._halt_func()
        pc = self._read_reg_func(self._pc_reg_index)
        return pc
    except Exception:
        return None
    finally:
        try:
            self._go_func()   # ← 성공/실패 무관하게 항상 실행
        except Exception:
            pass
```

### 10. 히트맵 시각화 (1D 커버리지 + 2D Edge)

기존 Graphviz DOT 그래프는 노드가 많아지면 가독성이 떨어지는 문제가 있었다. v4.2에서는 히트맵 기반 시각화를 추가한다.

**1D 커버리지 히트맵** (`coverage_heatmap_1d.png`):
- 펌웨어 주소 공간을 선형으로 펼쳐 bin별 히트 빈도를 색상으로 표현
- 전체 합산 + 명령어별 행으로 나열 → 한눈에 커버리지 분포 비교
- bin별 커버리지 비율(%) 표시

**2D Edge 히트맵** (`edge_heatmap_2d.png`):
- X축=prev_pc(출발), Y축=cur_pc(도착)의 인접 행렬
- 대각선 근처 = 순차 실행, 대각선에서 먼 점 = 분기/함수 호출
- 수평 밴드 = 공통 진입점, 수직 밴드 = 분기 지점
- 명령어별 subplot으로 비교
- log 스케일 색상 + inferno 컬러맵

---

## v4.0 → v4.1 변경사항 (요약)

- **Seed CDW 필드**: CDW2~CDW15를 Seed dataclass에 포함, mutation 대상
- **NVMe 스펙 기반 초기 시드**: Opcode별 정상 명령어 파라미터 26개 자동 생성
- **AFL++ mutation engine**: havoc(16종) + splice + CDW mutation
- **명령어별 CFG 시각화**: DOT/PNG 그래프 + matplotlib 비교 차트

---

## 설정 파라미터

```python
# 핵심 설정
FW_ADDR_START     = 0x00000000    # 펌웨어 .text 시작 주소
FW_ADDR_END       = 0x00147FFF    # 펌웨어 .text 끝 주소
JLINK_DEVICE      = 'Cortex-R8'
JLINK_SPEED       = 12000         # kHz
NVME_DEVICE       = '/dev/nvme0'
NVME_TIMEOUT      = 8000          # ms

# 샘플링
MAX_SAMPLES_PER_RUN = 500         # 실행당 최대 샘플 수
SATURATION_LIMIT    = 10          # idle PC 조기 중단 임계값
                                  # (글로벌 포화는 항상 20 고정)

# 퍼징
MAX_INPUT_LEN     = 4096          # 최대 입력 바이트
TOTAL_RUNTIME_SEC = 3600          # 총 실행 시간
MAX_ENERGY        = 16.0          # Power Schedule 최대 에너지
```

## 실행 방법

```bash
# 기본 실행 (모든 명령어)
sudo python3 pc_sampling_fuzzer_v4.2.py

# 특정 명령어만
sudo python3 pc_sampling_fuzzer_v4.2.py --commands Identify GetFeatures Write

# 이전 세션에서 재개
sudo python3 pc_sampling_fuzzer_v4.2.py --resume-coverage ./output/pc_sampling_v4/coverage.txt

# 주소 범위 지정
sudo python3 pc_sampling_fuzzer_v4.2.py --addr-start 0x20000 --addr-end 0x147FFF
```

## 의존성

- Python 3.8+
- `pylink-square`: J-Link Python 인터페이스
- `graphviz` (선택): DOT → PNG 렌더링 (`sudo apt install graphviz`)
- `matplotlib` + `numpy` (선택): 히트맵 및 비교 차트 (`pip install matplotlib numpy`)
- root 권한: `/dev/nvme0` ioctl 접근

## 출력 구조

```
output/pc_sampling_v4/
├── coverage.txt                  # 전체 PC 목록 (resume용)
├── coverage_edges.txt            # 전체 edge 목록 (resume용)
├── corpus/
│   ├── input_Identify_0x6_abc123
│   └── input_Identify_0x6_abc123.json   # CDW 메타데이터
├── crashes/
│   ├── crash_Write_0x1_def456
│   └── crash_Write_0x1_def456.json
├── graphs/
│   ├── coverage_heatmap_1d.png   # 1D 주소 커버리지 히트맵
│   ├── edge_heatmap_2d.png       # 2D edge 인접 행렬 히트맵
│   ├── Identify_cfg.dot          # Graphviz DOT
│   ├── Identify_cfg.png          # 렌더링된 CFG
│   ├── Identify_edges.json       # 원시 데이터
│   ├── summary.json
│   └── command_comparison.png    # 명령어 비교 차트
└── fuzzer_YYYYMMDD_HHMMSS.log
```
