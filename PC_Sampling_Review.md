# PC Sampling 기반 SSD 펌웨어 퍼징 - 기술 검토

## 1. 원본 코드의 핵심 문제점

### 문제 1: `cpu_get_reg(15)`는 CPU를 멈춥니다

```python
# 원본 코드 (작동 안 함)
pc = self.jlink.cpu_get_reg(15)  # ❌ CPU halt 필요
```

**pylink 라이브러리의 `cpu_get_reg()`는 내부적으로 CPU를 halt한 후 레지스터를 읽습니다.**

이것은 기획서의 "비침습적(Non-intrusive)" 목표와 완전히 상반됩니다.

### 문제 2: J-Link V9의 기술적 한계

| 기능 | J-Link V9 | J-Link Pro/Ultra+ | J-Trace |
|------|-----------|-------------------|---------|
| JTAG 연결 | ⭕ | ⭕ | ⭕ |
| Halt-Resume | ⭕ | ⭕ | ⭕ |
| SWO Trace | ❌ | ⭕ | ⭕ |
| ETM Trace | ❌ | ❌ | ⭕ |
| Non-halt PC Read | ❌ | ❌ | ⭕ (ETM) |
| PC Sampling (하드웨어) | ❌ | △ | ⭕ |

**결론: J-Link V9로는 완전한 Non-intrusive PC Sampling이 불가능합니다.**

---

## 2. 가능한 접근 방식

### 방식 A: Halt-Sample-Resume (수정된 코드)

```
CPU 실행 중 → 짧게 Halt → PC 읽기 → 즉시 Resume → 반복
              (수 us)
```

**장점:**
- J-Link V9에서 작동
- 추가 하드웨어 불필요

**단점:**
- 완전한 Non-intrusive가 아님
- 샘플링 간격이 길면 커버리지 정확도 저하
- 샘플링 간격이 짧으면 성능 저하 (CPU가 자주 멈춤)

**NVMe 타임아웃 위험:**
```
NVMe 타임아웃: 보통 500ms ~ 5000ms
샘플링 1회: ~10us halt + ~100us 간격
100 샘플: ~10ms (타임아웃보다 훨씬 짧음) → 안전할 수 있음
```

### 방식 B: GDB 기반 샘플링

```
JLinkGDBServer ← GDB ← Python Script
                       (interrupt, read $pc, continue)
```

**장점:**
- pylink보다 안정적
- 에러 처리가 더 좋음

**단점:**
- 오버헤드가 더 큼 (IPC 비용)
- Halt 시간이 더 길 수 있음

### 방식 C: Periodic Interrupt 방식 (펌웨어 수정 필요)

```
펌웨어에 타이머 인터럽트 추가 → 현재 PC를 버퍼에 기록 → Host가 버퍼 읽기
```

**장점:**
- 가장 정확한 커버리지
- Non-intrusive (정상 실행 흐름)

**단점:**
- 펌웨어 수정 필요 (보통 불가능)
- NVMe 인터럽트와 충돌 가능

---

## 3. 수정된 코드 설명

### 핵심 변경사항

```python
def _read_pc_halt_resume(self) -> Optional[int]:
    """Halt-Read-Resume 방식"""
    with self.lock:
        # 1. Halt
        self.jlink.halt()

        # 2. PC 읽기
        pc = self.jlink.register_read(15)

        # 3. Resume
        self.jlink.restart()

        return pc
```

### 샘플링 간격 설정

```python
@dataclass
class FuzzConfig:
    sample_interval_us: int = 100  # 샘플 간격 (마이크로초)
    max_samples_per_run: int = 1000  # 한 실행당 최대 샘플
```

- **간격이 짧을수록**: 커버리지 정확도 ↑, 성능 ↓, 타임아웃 위험 ↑
- **간격이 길수록**: 커버리지 정확도 ↓, 성능 ↑, 타임아웃 위험 ↓

**권장 시작값:**
- `sample_interval_us = 100` (100us)
- `max_samples_per_run = 500`
- NVMe timeout = 5000ms

---

## 4. 추가로 필요한 구현

### A. J-Link 재연결 로직

SSD가 리셋되거나 JTAG 노이즈가 발생하면 J-Link 연결이 끊어질 수 있습니다.

```python
def reconnect(self, max_retries: int = 5) -> bool:
    for i in range(max_retries):
        print(f"[J-Link] Reconnection attempt {i+1}/{max_retries}")
        time.sleep(2)
        if self.connect():
            return True
    return False
```

### B. NVMe 에러 코드 해석

```python
def _parse_nvme_status(self, returncode: int) -> str:
    """NVMe 에러 코드 해석"""
    status_codes = {
        0: "Success",
        1: "Invalid Command Opcode",
        2: "Invalid Field in Command",
        4: "Data Transfer Error",
        5: "Aborted due to Power Loss",
        6: "Internal Error",
        # ... 더 많은 코드
    }
    return status_codes.get(returncode, f"Unknown ({returncode})")
```

### C. 커버리지 데이터 영속화

```python
def save_coverage(self, filepath: str):
    """커버리지를 파일로 저장 (세션 간 유지)"""
    with open(filepath, 'w') as f:
        for pc in sorted(self.global_coverage):
            f.write(f"{hex(pc)}\n")

def load_coverage(self, filepath: str):
    """이전 커버리지 로드"""
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                self.global_coverage.add(int(line.strip(), 16))
```

### D. 주소 범위 필터링 (중요)

펌웨어 코드 영역만 커버리지로 인정하면 노이즈가 줄어듭니다.

```python
# Ghidra에서 펌웨어 코드 영역 확인 후 설정
config = FuzzConfig(
    addr_range_start=0x00010000,  # .text 섹션 시작
    addr_range_end=0x00100000,    # .text 섹션 끝
)
```

---

## 5. 실행 방법

### 필수 패키지 설치

```bash
# pylink 설치
pip install pylink-square

# nvme-cli 설치
sudo apt install nvme-cli

# J-Link 소프트웨어 설치 (Segger 홈페이지)
# https://www.segger.com/downloads/jlink/
```

### 실행

```bash
# 기본 실행
python pc_sampling_fuzzer.py

# 옵션 지정
python pc_sampling_fuzzer.py \
    --device Cortex-R8 \
    --nvme /dev/nvme0 \
    --opcode 0xC0 \
    --speed 4000 \
    --runtime 3600 \
    --output ./output/ssd_fuzz/

# 주소 범위 필터링 (Ghidra에서 확인한 코드 영역)
python pc_sampling_fuzzer.py \
    --addr-start 0x00010000 \
    --addr-end 0x00100000
```

---

## 6. 예상 결과 및 한계

### 기대 효과

| 항목 | GDBFuzz (브레이크포인트) | PC Sampling |
|------|------------------------|-------------|
| NVMe 타임아웃 | 자주 발생 (Halt가 김) | 가끔 발생 (Halt가 짧음) |
| 커버리지 정확도 | 높음 (정확한 BB 추적) | 낮음 (샘플링 기반) |
| 설정 복잡도 | 높음 (Ghidra CFG 필요) | 낮음 (바로 실행 가능) |
| 속도 | 느림 | 중간 |

### 한계점

1. **커버리지가 확률적**: 샘플링 간격 동안 실행된 코드를 놓칠 수 있음
2. **짧은 함수 누락**: 샘플링 간격보다 빨리 실행되는 함수는 감지 불가
3. **J-Link V9 불안정**: 장시간 퍼징 시 연결 끊김 가능
4. **NVMe 타임아웃**: 샘플링 빈도가 높으면 발생 가능

### 현실적 기대

```
PC Sampling은 "대략적인 커버리지 피드백"을 제공합니다.
정확한 basic block 레벨 커버리지가 아니라,
"이 입력이 새로운 코드 영역을 실행했을 가능성이 높다" 정도의 지표입니다.

그래도 완전 블랙박스 퍼징보다는 훨씬 효과적입니다.
```

---

## 7. 더 나은 대안 (장비 구매 시)

### Option 1: J-Trace + ETM (권장)

- **가격**: ~$1,000+
- **장점**: 완전한 Non-intrusive 트레이스
- **단점**: Cortex-R8이 ETM을 지원하는지 확인 필요

### Option 2: ARM DSTREAM + CoreSight

- **가격**: ~$3,000+
- **장점**: 가장 정확한 트레이스
- **단점**: 비쌈, 복잡한 설정

### Option 3: SSD 벤더 협조

- 디버그 빌드 펌웨어 요청 (심볼 포함)
- 커버리지 인스트루멘테이션 포함 버전 요청

---

## 8. 권장 진행 순서

```
[1] 수정된 코드로 테스트 실행 (짧은 시간)
    → NVMe 타임아웃 발생 여부 확인
    │
    ├─ 타임아웃 발생 → sample_interval_us 늘리기 (200, 500, 1000...)
    │
    └─ 타임아웃 없음 → [2]로 진행

[2] 커버리지 수집 확인
    → 새로운 PC가 발견되는지 확인
    │
    ├─ 발견됨 → 정상 작동, 장시간 퍼징 진행
    │
    └─ 안 발견됨 → 주소 필터 확인, J-Link 연결 상태 확인

[3] 장시간 퍼징 (1시간+)
    → 크래시/행 발견 여부 확인
```

---

## 9. 요약

| 항목 | 원본 코드 | 수정된 코드 |
|------|----------|------------|
| CPU Halt | 필수 (cpu_get_reg) | 최소화 (Halt-Resume) |
| 실현 가능성 | ❌ 불가능 | ⭕ 가능 (J-Link V9) |
| Non-intrusive | ❌ | △ (짧은 halt) |
| 에러 처리 | 기본 | 재연결, 타임아웃 처리 |
| 커버리지 저장 | 메모리만 | 파일 영속화 |
| NVMe 통합 | 없음 | nvme-cli 사용 |

**핵심 메시지:**
> J-Link V9로 완전한 Non-intrusive PC Sampling은 불가능합니다.
> 하지만 "빠른 Halt-Resume" 방식으로 NVMe 타임아웃을 피하면서
> 커버리지 기반 퍼징을 수행할 수 있습니다.
