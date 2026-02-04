# PC Sampling Fuzzer v3 - 개발 노트

SSD 펌웨어 대상 Coverage-Guided Fuzzer. J-Link V9의 Halt-Sample-Resume 방식으로 Cortex-R8 CPU의 PC를 수집하고, NVMe CLI를 통해 퍼징 입력을 전달한다.

## 환경

- **Target**: Cortex-R8 기반 SSD 컨트롤러
- **Debugger**: J-Link V9 (JTAG, 12MHz)
- **Host**: Ubuntu 20.04 (WSL2)
- **Python**: pylink-square

## 해결한 문제들

### 1. PC 값이 항상 0x27200으로 고정

**증상**: JLinkExe에서 halt하면 `PC: (R15) = 0x5DD4`인데, 스크립트에서는 항상 `0x27200`.

**원인 1 - `jlink.restart()`가 CPU를 리셋함**:
`_read_pc()`에서 halt → read → `restart()` 순서로 호출했는데, `restart()`는 단순 resume가 아니라 CPU를 리셋 벡터부터 재시작시킨다. 매 샘플마다 CPU가 리셋되어 부트 시퀀스의 동일 지점(0x27200)에서 잡혔다.

**원인 2 - `register_read(15)`가 R15(PC)가 아님**:
Cortex-R8에서 J-Link의 레지스터 인덱스는 ARM 레지스터 번호와 일치하지 않는다. `register_list()` + `register_name()`으로 확인한 결과, R15(PC)의 실제 인덱스는 **9**였다. index 15는 다른 레지스터.

**원인 3 - `jlink.go()`가 존재하지 않음**:
pylink 버전에 `go()` 메서드가 없어서 `AttributeError` 발생. J-Link SDK DLL을 직접 호출해야 한다.

**수정**:
```python
# Before (잘못된 코드)
self.jlink.halt()
pc = self.jlink.register_read(15)    # 잘못된 인덱스
self.jlink.restart()                  # CPU 리셋됨

# After (수정된 코드)
self.jlink.halt()
pc = self.jlink.register_read(self._pc_reg_index)  # index 9
self.jlink._dll.JLINKARM_Go()                      # 리셋 없이 resume
```

**진단 도구**: `jlink_reg_diag.py` — 레지스터 매핑, halt 상태, resume 방법을 테스트하는 스크립트.

### 2. 불필요한 지연 제거

| 지연 | 원래 값 | 의도 | 실제 | 수정 |
|------|---------|------|------|------|
| `time.sleep(0.01)` (NVMe 전송 전) | 10ms | 샘플링 스레드 구동 대기 | 스레드 start는 즉시. `_read_pc()` 자체가 ~1ms | 제거 |
| `post_cmd_delay_ms` | 5ms | 커맨드 후 추가 샘플링 | `stop_sampling()` 이후에 sleep하므로 샘플링이 안 됨 | 0으로 변경 |

### 3. 샘플링 포화 감지 및 조기 종료

**문제**: `MAX_SAMPLES_PER_RUN=500`인데, 실측 결과 `last_new_at < 5`. 나머지 495회는 idle loop 중복.

**해결**: 연속 N회(`SATURATION_LIMIT=30`) 새 unique PC가 없으면 조기 종료.

```
exec=1 cmd=Identify raw_samples=34 ... last_new_at=3 stop=saturated (no new PC for 30 consecutive samples)
  saturation: {10: 3, 25: 3}
```

- 빠른 커맨드: ~33회에서 자동 종료 (기존 500회 대비 15배 빠름)
- 느린 커맨드: 새 PC가 계속 나오면 500회 상한까지 계속 샘플링
- `SATURATION_LIMIT=0`으로 비활성화 가능

## 출력 구조

```
./output/pc_sampling_v2/
├── fuzzer_20260204_153000.log    # 실행마다 새 로그 파일 (날짜시간)
├── fuzzer_20260204_160000.log
└── crashes/                      # 크래시/타임아웃 입력만 저장
    ├── crash_Identify_0x6_a1b2c3d4e5f6
    └── crash_Identify_0x6_a1b2c3d4e5f6.json
```

- 로그 파일: DEBUG (파일) + INFO (콘솔). 10회 실행마다 flush.
- coverage/stats 별도 파일 없음: Fuzzing Complete 서머리에서 로그로 출력.

## 설정 파라미터

| 파라미터 | 기본값 | 설명 |
|----------|--------|------|
| `FW_ADDR_START/END` | `0x0` - `0x147FFF` | 펌웨어 .text 영역. 범위 밖 PC는 필터링 |
| `JLINK_DEVICE` | `Cortex-R8` | J-Link 타겟 디바이스 |
| `JLINK_SPEED` | `12000` | JTAG 속도 (kHz) |
| `MAX_SAMPLES_PER_RUN` | `500` | 1회 실행당 최대 PC 샘플 수 (상한) |
| `SATURATION_LIMIT` | `30` | 연속 N회 새 PC 없으면 조기 종료 |
| `SAMPLE_INTERVAL_US` | `0` | 샘플 간 대기 (0 = 최대 속도) |
| `TOTAL_RUNTIME_SEC` | `3600` | 총 퍼징 시간 (초) |

## 실행

```bash
# 기본 실행
sudo python3 pc_sampling_fuzzer_v3.py

# 특정 커맨드만
sudo python3 pc_sampling_fuzzer_v3.py --commands Identify GetFeatures

# 주소 범위 지정
sudo python3 pc_sampling_fuzzer_v3.py --addr-start 0x1000 --addr-end 0x50000
```

## 남은 병목

| 병목 | 원인 | 개선 방향 |
|------|------|-----------|
| `_read_pc()` USB RTT | halt+read+resume = 3회 USB 트랜잭션 (~1-2ms/샘플) | J-Link V9 하드웨어 한계. J-Link Pro/Ultra+ 또는 ETM trace 필요 |
| `subprocess.Popen` | 매 실행마다 nvme CLI 프로세스 fork | python-nvme 또는 ctypes ioctl로 직접 호출 |

## 파일 목록

| 파일 | 설명 |
|------|------|
| `pc_sampling_fuzzer_v3.py` | 메인 퍼저 |
| `jlink_reg_diag.py` | J-Link 레지스터 읽기 진단 스크립트 |
| `fuzzer_v3.md` | 이 문서 |
