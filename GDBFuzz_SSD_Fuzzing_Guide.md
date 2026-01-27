# GDBFuzz를 이용한 SSD 펌웨어 Fuzzing 가이드

## 개요

GDBFuzz는 하드웨어 브레이크포인트를 활용한 coverage-guided fuzzing 도구입니다.
이 가이드는 J-Link + JTAG 환경에서 SSD 펌웨어를 fuzzing하는 방법을 설명합니다.

---

## 동작 원리

```
┌─────────────────────────────────────────────────────────────┐
│                        Host PC                              │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐                 │
│  │ GDBFuzz │───▶│ Ghidra  │    │ Fuzzer  │                 │
│  │ (제어)   │    │ (분석)   │    │ (입력생성)│                │
│  └────┬────┘    └─────────┘    └────┬────┘                 │
│       │                              │                      │
│       ▼                              ▼                      │
│  ┌─────────┐                   ┌──────────┐                │
│  │   GDB   │                   │ NVMe CLI │                │
│  └────┬────┘                   └────┬─────┘                │
└───────┼─────────────────────────────┼──────────────────────┘
        │ JTAG (J-Link)               │ NVMe (PCIe)
        ▼                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      SSD Controller                         │
│                     (ARM Cortex-R8)                         │
│                                                             │
│   펌웨어 실행 ◀─────── NVMe 커맨드 수신                      │
│        │                                                    │
│        ▼                                                    │
│   [브레이크포인트] ──▶ GDB가 감지 ──▶ 새 코드 도달 확인       │
└─────────────────────────────────────────────────────────────┘
```

### Fuzzing 루프

```
① Fuzzer가 입력 데이터 생성 (mutation)
          ↓
② NVMe CLI로 SSD에 커맨드 전송
          ↓
③ SSD 펌웨어가 커맨드 처리 (코드 실행)
          ↓
④ 브레이크포인트 도달 시 → GDB가 감지 (J-Link 통해)
          ↓
⑤ 새로운 코드 영역 도달?
   → Yes: 입력을 corpus에 저장, 브레이크포인트 재배치
   → No: 다음 입력으로 진행
          ↓
⑥ ①번으로 반복
```

### 핵심 구성요소

| 구성요소 | 역할 |
|---------|------|
| **J-Link + GDB** | 실행 흐름 모니터링 (어디까지 실행됐나) |
| **NVMe CLI** | 실제 입력 전송 (fuzzing 데이터) |
| **Ghidra** | 브레이크포인트 위치 결정 (CFG 분석) |
| **Fuzzer** | 입력 생성/변형 (mutation) |

---

## 전체 준비 단계

```
[1] Entrypoint 함수 찾기 (동적 분석)
              ↓
[2] NVMe Connection 파일 작성
              ↓
[3] 설정 파일(.cfg) 작성
              ↓
[4] J-Link GDB Server 실행
              ↓
[5] Ghidra에서 Bridge 서버 실행
              ↓
[6] GDBFuzz 실행
```

---

## [1] Entrypoint 함수 찾기

### 왜 심볼이 없는가?

| 파일 형식 | 심볼 유무 |
|----------|----------|
| `.elf` (디버그 빌드) | 함수명, 변수명 있음 |
| `.bin` (릴리즈) | 심볼 없음 (`FUN_00012345` 형태) |

릴리즈용 펌웨어(.bin)는 심볼이 제거(stripped)되어 있어서 정적 분석만으로는 함수를 찾기 어렵습니다.

---

### 방법 A: 동적 분석으로 Entrypoint 찾기 (권장)

J-Link + GDB로 **실제 실행하면서** NVMe 커맨드 처리 함수를 찾습니다.

#### 준비물
- 터미널 3개
- J-Link 연결된 SSD
- NVMe CLI 설치됨

#### 단계별 진행

**[터미널 1] J-Link GDB Server 실행**
```bash
JLinkGDBServer -device Cortex-R8 -if JTAG -speed 4000
```
→ `Waiting for GDB connection...` 메시지 확인

**[터미널 2] GDB 연결**
```bash
gdb-multiarch

# GDB 프롬프트에서:
(gdb) target remote localhost:2331
(gdb) continue
```
→ SSD가 정상 실행 상태가 됨

**[터미널 3] NVMe 커맨드 전송**
```bash
# Identify 명령 (opcode 0x06)
sudo nvme admin-passthru /dev/nvme0 --opcode=0x06 -r

# 또는 Get Log Page (opcode 0x02)
sudo nvme admin-passthru /dev/nvme0 --opcode=0x02 -r

# 또는 Vendor Specific (opcode 0xC0)
sudo nvme admin-passthru /dev/nvme0 --opcode=0xC0 -r
```

**[터미널 2] GDB에서 실행 중단 및 분석**
```bash
# NVMe 커맨드 전송 직후 재빨리:
Ctrl+C

# 현재 PC(Program Counter) 확인
(gdb) info registers pc
# 출력 예: pc  0x12345678

# 콜스택 확인 (가장 중요!)
(gdb) bt
# 출력 예:
# #0  0x12345678 in ?? ()
# #1  0x11112222 in ?? ()  ← 커맨드 핸들러 후보
# #2  0x11113333 in ?? ()  ← 디스패처 후보
# #3  0x11114444 in ?? ()
```

#### 반복해서 정확한 함수 찾기

```
1. (gdb) continue
2. [터미널 3] NVMe 커맨드 전송
3. [터미널 2] Ctrl+C
4. (gdb) bt
5. 콜스택 기록
6. 1~5 반복 (5~10회)
```

→ **콜스택에서 반복적으로 나타나는 주소** = 커맨드 처리 함수

#### 콜스택 분석 예시

```
# 1차 시도 (Identify 명령)
#0  0x00054321 in ?? ()
#1  0x00012345 in ?? ()  ← 반복 출현
#2  0x00011111 in ?? ()  ← 반복 출현
#3  0x00010000 in ?? ()

# 2차 시도 (Get Log Page 명령)
#0  0x00054999 in ?? ()
#1  0x00012345 in ?? ()  ← 반복 출현 (같은 주소!)
#2  0x00011111 in ?? ()  ← 반복 출현 (같은 주소!)
#3  0x00010000 in ?? ()

# 3차 시도 (Vendor Specific 명령)
#0  0x00058888 in ?? ()
#1  0x00012345 in ?? ()  ← 반복 출현 (같은 주소!)
#2  0x00011111 in ?? ()  ← 반복 출현 (같은 주소!)
#3  0x00010000 in ?? ()
```

**분석 결과:**
- `0x00012345` = Admin Command Handler (entrypoint 후보 1)
- `0x00011111` = Command Dispatcher (entrypoint 후보 2)

#### 찾은 주소를 Ghidra에서 확인

```
Ghidra → Navigation → Go To Address (단축키: G)
→ 주소 입력: 0x00012345
→ 함수 구조 확인 (switch문, 분기문 등)
```

#### 최종 Entrypoint 선택 기준

| 함수 특성 | Entrypoint로 적합? |
|----------|-------------------|
| 여러 opcode로 분기하는 switch문 | O (적합) |
| 단일 기능만 수행 | X (너무 구체적) |
| 인터럽트 핸들러 최상위 | X (너무 광범위) |

→ **커맨드별로 분기하는 디스패처 함수**가 가장 적합

---

### 방법 B: 정적 분석 (심볼 없을 때)

동적 분석이 어려운 경우 Ghidra에서 정적으로 찾습니다.

#### B-1. Scalar(상수) 검색
- **Search → For Scalars**
- 값: `6` (Identify), `2` (Get Log Page), `192` (0xC0, Vendor Specific)
- 이 값을 비교하는 함수 확인

#### B-2. 큰 함수 찾기
- **Window → Functions**
- **Function Size** 컬럼 클릭해서 정렬
- 가장 큰 함수들 = switch문 많음 = 디스패처 가능성

#### B-3. 함수 호출 그래프
- **Window → Function Call Graph**
- 많이 호출되는 함수 확인

---

### 방법 C: 브레이크포인트로 정밀 추적

특정 주소에서 멈추고 싶을 때:

```bash
(gdb) break *0x00012345
(gdb) continue

# 브레이크포인트 도달 시
(gdb) info registers
(gdb) x/10i $pc          # 현재 위치 어셈블리 확인
(gdb) x/20x $sp          # 스택 확인
```

---

## [2] NVMe Connection 파일 작성

```bash
nano src/GDBFuzz/connections/NVMeConnection.py
```

```python
from GDBFuzz.connections.SUTConnection import SUTConnection
import subprocess
import os

class NVMeConnection(SUTConnection):
    def __init__(self, **kwargs):
        self.device = kwargs.get('device', '/dev/nvme0')
        self.opcode = kwargs.get('opcode', '0xC0')

    def send_input(self, data: bytes) -> None:
        input_file = '/tmp/nvme_fuzz_input'
        with open(input_file, 'wb') as f:
            f.write(data)

        try:
            subprocess.run([
                'nvme', 'admin-passthru',
                self.device,
                '--opcode=' + self.opcode,
                '--input-file=' + input_file,
                '--data-len=' + str(len(data)),
                '-r'
            ], capture_output=True, timeout=5)
        except:
            pass

    def reset(self) -> None:
        pass
```

---

## [3] 설정 파일 작성

```bash
cp example_programs/fuzz_json.cfg my_ssd_fuzz.cfg
nano my_ssd_fuzz.cfg
```

```ini
[SUT]
binary_file_path = /path/to/ssd_firmware.bin
entrypoint = 0x00012345
until_rotate_breakpoints = 10
max_breakpoints = 4
ignore_functions =
target_mode = Hardware
start_ghidra = False
software_breakpoint_addresses =
consider_sw_breakpoint_as_error = False

[SUTConnection]
SUT_connection_file = NVMeConnection.py
device = /dev/nvme0
opcode = 0xC0

[GDB]
path_to_gdb = gdb-multiarch
gdb_server_address = localhost:2331

[Fuzzer]
maximum_input_length = 4096
single_run_timeout = 10
total_runtime = 3600
seeds_directory =

[BreakpointStrategy]
breakpoint_strategy_file = RandomBasicBlockStrategy.py

[Dependencies]
path_to_ghidra = dependencies/ghidra

[LogsAndVisualizations]
loglevel = INFO
output_directory = ./output
enable_UI = False
```

**주요 설정 설명:**
- `entrypoint`: 동적 분석으로 찾은 주소 (예: `0x00012345`)
- `max_breakpoints`: ARM Cortex-R8은 보통 하드웨어 BP 6~8개 지원, 안전하게 4개 사용
- `opcode`: fuzzing할 NVMe 커맨드 opcode

---

## [4] J-Link GDB Server 실행

터미널 1에서:

```bash
JLinkGDBServer -device Cortex-R8 -if JTAG -speed 4000
```

→ `localhost:2331`에서 대기

**옵션 설명:**
- `-device Cortex-R8`: 타겟 CPU
- `-if JTAG`: 인터페이스 (SWD도 가능)
- `-speed 4000`: JTAG 속도 (kHz)

---

## [5] Ghidra Bridge 서버 실행

Ghidra GUI에서:
1. 분석한 프로젝트 열기
2. **Window → Script Manager**
3. 검색: `ghidra_bridge`
4. `ghidra_bridge_server.py` 실행 (▶ 버튼)

→ 콘솔에 `Bridge server running on port 4768` 출력되면 성공

---

## [6] GDBFuzz 실행

터미널 2에서:

```bash
cd gdbfuzz
source .venv/bin/activate
./src/GDBFuzz/main.py --config ./my_ssd_fuzz.cfg
```

---

## 결과 확인

### 실시간 진행도 확인

```bash
# fuzzer 통계
cat output/trial-0/fuzzer_stats

# 커버리지 데이터
cat output/trial-0/plot_data

# 실시간 모니터링 (5초마다 갱신)
watch -n 5 cat output/trial-0/fuzzer_stats

# corpus/crashes 개수
ls output/trial-0/corpus | wc -l
ls output/trial-0/crashes | wc -l
```

### 출력 폴더 구조

```
output/trial-0/
├── corpus/       # 입력 corpus
├── crashes/      # 크래시 발견 시
├── cfg           # Control Flow Graph
├── fuzzer_stats  # 통계
├── plot_data     # 커버리지 데이터
└── reverse_cfg   # Reverse CFG
```

---

## 오프라인 설치 방법

### WSL에서 패키지 준비

```bash
# 폴더 생성
mkdir -p ~/gdbfuzz_offline/apt_packages
mkdir -p ~/gdbfuzz_offline/pip_packages

# apt 패키지 다운로드
cd ~/gdbfuzz_offline/apt_packages
apt-get download $(apt-cache depends --recurse --no-recommends --no-suggests \
    --no-conflicts --no-breaks --no-replaces --no-enhances \
    python3-pip python3-venv python3-dev virtualenv make clang gdb gdb-multiarch \
    wget unzip default-jdk graphviz git build-essential ninja-build pkg-config \
    libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libgss-dev libz-dev \
    autotools-dev libtool libarchive-dev libpng-dev libbz2-dev libxml2-dev \
    libssl-dev liblzma-dev libgcrypt20-dev stlink-tools 2>/dev/null | grep "^\w" | sort -u)

# pip 패키지 다운로드
cd ~/gdbfuzz_offline/pip_packages
pip download pygdbmi==0.10.0.1 ghidra-bridge==0.2.5 networkx==2.6.3 \
    paho-mqtt==1.6.1 attrs==21.2.0 seaborn==0.11.2 pandas==1.3.4 \
    matplotlib==3.5.1 pyelftools==0.27 pyserial==3.5 pyusb==1.2.1 \
    jfx-bridge==0.9.1 wheel setuptools

# 전체 압축
cd /home/ssd
tar -czvf gdbfuzz_offline.tar.gz gdbfuzz ~/gdbfuzz_offline
```

### 네이티브 PC에서 설치

```bash
# 압축 풀기
tar -xzvf gdbfuzz_offline.tar.gz

# apt 패키지 설치
cd ~/gdbfuzz_offline/apt_packages
sudo dpkg -i *.deb

# Python 가상환경 생성 (Python 3.8 사용)
cd gdbfuzz
rm -rf .venv
virtualenv .venv -p python3.8
source .venv/bin/activate

# pip 패키지 오프라인 설치
pip install --no-index --find-links=~/gdbfuzz_offline/pip_packages -e .

# Ghidra Bridge 서버 스크립트 설치
python3 -m ghidra_bridge.install_server ~/ghidra_scripts
```

---

## 문제 해결

### Ghidra Bridge 서버 스크립트 없음
```
Exception: No Such file ghidra_bridge_script='/root/ghidra_scripts/ghidra_bridge_server.py'
```

해결:
```bash
source .venv/bin/activate
python3 -m ghidra_bridge.install_server ~/ghidra_scripts
```

### pandas 버전 호환 문제
Python 3.10 이상에서 pandas 1.3.4 설치 실패 시:
→ Python 3.8로 가상환경 재생성

```bash
rm -rf .venv
virtualenv .venv -p python3.8
source .venv/bin/activate
pip install --no-index --find-links=~/gdbfuzz_offline/pip_packages -e .
```

### GDB 연결 실패
```
Error: Cannot connect to target
```

확인사항:
1. J-Link GDB Server가 실행 중인지 확인
2. 포트 번호 확인 (기본 2331)
3. J-Link USB 연결 상태 확인
4. JTAG 케이블 연결 확인

### 하드웨어 브레이크포인트 부족
```
Error: No more hardware breakpoints available
```

해결: `max_breakpoints` 값을 줄이기 (ARM Cortex-R8은 보통 6~8개 지원)

---

## NVMe Opcode 참고

### Admin Commands
| Opcode | 명령 |
|--------|------|
| 0x00 | Delete I/O Submission Queue |
| 0x01 | Create I/O Submission Queue |
| 0x02 | Get Log Page |
| 0x04 | Delete I/O Completion Queue |
| 0x05 | Create I/O Completion Queue |
| 0x06 | Identify |
| 0x08 | Abort |
| 0x09 | Set Features |
| 0x0A | Get Features |
| 0x0C | Asynchronous Event Request |
| 0x10 | Firmware Commit |
| 0x11 | Firmware Image Download |
| 0xC0-0xFF | Vendor Specific |

### NVMe CLI 예시
```bash
# Identify
sudo nvme admin-passthru /dev/nvme0 --opcode=0x06 -r

# Get Log Page
sudo nvme admin-passthru /dev/nvme0 --opcode=0x02 --cdw10=0x01 -r

# Vendor Specific with data
echo -n "test data" > /tmp/input
sudo nvme admin-passthru /dev/nvme0 --opcode=0xC0 --input-file=/tmp/input --data-len=9 -r
```

---

## 참고

- GDBFuzz GitHub: https://github.com/boschresearch/gdbfuzz
- Python 요구사항: >= 3.8.0
- 테스트 환경: Ubuntu 20.04 LTS
- NVMe Spec: https://nvmexpress.org/specifications/
