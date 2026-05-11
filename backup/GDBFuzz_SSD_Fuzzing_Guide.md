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

## Ghidra vs GDB 역할 분리

### 왜 Ghidra는 파일만 분석하는가?

```
┌─────────────────────────────────────────────────────────────┐
│                      Ghidra                                 │
│              (정적 분석 - 파일 분석)                          │
│                                                             │
│   바이너리 파일(.bin) → CFG 추출 → 브레이크포인트 위치 결정    │
│                                                             │
│   "이 주소에서 분기가 있다", "이 함수는 여기서 끝난다"         │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ Ghidra Bridge (CFG 정보 전달)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                      GDBFuzz                                │
│                                                             │
│   Ghidra에서 받은 CFG 정보로 브레이크포인트 위치 결정         │
│   GDB에 브레이크포인트 설정 명령                             │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ GDB 명령
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    GDB + J-Link                             │
│              (동적 분석 - 실행 관찰)                          │
│                                                             │
│   실제 SSD에 브레이크포인트 설정 → 실행 모니터링              │
│                                                             │
│   "0x12345에서 멈췄다!", "이 코드가 실행됐다!"               │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ JTAG
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    SSD (실행 중)                             │
└─────────────────────────────────────────────────────────────┘
```

| 도구 | 역할 | 대상 |
|------|------|------|
| **Ghidra** | 정적 분석 | 바이너리 **파일** |
| **GDB** | 동적 모니터링 | 실행 중인 **SSD** |

- Ghidra는 SSD를 직접 보지 않음
- Ghidra는 **파일만 분석**해서 "어디에 브레이크포인트를 걸면 좋겠다"를 알려줌
- GDB가 **실제 SSD**에 브레이크포인트를 설정하고 모니터링

### 중요한 전제조건

**바이너리 파일 = SSD에 올라간 펌웨어** (동일해야 함)

주소가 일치해야 Ghidra가 분석한 `0x12345` 주소가 실제 SSD에서도 같은 코드를 가리킴.

---

## 커버리지 체크 담당

**GDB + GDBFuzz**가 함께 합니다.

```
┌─────────────────────────────────────────────────────────────┐
│                      GDBFuzz                                │
│                                                             │
│  1. Ghidra에서 CFG 받음 → "도달 안 한 basic block 목록"      │
│  2. 그 중 일부에 브레이크포인트 설정 (GDB에 명령)             │
│  3. 브레이크포인트 hit 시 → "새 코드 도달!" 기록             │
│  4. 커버리지 통계 관리                                       │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                        GDB                                  │
│                                                             │
│  - 하드웨어 브레이크포인트 설정                              │
│  - 브레이크포인트 hit 감지 → GDBFuzz에 알림                  │
└─────────────────────────────────────────────────────────────┘
```

### 커버리지 동작 흐름

```
1. GDBFuzz: "0x1000, 0x2000, 0x3000에 BP 설정해줘" → GDB
                          ↓
2. 입력 전송 → SSD 실행
                          ↓
3. SSD가 0x2000 실행 → GDB: "BP hit at 0x2000!"
                          ↓
4. GDBFuzz: "0x2000 도달 기록!" (커버리지 +1)
                          ↓
5. GDBFuzz: "0x2000 BP 제거, 새 위치 0x4000에 BP 설정"
                          ↓
6. 반복
```

### 일반 Fuzzer와 차이점

| 방식 | AFL/libFuzzer | GDBFuzz |
|------|---------------|---------|
| 커버리지 수집 | 컴파일 시 코드 삽입 (instrumentation) | 하드웨어 브레이크포인트 |
| 펌웨어 수정 | 필요 | **불필요** |
| 속도 | 빠름 | 느림 (BP hit마다 멈춤) |
| 적용 대상 | 소스코드 있을 때 | 바이너리만 있어도 가능 |

**GDBFuzz의 장점**: 펌웨어 수정 없이 커버리지 측정 가능 (임베디드/SSD에 적합)

---

## 하드웨어/소프트웨어 세팅

### 전체 세팅 구조

```
┌─────────────────────────────────────────────────────────────────┐
│                         Host PC                                 │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ GDBFuzz  │  │  Ghidra  │  │ J-Link   │  │ NVMe CLI │        │
│  │          │  │          │  │ GDB Svr  │  │          │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │               │
│       └──────┬──────┴─────────────┤             │               │
│              │                    │             │               │
│         Ghidra Bridge        GDB 연결           │               │
│              │                    │             │               │
└──────────────┼────────────────────┼─────────────┼───────────────┘
               │                    │             │
               │               USB 케이블         │ PCIe
               │                    │             │
               │              ┌─────┴─────┐       │
               │              │  J-Link   │       │
               │              │    V9     │       │
               │              └─────┬─────┘       │
               │                    │ JTAG        │
               │                    │             │
         ┌─────┴────────────────────┴─────────────┴─────┐
         │                    SSD                       │
         │              (ARM Cortex-R8)                 │
         │                                              │
         │   ┌─────────┐          ┌─────────┐          │
         │   │ JTAG    │          │  NVMe   │          │
         │   │ 포트    │          │ 인터페이스│          │
         │   └─────────┘          └─────────┘          │
         └──────────────────────────────────────────────┘
```

### 필요 장비 (하드웨어)

| 장비 | 용도 |
|------|------|
| Host PC | GDBFuzz, Ghidra, J-Link 소프트웨어 실행 |
| J-Link V9 | JTAG 디버거 |
| JTAG 케이블 | J-Link ↔ SSD 연결 |
| SSD | 타겟 (펌웨어 올라간 상태) |
| PCIe 슬롯/어댑터 | Host PC ↔ SSD NVMe 연결 |

### 연결 방법

```
1. J-Link V9 ←(USB)→ Host PC
2. J-Link V9 ←(JTAG 케이블)→ SSD JTAG 포트
3. SSD ←(PCIe)→ Host PC
```

### JTAG 핀 연결 (확인 필요)

| J-Link 핀 | SSD JTAG 핀 |
|-----------|-------------|
| TDI | TDI |
| TDO | TDO |
| TCK | TCK |
| TMS | TMS |
| GND | GND |
| (VTref) | (3.3V 또는 타겟 전압) |

### 필요 소프트웨어

```bash
# 1. J-Link 소프트웨어 (Segger 홈페이지에서 다운로드)
#    https://www.segger.com/downloads/jlink/

# 2. gdb-multiarch
sudo apt install gdb-multiarch

# 3. NVMe CLI
sudo apt install nvme-cli

# 4. GDBFuzz (이미 설치됨)
cd gdbfuzz
source .venv/bin/activate

# 5. Ghidra (이미 설치됨)
# dependencies/ghidra/
```

### 실행 순서 (터미널 4개)

```
┌─────────────────┬─────────────────┐
│ [터미널 1]       │ [터미널 2]       │
│ J-Link GDB Svr  │ Ghidra GUI      │
├─────────────────┼─────────────────┤
│ [터미널 3]       │ [터미널 4]       │
│ GDBFuzz         │ 모니터링/테스트   │
└─────────────────┴─────────────────┘
```

**[터미널 1] J-Link GDB Server**
```bash
JLinkGDBServer -device Cortex-R8 -if JTAG -speed 4000
```
→ `Waiting for GDB connection...` 확인

**[터미널 2] Ghidra**
```bash
cd gdbfuzz/dependencies/ghidra
./ghidraRun
```
→ 프로젝트 열기 → Window → Script Manager → `ghidra_bridge_server.py` 실행

**[터미널 3] GDBFuzz**
```bash
cd gdbfuzz
source .venv/bin/activate
./src/GDBFuzz/main.py --config ./my_ssd_fuzz.cfg
```

**[터미널 4] 모니터링**
```bash
watch -n 5 cat gdbfuzz/output/trial-0/fuzzer_stats
```

### 세팅 체크리스트

#### 하드웨어
- [ ] J-Link V9 USB 연결됨
- [ ] JTAG 케이블 연결됨 (핀 배열 확인)
- [ ] SSD PCIe 연결됨
- [ ] `lsblk` 또는 `nvme list`에서 SSD 보임

#### 소프트웨어
- [ ] J-Link GDB Server 설치됨
- [ ] gdb-multiarch 설치됨
- [ ] nvme-cli 설치됨
- [ ] GDBFuzz 가상환경 설정됨
- [ ] Ghidra 실행 가능
- [ ] Ghidra Bridge 스크립트 설치됨

#### 설정
- [ ] my_ssd_fuzz.cfg 작성됨
- [ ] entrypoint 주소 찾음 (동적 분석)
- [ ] NVMeConnection.py 작성됨
- [ ] binary_file_path 경로 정확함

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

## 제공 파일

이 레포지토리에 SSD Fuzzing을 위한 파일들이 포함되어 있습니다.

### NVMeConnection.py

NVMe CLI를 통해 SSD에 퍼징 데이터를 전송하는 Connection 클래스입니다.

**설치 위치:**
```bash
cp NVMeConnection.py /path/to/gdbfuzz/src/GDBFuzz/connections/
```

**주요 기능:**
- NVMe admin-passthru 명령으로 데이터 전송
- 설정 가능한 opcode, device, timeout
- GDBFuzz ConnectionBaseClass 상속

### ssd_fuzz.cfg

SSD Fuzzing용 설정 파일 템플릿입니다.

**사용 방법:**
```bash
cp ssd_fuzz.cfg /path/to/gdbfuzz/
# 파일을 열고 다음 항목 수정:
# - binary_file_path: 펌웨어 바이너리 경로
# - entrypoint: 동적 분석으로 찾은 함수 주소
# - device: NVMe 장치 경로 (/dev/nvme0 등)
# - opcode: 퍼징할 NVMe 커맨드 opcode
```

**수정 필수 항목:**

| 항목 | 설명 | 예시 |
|------|------|------|
| `binary_file_path` | 펌웨어 바이너리 경로 | `/home/user/firmware.bin` |
| `entrypoint` | 퍼징 시작 함수 주소 | `0x00012345` |
| `device` | NVMe 장치 | `/dev/nvme0` |
| `opcode` | NVMe 커맨드 opcode | `0xC0` |

---

## GDBFuzz 설정 구조

GDBFuzz는 config.py가 아니라 **`.cfg` 파일** (INI 형식)을 사용합니다.

```
설정 파일 구조:
├── [SUT]              # 타겟(SSD) 설정
├── [SUTConnection]    # 입력 전송 방법 (NVMe)
├── [GDB]              # GDB 연결 설정
├── [Fuzzer]           # Fuzzer 파라미터
├── [BreakpointStrategy]  # 브레이크포인트 전략
├── [Dependencies]     # 의존성 경로
└── [LogsAndVisualizations]  # 로그 설정
```

### BUFFER_ADDRESS가 필요 없는 이유

GDBFuzz는 **BUFFER_ADDRESS가 필요 없습니다**.

- GDBFuzz는 NVMe CLI를 통해 직접 커맨드 전송
- SSD 내부에서 데이터가 어디에 저장되는지는 SSD가 처리
- GDBFuzz는 **CFG 기반 브레이크포인트**로 커버리지만 측정

---

## 퀵 스타트 순서

```
[1] Entrypoint 찾기 (동적 분석)
    │
    │  JLinkGDBServer → GDB 연결 → NVMe 커맨드 전송 → bt로 콜스택 확인
    │
    ▼
[2] 설정 파일 수정
    │
    │  ssd_fuzz.cfg에서 entrypoint, binary_file_path 등 수정
    │
    ▼
[3] 파일 복사
    │
    │  NVMeConnection.py → gdbfuzz/src/GDBFuzz/connections/
    │  ssd_fuzz.cfg → gdbfuzz/
    │
    ▼
[4] 실행
    │
    │  터미널 1: JLinkGDBServer
    │  터미널 2: Ghidra + Bridge 실행
    │  터미널 3: ./src/GDBFuzz/main.py --config ./ssd_fuzz.cfg
    │
    ▼
[5] 결과 확인
    │
    │  output/ssd_fuzz/trial-0/ 폴더 확인
```

---

## 참고

- GDBFuzz GitHub: https://github.com/boschresearch/gdbfuzz
- Python 요구사항: >= 3.8.0
- 테스트 환경: Ubuntu 20.04 LTS
- NVMe Spec: https://nvmexpress.org/specifications/
- 



Ghidra 분석 완료)까지 되셨다면, 이제 "GDBFuzz가 내 SSD의 어디를 찌르고(Input), 어디서 멈춰야(Breakpoint) 하는지" 알려주는 설정 작업을 해야 합니다.

가장 수정이 시급한 파일은 보통 프로젝트 루트에 있는 config.py (또는 gdbfuzz_config.py)입니다.

텍스트 에디터(VS Code, vim 등)로 **config.py**를 열고, 아래 4가지 핵심 항목을 찾아 수정해주세요. (변수명은 코드 버전에 따라 조금 다를 수 있으나 의미는 같습니다.)

1. 하드웨어 브레이크포인트 개수 제한 (HW_BP_LIMIT)
예제(소프트웨어 시뮬레이션)에서는 브레이크포인트를 무한대로 걸 수 있지만, 실제 SSD(ARM Cortex-R 계열)는 하드웨어적으로 개수가 제한되어 있습니다. 이걸 설정하지 않으면 GDB 에러가 납니다.

찾을 변수: HW_BREAKPOINT_LIMIT 또는 MAX_BREAKPOINTS

수정 값: 4 (또는 6)

설명: 보통 ARM Cortex-R8/R5는 4~8개를 지원하지만, GDB가 내부적으로 1~2개를 쓸 수 있으므로 안전하게 4로 설정하세요.

2. GDB 접속 포트 변경 (GDB_PORT)
예제는 보통 QEMU 포트(1234)를 쓰지만, 실장비(J-Link)는 포트가 다릅니다.

찾을 변수: GDB_PORT 또는 TARGET_PORT

수정 값: 2331

설명: J-Link GDB Server의 기본 포트입니다. (만약 J-Link 실행 시 포트를 바꿨다면 그 번호를 넣으세요)

3. 입력 버퍼 주소 (BUFFER_ADDRESS) [가장 중요]
Fuzzer가 생성한 "랜덤 데이터(Payload)"를 SSD 메모리의 어디에 써넣을지 지정해야 합니다. 엉뚱한 곳에 쓰면 펌웨어가 죽습니다.

찾을 변수: INPUT_BUFFER_ADDRESS 또는 PAYLOAD_ADDR

값 찾는 법 (Ghidra):

Ghidra에서 펌웨어가 NVMe Write 명령을 처리할 때, 호스트 데이터를 저장하는 DRAM 상의 버퍼 주소를 찾아야 합니다.

보통 0x40000000이나 0x20000000 같은 램 영역 주소입니다.

(모르겠다면?): 우선 임시로 사용되지 않는 RAM 영역(빈 공간) 주소를 넣어도 되지만, 펌웨어가 그 데이터를 읽어가도록 로직을 유도해야 합니다.

4. 타겟 함수 범위 (Target Function)
Fuzzing을 수행할 대상 함수(Entry)와 종료 지점(Exit)을 정해야 합니다.

찾을 변수: TARGET_FUNCTION 또는 START_ADDRESS / END_ADDRESS

수정 값: Ghidra에서 분석한 함수 이름 또는 주소(Hex)

예시: 0x000104A0 (NVMe 커맨드 파싱 함수 시작점)

[추가 수정] NVMe 입력 전달 방식 (interface.py 등)
config.py 외에, 실제로 데이터를 쏘는 부분을 확인해야 합니다. 예제는 메모리에 직접 썼겠지만, SSD는 nvme-cli를 써야 할 수도 있습니다.

확인할 파일: interface.py 또는 executor.py

수정 내용: write_memory 방식이 아니라, NVMe Vendor Unique Command를 날리는 방식으로 되어 있는지 확인하세요.

python
# 예시: subprocess를 이용해 nvme 명령 실행
subprocess.run(f"nvme admin-passthru /dev/nvme0n1 ...", shell=True)
만약 이 부분이 구현 안 되어 있다면, 단순히 메모리에 값만 쓰고 펌웨어 루틴을 강제로 실행시키는 방식일 수 있습니다. (이 경우 3번의 버퍼 주소가 정확해야 합니다.)



import gdb
import time

gdb.execute("target remote localhost:2331")
gdb.execute("set pagination off")

log = open("pc_log.txt", "w")

print("Tracing started. Press Ctrl+C to stop.")

try:
    while True:
        gdb.execute("continue&")  # 백그라운드 실행
        time.sleep(0.01)  # 10ms마다 샘플링
        gdb.execute("interrupt")  # 멈춤
        pc = gdb.parse_and_eval("$pc")
        log.write(f"0x{int(pc):08x}\n")
        log.flush()
except KeyboardInterrupt:
    print("\nTrace stopped.")
    log.close()

