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
[1] Ghidra에서 entrypoint 함수 찾기
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

## [1] Ghidra에서 entrypoint 함수 찾기

Ghidra에서 분석한 프로젝트를 열고 NVMe 커맨드 처리 함수를 찾습니다.

### 1-1. 문자열 검색으로 단서 찾기
- 메뉴: **Search → For Strings**
- 검색: `nvme`, `admin`, `command`, `opcode`
- 찾은 문자열 더블클릭 → 참조하는 함수로 이동

### 1-2. Opcode 상수 검색
- 메뉴: **Search → For Scalars**
- 값: `6` (Identify 명령) 또는 `192` (0xC0, Vendor Specific)
- 이 값을 사용하는 함수 확인

### 1-3. 후보 함수 확인
- switch문이나 if-else 체인이 있는 함수
- opcode 값으로 분기하는 구조
- **함수 이름 또는 주소 메모**

### NVMe SQE 구조체 참고 (64바이트)

```c
struct nvme_command {
    uint8_t  opcode;      // offset 0x00
    uint8_t  flags;       // offset 0x01
    uint16_t command_id;  // offset 0x02
    uint32_t nsid;        // offset 0x04
    ...
};
```

→ Ghidra에서 **offset 0x00에서 1바이트 읽고 switch하는 함수**를 찾으세요.

### 찾아야 할 함수 패턴

```
[NVMe Submission Queue Entry 수신]
         ↓
[Command Dispatcher] ← 이 함수가 entrypoint 후보
         ↓
    ┌────┴────┐
    ↓         ↓
[Admin Cmd] [IO Cmd]
Handler     Handler
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
binary_file_path = /path/to/ssd_firmware.elf
entrypoint = <찾은 함수명 또는 주소>
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

---

## [4] J-Link GDB Server 실행

터미널 1에서:

```bash
JLinkGDBServer -device Cortex-R8 -if JTAG -speed 4000
```

→ `localhost:2331`에서 대기

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

---

## 참고

- GDBFuzz GitHub: https://github.com/boschresearch/gdbfuzz
- Python 요구사항: >= 3.8.0
- 테스트 환경: Ubuntu 20.04 LTS
