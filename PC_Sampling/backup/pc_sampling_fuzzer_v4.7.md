# PC Sampling SSD Firmware Fuzzer v4.7

J-Link Halt-Sample-Resume 방식으로 커버리지를 수집하고,
`nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

---

## 목차

1. [요구사항](#요구사항)
2. [빠른 시작](#빠른-시작)
3. [코드 상단 상수 설정](#코드-상단-상수-설정)
4. [CLI 옵션](#cli-옵션)
5. [명령어 목록](#명령어-목록)
6. [출력 디렉터리 구조](#출력-디렉터리-구조)
7. [크래시 발생 후 처리](#크래시-발생-후-처리)
8. [seed_replay_test.sh](#seed_replay_testsh)
9. [버전 이력 요약](#버전-이력-요약)

---

## 요구사항

```
Python 3.9+
pylink-square       # pip install pylink-square
nvme-cli            # apt install nvme-cli
J-Link V9 (JTAG)   # 펌웨어 PC 샘플링용
```

실행 권한:
```bash
# nvme-cli는 root 권한 필요
sudo python3 pc_sampling_fuzzer_v4.7.py [옵션]
```

---

## 빠른 시작

### 기본 실행 (안전 명령어만, FW 제외)

```bash
sudo python3 pc_sampling_fuzzer_v4.7.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --output ./output/run1
```

기본 활성 명령어: `Identify`, `GetLogPage`, `GetFeatures`, `Read`, `Write`

---

### SWD 인터페이스 (idle 감지 비활성화 권장)

```bash
sudo python3 pc_sampling_fuzzer_v4.7.py \
  --device Cortex-R8 \
  --interface swd \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --saturation-limit 0 \          # SWD: per-run local saturation 비활성화
  --global-saturation-limit 20 \  # global 기준 종료 신호로 대체
  --output ./output/run_swd
```

> SWD에서 `--saturation-limit` 기본값(10)을 그대로 쓰면 명령 처리 루프에서 오발동할 수 있습니다.

---

### 펌웨어 포함 전체 명령어 실행 (FWDownload/FWCommit 포함)

```bash
sudo python3 pc_sampling_fuzzer_v4.7.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --all-commands \
  --fw-bin ./FW.bin \
  --fw-xfer 32768 \
  --fw-slot 1 \
  --output ./output/run_fw
```

---

### 특정 명령어만 선택

```bash
sudo python3 pc_sampling_fuzzer_v4.7.py \
  --commands Read Write FormatNVM \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF
```

---

### 이전 세션에서 재개 (커버리지 이어받기)

```bash
sudo python3 pc_sampling_fuzzer_v4.7.py \
  --resume-coverage ./output/run1/coverage.txt \
  --seed-dir ./output/run1/corpus \
  --output ./output/run2
```

---

## 코드 상단 상수 설정

퍼저 실행 전 코드 상단 `USER CONFIGURATION` 섹션을 환경에 맞게 수정해야 합니다.

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FW_ADDR_START` | `0x00000000` | 펌웨어 .text 섹션 시작 주소 (Ghidra에서 확인) |
| `FW_ADDR_END`   | `0x00147FFF` | 펌웨어 .text 섹션 끝 주소 |
| `JLINK_DEVICE`  | `'Cortex-R8'` | J-Link 타깃 디바이스명 |
| `JLINK_SPEED`   | `12000` | JTAG 속도 (kHz) |
| `NVME_DEVICE`   | `'/dev/nvme0'` | NVMe 캐릭터 디바이스 경로 |
| `NVME_NAMESPACE`| `1` | NVMe 네임스페이스 번호 |
| `MAX_SAMPLES_PER_RUN` | `500` | 명령어 1회당 최대 PC 샘플 수 |
| `TOTAL_RUNTIME_SEC`   | `604800` | 총 퍼징 시간 (초, 기본 1주일) |
| `OUTPUT_DIR`    | `'./output/pc_sampling_v4.7/'` | 결과 저장 경로 |

타임아웃은 코드 내 `NVME_TIMEOUTS` 딕셔너리에서 설정:

```python
NVME_TIMEOUTS = {
    'command':   18_000,    # 일반 명령어 (ms)
    'format':    600_000,   # FormatNVM
    'sanitize':  600_000,   # Sanitize
    'fw_commit': 120_000,   # FWCommit
    'telemetry': 30_000,    # TelemetryHostInitiated
    'dsm':       30_000,    # DatasetManagement
    'flush':     30_000,    # Flush
}
```

---

## CLI 옵션

### 필수/주요 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--device NAME` | `Cortex-R8` | J-Link 타깃 디바이스명 |
| `--nvme PATH` | `/dev/nvme0` | NVMe 디바이스 경로 |
| `--namespace N` | `1` | NVMe 네임스페이스 번호 |
| `--addr-start HEX` | `0x00000000` | 펌웨어 .text 시작 주소 |
| `--addr-end HEX` | `0x00147FFF` | 펌웨어 .text 끝 주소 |
| `--output DIR` | `./output/...` | 결과 저장 디렉터리 |
| `--runtime SEC` | `604800` | 총 퍼징 시간 (초) |

### 명령어 선택 옵션

| 옵션 | 설명 |
|------|------|
| *(없음)* | 기본 안전 명령어만: `Identify`, `GetLogPage`, `GetFeatures`, `Read`, `Write` |
| `--commands A B C` | 명시적으로 명령어 선택. 가능한 이름은 [명령어 목록](#명령어-목록) 참조 |
| `--all-commands` | 파괴적 명령어 포함 전체 활성화 (`FormatNVM`, `Sanitize`, `FWDownload` 등) |

### 펌웨어 다운로드 옵션 (v4.7)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--fw-bin PATH` | `None` | 펌웨어 바이너리 경로. 없으면 더미 1KB 시드 사용 |
| `--fw-xfer BYTES` | `32768` | FWDownload 청크 크기 (컨트롤러 FWUG × 4096, 보통 32KB) |
| `--fw-slot N` | `1` | FWCommit 슬롯 번호 (1~7) |

> `--fw-bin` 없이 `FWDownload`를 실행하면 더미 0x00 데이터로 퍼징됩니다.
> 실제 펌웨어 파싱 경로를 테스트하려면 반드시 `--fw-bin`을 지정하세요.

### 타임아웃 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--timeout GROUP MS` | (각 그룹 기본값) | 그룹별 timeout 오버라이드. 예: `--timeout command 8000 --timeout format 300000` |
| `--passthru-timeout MS` | `2592000000` (30일) | nvme-cli `--timeout` 값. 크게 설정할수록 커널 reset 방지 |
| `--kernel-timeout SEC` | `2592000` (30일) | nvme_core 모듈의 `admin_timeout`/`io_timeout`. 퍼저 시작 시 `/sys/module/nvme_core/parameters/`에 기록 |

### 샘플링 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--samples N` | `500` | 명령어 1회당 최대 PC 샘플 수 |
| `--interval US` | `0` | 샘플 간격 (마이크로초, 0 = halt 직후 즉시 재샘플) |
| `--post-cmd-delay MS` | `0` | 명령 완료 후 추가 tail 샘플링 시간 (ms) |
| `--saturation-limit N` | `10` | per-run 수렴 감지: 이번 실행에서 이미 본 PC가 N회 연속이면 조기 종료. **JTAG**: 단일 idle PC에서 빠르게 수렴, 그대로 사용. **SWD**: 처리 루프 재방문과 idle 구별 불가 → `0`으로 비활성화 권장 |
| `--global-saturation-limit N` | `20` | global 커버리지 대비 새 PC 없이 N회 연속이면 조기 종료. SWD에서 `--saturation-limit 0` 설정 시 주요 종료 신호 |

### Mutation 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--random-gen-ratio R` | `0.2` | 완전 랜덤 입력 생성 비율 (0.0~1.0) |
| `--opcode-mut-prob P` | `0.10` | Opcode 무작위 교체 확률 |
| `--nsid-mut-prob P` | `0.10` | Namespace ID 무작위 교체 확률 |
| `--admin-swap-prob P` | `0.05` | Admin↔IO 교차 전송 확률 |
| `--datalen-mut-prob P` | `0.08` | data_len↔CDW 의도적 불일치 확률 |
| `--exclude-opcodes HEX` | `''` | 퍼징에서 제외할 opcode (쉼표 구분, e.g. `0xC1,0xC0`) |
| `--max-energy F` | `16.0` | Power Schedule 최대 에너지 |

### Calibration / Deterministic / MOpt 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--calibration-runs N` | `3` | 초기 시드당 calibration 반복 횟수 (0 = 비활성화) |
| `--no-deterministic` | `False` | Deterministic stage 비활성화 |
| `--det-arith-max N` | `10` | Deterministic arithmetic delta 최대값 |
| `--no-mopt` | `False` | MOpt mutation scheduling 비활성화 |
| `--mopt-pilot-period N` | `5000` | MOpt pilot 단계 실행 횟수 |
| `--mopt-core-period N` | `50000` | MOpt core 단계 실행 횟수 |

### 기타 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--speed KHZ` | `12000` | JTAG 속도 |
| `--seed-dir DIR` | `None` | 이전 corpus 디렉터리 (시드로 로드) |
| `--resume-coverage FILE` | `None` | 이전 세션 `coverage.txt` 경로 (커버리지 이어받기) |

---

## 명령어 목록

### 기본 명령어 (항상 활성, 비파괴)

| 이름 | Opcode | 타입 | 설명 |
|------|--------|------|------|
| `Identify` | `0x06` | Admin | 장치/네임스페이스 정보 조회 |
| `GetLogPage` | `0x02` | Admin | 로그 페이지 조회 |
| `GetFeatures` | `0x0A` | Admin | 기능 조회 |
| `Read` | `0x02` | IO | 데이터 읽기 |
| `Write` | `0x01` | IO | 데이터 쓰기 |

### 확장 명령어 (`--all-commands` 또는 `--commands`로 활성화)

| 이름 | Opcode | 타입 | timeout_group | 주의 |
|------|--------|------|---------------|------|
| `SetFeatures` | `0x09` | Admin | command | |
| `FWDownload` | `0x11` | Admin | command | `--fw-bin` 권장 |
| `FWCommit` | `0x10` | Admin | fw_commit | 펌웨어 재부팅 유발 가능 |
| `FormatNVM` | `0x80` | Admin | format | ⚠️ 미디어 초기화 |
| `Sanitize` | `0x84` | Admin | sanitize | ⚠️ 전체 데이터 소거 |
| `TelemetryHostInitiated` | `0x02` | Admin | telemetry | |
| `Flush` | `0x00` | IO | flush | |
| `DatasetManagement` | `0x09` | IO | dsm | TRIM/Deallocate |

---

## 출력 디렉터리 구조

```
output/pc_sampling_v4.7/
├── fuzzer_YYYYMMDD_HHMMSS.log   # 실행 로그
├── coverage.txt                  # 발견된 PC 주소 목록 (resume용)
├── corpus/
│   ├── seed_0000.bin            # corpus 시드 바이너리
│   ├── seed_0001.bin
│   └── ...
├── crashes/
│   ├── crash_<md5>.json         # 크래시 메타데이터
│   ├── crash_<md5>.bin          # 크래시 유발 입력
│   └── crash_<md5>.dmesg.txt    # 크래시 시점 dmesg
├── cfg/
│   ├── cfg_Read.dot             # 명령어별 CFG 그래프
│   └── ...
└── heatmap_<timestamp>.png      # PC 히트맵 이미지
```

---

## 크래시 발생 후 처리

퍼저는 크래시(timeout) 감지 즉시 NVMe 드라이버를 unbind해 SSD 상태를 보존합니다.

### 1. 크래시 확인

```bash
ls ./output/pc_sampling_v4.7/crashes/
cat ./output/pc_sampling_v4.7/crashes/crash_<md5>.json
```

### 2. JTAG으로 펌웨어 상태 분석

```bash
# J-Link GDB Server 재연결 후
(gdb) monitor halt
(gdb) info registers pc
(gdb) backtrace
```

### 3. 분석 완료 후 드라이버 재바인드

```bash
# BDF (Bus:Device.Function) 확인
lspci | grep -i nvme

# 드라이버 바인드 (BDF 형식: 0000:02:00.0)
echo '0000:02:00.0' | sudo tee /sys/bus/pci/drivers/nvme/bind
```

### 4. SSD가 정상 복귀하지 않는 경우

nvme-cli ctrl reset으로는 CPU 하드웨어 리셋이 되지 않습니다.
GDB를 통해 직접 리셋해야 합니다:

```gdb
monitor reset run
```

---

## seed_replay_test.sh

퍼저 초기 시드를 실제 NVMe 명령어로 실행해 동작을 검증하는 스크립트입니다.
파일 위치: `PC_Sampling/seed_replay_test.sh`

### 사용법

```bash
cd /path/to/PC_Sampling
./seed_replay_test.sh /dev/nvme0 [FW.bin] [fw_xfer_size] [fw_slot]
```

| 인자 | 기본값 | 설명 |
|------|--------|------|
| `DEVICE` | (필수) | NVMe 디바이스 경로 (e.g. `/dev/nvme0`) |
| `FW_BIN` | `FW.bin` | 펌웨어 바이너리 파일명 (스크립트와 같은 디렉터리) |
| `FW_XFER` | `32768` | fw-download 청크 크기 (bytes) |
| `FW_SLOT` | `1` | fw-commit 슬롯 번호 |

### 예시

```bash
# 기본 (FW.bin 파일이 현재 디렉터리에 있어야 함)
sudo ./seed_replay_test.sh /dev/nvme0

# 슬롯 2 사용
sudo ./seed_replay_test.sh /dev/nvme0 FW.bin 32768 2
```

### 스크립트가 테스트하는 시드 목록

각 시드는 v4.7 퍼저의 초기 시드와 동일한 명령어 파라미터를 사용합니다.

| # | 명령어 | 설명 |
|---|--------|------|
| 0 | Identify (Namespace) | CNS=0x00 NSID=1 |
| 1 | Identify (Controller) | CNS=0x01 NSID=0 |
| 2 | GetLogPage (Error) | LID=0x01 NSID=0 |
| 3 | GetLogPage (SMART) | LID=0x02 NSID=0 |
| 4 | GetLogPage (FW Slot) | LID=0x03 NSID=1 |
| 5 | GetFeatures (Arbitration) | FID=0x01 |
| 6 | GetFeatures (Power Mgmt) | FID=0x02 |
| 7 | GetFeatures (LBA Range) | FID=0x03 |
| 8 | GetFeatures (Temp Threshold) | FID=0x04 |
| 9 | GetFeatures (Error Recovery) | FID=0x05 |
| 10 | GetFeatures (Volatile Write Cache) | FID=0x06 |
| 11 | GetFeatures (Queues) | FID=0x07 |
| 12 | Read LBA 0 (1 block) | NLB=0 |
| 13 | Read LBA 0 FUA | CDW12[29]=1 |
| 14 | Read LBA 0 (256 blocks) | NLB=255, 128KB |
| 15 | Write LBA 0 (1 block) | NLB=0 |
| 16 | Write LBA 0 FUA | CDW12[29]=1 |
| 17 | Write LBA 0 (256 blocks) | NLB=255, 128KB |
| 18 | TelemetryHostInitiated | LID=0x07 NSID=0 |
| 19 | SetFeatures (Volatile Write Cache) | FID=0x06 SAVE=0 |
| 20 | FormatNVM (SES=0) | LBAF=0, 비파괴 |
| 21 | FWDownload | `nvme fw-download -f FW.bin -x 32768` |
| 22 | FWCommit | `nvme fw-commit -s 1 -a 1` |
| 23 | DatasetManagement | NR=0, AD=1 (TRIM) |
| 24 | Flush | |

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v4.7** | FUA 비트 수정 (CDW12[14]→[29]), 컨트롤러 범위 명령 NSID=0, Sanitize 초기 시드 제거, `--fw-bin/--fw-xfer/--fw-slot` 추가, `all_commands` 기본값 False 수정, `_select_seed()` None 가드 추가 |
| **v4.6** | io-passthru → namespace device, passthru timeout 분리 (커널 reset 방지), 크래시 시 nvme 드라이버 unbind |
| **v4.5** | Calibration, Deterministic stage (bitflip/arith/interesting), MOpt mutation scheduling |
| **v4.4** | Opcode→name 역방향 테이블, Heatmap 크기 제한, timeout 시 dmesg 캡처 |
| **v4.3** | Corpus culling, J-Link heartbeat, 랜덤 생성 비율, 확장 mutation 확률 |
| **v4.2** | subprocess + 샘플링 연동, 글로벌 기준 포화 판정, idle PC 감지 |
| **v4.1** | CDW2~CDW15 시드 필드, NVMe 스펙 기반 초기 시드 자동 생성 |
| **v4.0** | unique PC 기반 coverage signal, CFG/히트맵, AFLfast Power Schedule |
