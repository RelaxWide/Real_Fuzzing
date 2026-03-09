# PC Sampling SSD Firmware Fuzzer v5.1

J-Link Halt-Sample-Resume 방식으로 커버리지를 수집하고,
`nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v5.1에서는 **PM(Power Management) 주입** 기능이 추가되어, 확률적으로 SSD를 저전력 상태(PS1~PS4)에 진입시킨 상태에서 NVMe 명령을 전달함으로써 PM 관련 펌웨어 경로를 탐색합니다.

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
sudo python3 pc_sampling_fuzzer_v5.1.py [옵션]
```

---

## 빠른 시작

### 기본 실행 (PM injection 15% 확률, 기본값)

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --output ./output/run_pm
```

기본 활성 명령어: `Identify`, `GetLogPage`, `GetFeatures`, `Read`, `Write`
기본 PM injection 확률: 15% (매 iteration마다 독립 시행)

---

### PM injection 비활성화

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --pm-inject-prob 0.0 \
  --output ./output/run_no_pm
```

---

### PM injection 100% (검증/디버깅용)

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
  --device Cortex-R8 \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --pm-inject-prob 1.0 \
  --output ./output/run_pm_always
```

모든 iteration에서 `[PM] SetFeatures cdw11=0x...` 로그가 출력됩니다.

---

### SWD 인터페이스 (idle 감지 비활성화 권장)

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
  --device Cortex-R8 \
  --interface swd \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x00147FFF \
  --saturation-limit 0 \
  --global-saturation-limit 20 \
  --output ./output/run_swd
```

---

### 펌웨어 포함 전체 명령어 실행

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
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

### 이전 세션에서 재개 (커버리지 이어받기)

```bash
sudo python3 pc_sampling_fuzzer_v5.1.py \
  --resume-coverage ./output/run_pm/coverage.txt \
  --seed-dir ./output/run_pm/corpus \
  --output ./output/run2
```

---

## PM injection 동작 원리

```
[일반 iteration]            [PM-wrapped iteration (확률: pm_inject_prob)]
  NVMe command 전송            _pm_set_state(random 1~4)   ← PS 진입 (silent)
  J-Link 샘플링                NVMe command 전송 + J-Link 샘플링
                               stop_sampling()
                               _pm_set_state(0)            ← PS0 복귀 (silent)
```

- PM enter/exit는 `SetFeatures(FID=0x02, CDW11=ps)` Admin 명령으로 전송
- J-Link 샘플링은 **메인 NVMe 명령** 구간에만 적용 (PM enter/exit는 샘플링 없음)
- PM 전송 실패 시 로그만 출력하고 퍼징 흐름에는 영향 없음
- `pm_inject_count` 통계가 세션 종료 시 출력됨

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
| `OUTPUT_DIR`    | `'./output/pc_sampling_v5.1/'` | 결과 저장 경로 |

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
| `--commands A B C` | 명시적으로 명령어 선택 |
| `--all-commands` | 파괴적 명령어 포함 전체 활성화 |

### v5.1 PM Injection 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--pm-inject-prob P` | `0.15` | PM 상태 주입 확률 (0.0=비활성화, 1.0=항상). iteration마다 독립 시행. |

### 펌웨어 다운로드 옵션 (v4.7)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--fw-bin PATH` | `None` | 펌웨어 바이너리 경로. 없으면 더미 1KB 시드 사용 |
| `--fw-xfer BYTES` | `32768` | FWDownload 청크 크기 |
| `--fw-slot N` | `1` | FWCommit 슬롯 번호 (1~7) |

### 타임아웃 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--timeout GROUP MS` | (각 그룹 기본값) | 그룹별 timeout 오버라이드 |
| `--passthru-timeout MS` | `2592000000` (30일) | nvme-cli `--timeout` 값 |
| `--kernel-timeout SEC` | `2592000` (30일) | nvme_core 모듈 타임아웃 |

### 샘플링 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--samples N` | `500` | 명령어 1회당 최대 PC 샘플 수 |
| `--interval US` | `0` | 샘플 간격 (마이크로초) |
| `--post-cmd-delay MS` | `0` | 명령 완료 후 추가 tail 샘플링 시간 |
| `--saturation-limit N` | `10` | per-run 수렴 감지 임계값. SWD에서는 `0` 권장 |
| `--global-saturation-limit N` | `20` | global 커버리지 대비 수렴 감지 임계값 |

### Mutation 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--random-gen-ratio R` | `0.2` | 완전 랜덤 입력 생성 비율 |
| `--opcode-mut-prob P` | `0.10` | Opcode 무작위 교체 확률 |
| `--nsid-mut-prob P` | `0.10` | Namespace ID 무작위 교체 확률 |
| `--admin-swap-prob P` | `0.05` | Admin↔IO 교차 전송 확률 |
| `--datalen-mut-prob P` | `0.08` | data_len↔CDW 의도적 불일치 확률 |
| `--exclude-opcodes HEX` | `''` | 제외할 opcode (쉼표 구분) |
| `--max-energy F` | `16.0` | Power Schedule 최대 에너지 |

### Calibration / Deterministic / MOpt 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--calibration-runs N` | `3` | 초기 시드당 calibration 반복 횟수 |
| `--no-deterministic` | `False` | Deterministic stage 비활성화 |
| `--det-arith-max N` | `10` | Deterministic arithmetic delta 최대값 |
| `--no-mopt` | `False` | MOpt mutation scheduling 비활성화 |
| `--mopt-pilot-period N` | `5000` | MOpt pilot 단계 실행 횟수 |
| `--mopt-core-period N` | `50000` | MOpt core 단계 실행 횟수 |

### 기타 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--speed KHZ` | `12000` | JTAG 속도 |
| `--seed-dir DIR` | `None` | 이전 corpus 디렉터리 |
| `--resume-coverage FILE` | `None` | 이전 세션 coverage.txt 경로 |

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
| `SetFeatures` | `0x09` | Admin | command | PM injection에서도 내부적으로 사용 |
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
output/pc_sampling_v5.1/
├── fuzzer_YYYYMMDD_HHMMSS.log   # 실행 로그
├── coverage.txt                  # 발견된 PC 주소 목록 (resume용)
├── corpus/
│   ├── seed_0000.bin
│   └── ...
├── crashes/
│   ├── crash_<md5>.json
│   ├── crash_<md5>.bin
│   └── crash_<md5>.dmesg.txt
├── cfg/
│   └── cfg_Read.dot
└── heatmap_<timestamp>.png
```

---

## 크래시 발생 후 처리

퍼저는 크래시(timeout) 감지 즉시 NVMe 드라이버를 unbind해 SSD 상태를 보존합니다.

### 1. 크래시 확인

```bash
ls ./output/pc_sampling_v5.1/crashes/
cat ./output/pc_sampling_v5.1/crashes/crash_<md5>.json
```

### 2. JTAG으로 펌웨어 상태 분석

```bash
(gdb) monitor halt
(gdb) info registers pc
(gdb) backtrace
```

### 3. 분석 완료 후 드라이버 재바인드

```bash
lspci | grep -i nvme
echo '0000:02:00.0' | sudo tee /sys/bus/pci/drivers/nvme/bind
```

### 4. SSD가 정상 복귀하지 않는 경우

```gdb
monitor reset run
```

---

## seed_replay_test.sh

퍼저 초기 시드를 실제 NVMe 명령어로 실행해 동작을 검증하는 스크립트입니다.

```bash
sudo ./seed_replay_test.sh /dev/nvme0 [FW.bin] [fw_xfer_size] [fw_slot]
```

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v5.1** | PM injection 추가: `--pm-inject-prob`로 SetFeatures(FID=0x02) silent 전송, 확률적 PS1~PS4 진입 후 메인 명령 실행, `pm_inject_count` 통계 |
| **v5.0** | `diagnose()` halt 빈도 감소, `_wait_nvme_live()` 실제 응답 확인, `GoEx(0,0)` 전면 교체, SMART-DIAG 코드 정리 |
| **v4.7** | FUA 비트 수정 (CDW12[14]→[29]), 컨트롤러 범위 명령 NSID=0, `--fw-bin/--fw-xfer/--fw-slot` 추가 |
| **v4.6** | io-passthru → namespace device, passthru timeout 분리, 크래시 시 nvme 드라이버 unbind |
| **v4.5** | Calibration, Deterministic stage, MOpt mutation scheduling |
| **v4.4** | Opcode→name 역방향 테이블, Heatmap 크기 제한, timeout 시 dmesg 캡처 |
| **v4.3** | Corpus culling, J-Link heartbeat, 랜덤 생성 비율, 확장 mutation 확률 |
| **v4.2** | subprocess + 샘플링 연동, 글로벌 기준 포화 판정, idle PC 감지 |
| **v4.1** | CDW2~CDW15 시드 필드, NVMe 스펙 기반 초기 시드 자동 생성 |
| **v4.0** | unique PC 기반 coverage signal, CFG/히트맵, AFLfast Power Schedule |
