# PC Sampling SSD Firmware Fuzzer v6.0

OpenOCD PCSR(PC Sampling Register) 방식으로 커버리지를 수집하고, `nvme-cli` subprocess를 통해 NVMe 명령어를 SSD에 전달하는 Coverage-Guided Fuzzer.

v6.0에서는 **J-Link halt-sample-resume → OpenOCD PCSR 비침습 샘플링** 전환 + **3코어(Core0/1/2) 동시 수집**.  
펌웨어를 중단하지 않으므로 NVMe DMA 타이밍 간섭 없음. `import pylink` 완전 제거.

---

## 목차

1. 요구사항
2. 빠른 시작
3. v6.0 변경사항 상세
4. 코드 상단 상수 설정
5. CLI 옵션
6. OpenOCD 설정 파일 (`r8_pcsr.cfg`)
7. Power Combo 동작 원리
8. 명령어 목록
9. 출력 디렉터리 구조
10. 크래시 발생 후 처리
11. 정적 분석 커버리지 연동
12. 버전 이력 요약

---

## 요구사항

```
Python 3.8+
openocd               # xPack OpenOCD 0.12.0+  (libjaylink 포함)
nvme-cli              # apt install nvme-cli
setpci                # apt install pciutils
J-Link V9 / EDU       # USB 동글 (SWD 물리 연결용, pylink 불필요)
```

xPack OpenOCD 설치 예시 (Linux x64):
```bash
tar -xf xpack-openocd-0.12.0-7-linux-x64.tar.gz -C /opt/
sudo ln -sf /opt/xpack-openocd-0.12.0-7/bin/openocd /usr/local/bin/openocd
```

실행 권한:
```bash
sudo python3 pc_sampling_fuzzer_v6.0.py [옵션]
```

파일 구성:
```
PC_Sampling/
├── pc_sampling_fuzzer_v6.0.py   # 메인 퍼저
├── nvme_seeds.py                # NVMe 명령 시드 템플릿
└── r8_pcsr.cfg                  # OpenOCD 설정 파일 (별도 준비)
```

---

## 빠른 시작

### 기본 실행

```bash
sudo python3 pc_sampling_fuzzer_v6.0.py \
  --nvme /dev/nvme0 \
  --addr-start 0x00000000 \
  --addr-end 0x003B7FFF \
  --output ./output/run_base
```

### OpenOCD 경로/설정 명시

```bash
sudo python3 pc_sampling_fuzzer_v6.0.py \
  --openocd-binary /opt/xpack-openocd-0.12.0-7/bin/openocd \
  --openocd-config /path/to/r8_pcsr.cfg \
  --nvme /dev/nvme0 \
  --output ./output/run_openocd
```

### Power Combo 활성화

```bash
sudo python3 pc_sampling_fuzzer_v6.0.py \
  --nvme /dev/nvme0 \
  --pm \
  --output ./output/run_pm
```

---

## v6.0 변경사항 상세

### [Arch] J-Link halt-sample-resume → OpenOCD PCSR 비침습 샘플링

기존 v5.x는 `JLINKARM_Halt()` → `ReadReg(PC)` → `JLINKARM_Go()` 루프로 Core 0만 샘플링했다.
이 방식의 문제:

- halt가 NVMe DMA 타이밍을 간섭 → SWD + 레벨시프터 환경에서 NVMe 커맨드 타임아웃 빈발
- Core 1/2 커버리지 완전 누락 (pylink는 DAP 멀티코어 전환 불가)
- 펌웨어 실행 흐름을 관찰자 효과로 왜곡

v6.0의 PCSR 방식:

- ARM CoreSight PCSR(PC Sampling Register) = CoreBase + 0x084 (APB-AP, ap-num 0)
- CPU 실행 중단 없이 현재 PC를 읽음 (비침습, Non-intrusive)
- OpenOCD가 APB-AP에 직접 접근하여 PCSR 읽기 수행
- `go_settle_ms` 파라미터 완전 제거 (halt 없으므로 settle 불필요)

| 항목 | v5.x (J-Link halt) | v6.0 (OpenOCD PCSR) |
|------|-------------------|---------------------|
| 펌웨어 영향 | halt로 DMA 간섭 | **없음** |
| 코어 수 | Core 0만 | **Core 0/1/2 동시** |
| pylink 의존 | 있음 | **없음** |
| 샘플링 속도 | ~200/s (halt 오버헤드) | ~1000/s (1 RTT = 3코어) |
| go_settle 설정 | 필요 (SWD 불안정 환경) | **불필요** |

---

### [Arch] 3코어 동시 수집

PCSR 주소:

| 코어 | CoreBase | PCSR 주소 |
|------|----------|-----------|
| Core 0 | `0x80030000` | `0x80030084` |
| Core 1 | `0x80032000` | `0x80032084` |
| Core 2 | `0x80034000` | `0x80034084` |

`_read_all_pcs()` 메서드가 1 RTT로 3코어를 배치 읽기 (OpenOCD `read_all_pcs` Tcl proc):

```tcl
proc read_all_pcs {} {
    set pc0 [lindex [r8.abp read_memory 0x80030084 32 1] 0]
    set pc1 [lindex [r8.abp read_memory 0x80032084 32 1] 0]
    set pc2 [lindex [r8.abp read_memory 0x80034084 32 1] 0]
    return "$pc0 $pc1 $pc2"
}
```

반환 타입: `Optional[Tuple[int, int, int]]`.

---

### [Arch] 튜플 단위 idle 포화 판정

`_sampling_worker()` 내 idle 판정 변경:

- **v5.x**: 단일 PC가 `idle_pcs` 집합에 있으면 idle 카운트
- **v6.0**: 튜플 내 in-range PC가 **모두** `idle_pcs`에 속할 때만 idle 카운트

이유: Core 1/2가 idle 상태여도 Core 0이 NVMe 처리 중이면 조기 종료를 막아야 함.

---

### [Arch] pylink 제거 → OpenOCD + libjaylink

`import pylink` 완전 제거. 대신:

- `subprocess.Popen([openocd, '-f', cfg])` 로 OpenOCD 실행
- raw socket으로 OpenOCD telnet(4444) 통신
- `_openocd_alive()` + `_reconnect()` 로 OpenOCD 크래시 자동 복구

J-Link USB 동글은 여전히 필요 (SWD 물리 연결). 단, pylink/libjlinkarm DLL 없이 동작.

---

### [Arch] OpenOCDPCSampler 클래스 구조

`JLinkPCSampler` → `OpenOCDPCSampler` 교체. **공개 인터페이스 동일**:

```
connect() → bool
diagnose(count) → bool
start_sampling()
stop_sampling() → int
evaluate_coverage() → Tuple[bool, int]
load_coverage(filepath) → int
save_coverage(output_dir)
read_stuck_pcs(count) → List[int]
close()
```

`NVMeFuzzer` 클래스는 **한 줄만 변경**: `self.sampler = OpenOCDPCSampler(config)`

---

## 코드 상단 상수 설정

| 상수 | 기본값 | 설명 |
|------|--------|------|
| `FW_ADDR_START` | `0x00000000` | 펌웨어 .text 시작 주소 |
| `FW_ADDR_END` | `0x003B7FFF` | 펌웨어 .text 끝 주소 |
| `OPENOCD_BINARY` | `'openocd'` | OpenOCD 바이너리 경로 |
| `OPENOCD_CONFIG` | `'r8_pcsr.cfg'` | OpenOCD 설정 파일 (퍼저 디렉토리 기준) |
| `OPENOCD_TELNET_HOST` | `'127.0.0.1'` | OpenOCD telnet 호스트 |
| `OPENOCD_TELNET_PORT` | `4444` | OpenOCD telnet 포트 |
| `OPENOCD_STARTUP_TIMEOUT` | `10.0` | OpenOCD 시작 대기 타임아웃 (초) |
| `PCSR_CORE0` | `0x80030084` | Core 0 PCSR 주소 |
| `PCSR_CORE1` | `0x80032084` | Core 1 PCSR 주소 |
| `PCSR_CORE2` | `0x80034084` | Core 2 PCSR 주소 |
| `PCSR_POWER_ADDR` | `0x30313f30` | 디버그 전원 레지스터 (AXI-AP) |
| `PCSR_POWER_MASK` | `0x00010101` | Core0=bit0, Core1=bit8, Core2=bit16 |
| `L1_SETTLE` | `0.05` | PCIe L1 settle (초) |
| `L1_2_SETTLE` | `0.05` | PCIe L1.2 추가 settle (초) |
| `IDLE_WINDOW_SIZE` | `30` | window-ratio 윈도우 크기 |
| `IDLE_RATIO_THRESH` | `0.80` | idle 비율 임계값 |
| `SATURATION_LIMIT` | `10` | 연속 idle 카운터 임계값 |
| `GLOBAL_SATURATION_LIMIT` | `20` | 연속 알려진 PC 임계값 |
| `MAX_SAMPLES_PER_RUN` | `500` | 실행당 최대 샘플 수 |
| `CALIBRATION_RUNS` | `3` | 시드당 calibration 반복 횟수 |
| `FW_BIN_FILENAME` | `None` | FWDownload용 펌웨어 파일명 |
| `GRAPH_REFRESH_INTERVAL` | `5000` | 주기 그래프 갱신 간격 (executions 단위) |

값 변경 시 스크립트 상단 상수 블록을 직접 수정.

---

## CLI 옵션

```
--openocd-binary PATH    OpenOCD 바이너리 경로 (기본: openocd)
--openocd-config PATH    OpenOCD 설정 파일 경로 (기본: r8_pcsr.cfg)
--openocd-host HOST      OpenOCD telnet 호스트 (기본: 127.0.0.1)
--openocd-port PORT      OpenOCD telnet 포트 (기본: 4444)
--openocd-timeout SEC    OpenOCD 시작 대기 타임아웃 (기본: 10.0)

--nvme DEVICE            NVMe 장치 경로 (기본: /dev/nvme0)
--namespace N            NVMe 네임스페이스 ID (기본: 1)
--lba-size N             NVMe LBA 크기(바이트). 0=자동 감지 (기본: 0)
--addr-start HEX         펌웨어 .text 시작 주소
--addr-end HEX           펌웨어 .text 끝 주소
--output DIR             출력 디렉터리
--runtime SEC            퍼징 총 실행 시간 (기본: 604800 = 1주)
--pm                     Power Combo 활성화 (NVMe PS + PCIe L/D-state)
--samples N              실행당 최대 샘플 수 (기본: 500)
--interval US            샘플 간격 µs (기본: 0 = 최대 밀도)
--diagnose-sleep-ms MS   diagnose() 샘플 간격 ms (기본: 10)
--diagnose-stability N   idle 수렴 연속 횟수 (기본: 100)
--diagnose-max N         최대 샘플 수 (기본: 5000)
--calibration-runs N     시드당 calibration 반복 횟수 (기본: 3)
--exclude-opcodes A,B,...  제외할 opcode (hex). 예: "0xC1,0xC0"
--random-gen-ratio F     랜덤 생성 비율 (기본: 0.2)
--admin-swap-prob F      admin↔IO 교체 확률 (기본: 0.05)
--fw-bin PATH            FWDownload용 펌웨어 바이너리 경로
--fw-xfer BYTES          FWDownload 청크 크기 (기본: 32768)
--fw-slot N              FWCommit 슬롯 번호 (기본: 1)
--passthru-timeout MS    nvme-cli --timeout 값 (기본: 30일)
--kernel-timeout SEC     nvme_core 모듈 타임아웃 (기본: 30일)
--timeout GROUP MS       명령 그룹별 타임아웃 설정 (예: command 18000)
--post-cmd-delay MS      명령 후 추가 대기 (기본: 0)
--seed-dir DIR           초기 시드 디렉터리
--resume-coverage FILE   이전 coverage.txt 경로
--commands CMD ...       활성화할 명령어 목록
--all-commands           위험 명령어 포함 전체 활성화
```

> v5.6 대비 제거된 인자: `--device`, `--interface`, `--speed`, `--pc-reg-index`, `--go-settle`
>
> v6.0 추가 인자: `--openocd-binary`, `--openocd-config`, `--openocd-host`, `--openocd-port`, `--openocd-timeout`

---

## OpenOCD 설정 파일 (`r8_pcsr.cfg`)

퍼저 스크립트와 같은 디렉토리에 아래 내용으로 `r8_pcsr.cfg`를 준비한다.  
(`--openocd-config` 옵션으로 다른 경로 지정 가능)

```tcl
adapter driver jlink
adapter speed 4000
transport select swd
reset_config none
swd newdap r8 cpu -enable
dap create r8.dap -chain-position r8.cpu
target create r8.abp mem_ap -dap r8.dap -ap-num 0
target create r8.axi mem_ap -dap r8.dap -ap-num 1
init
```

> `r8.abp`: APB-AP (ap-num 0) — PCSR, 디버그 레지스터 접근  
> `r8.axi`: AXI-AP (ap-num 1) — 시스템 메모리, 전원 레지스터 접근

OpenOCD 단독 동작 확인:
```bash
openocd -f r8_pcsr.cfg
# 출력 예:
# SWD DPIDR 0x6ba02477
# [r8.abp] Examination succeeded
# [r8.axi] Examination succeeded
```

---

## Power Combo 동작 원리

`--pm` 활성화 시 30개 조합(PS0~4 × L0/L1/L1.2 × D0/D3hot) 랜덤 전환.

- `PM_ROTATE_INTERVAL`(기본 100)회 exec마다 combo 전환
- Non-Operational 상태(PS3/4, D3hot) 진입 시 NVMe 명령 전 강제 복귀
- PM coverage는 global_coverage에만 반영 (corpus 오염 방지)
- preflight: 30개 combo 모두 검증 (~21초)
- calibration 완료 후 APST 재비활성화로 자율 PS 전환 간섭 제거

---

## 명령어 목록

### 기본 명령어 (`NVME_COMMANDS_DEFAULT`)

| 명령 | Opcode | 비고 |
|------|--------|------|
| Identify | 0x06 | — |
| GetLogPage | 0x02 | — |
| GetFeatures | 0x0A | — |
| SetFeatures | 0x09 | weight=1 |
| Read | 0x02 (IO) | weight=2 |
| Write | 0x01 (IO) | weight=2 |

### 확장 명령어 (`--all-commands` 또는 `--commands`로 활성화)

FWDownload, FWCommit, FormatNVM\*, Sanitize\*, TelemetryHostInitiated, Flush,
DatasetManagement, WriteZeroes, Compare, WriteUncorrectable, Verify,
DeviceSelfTest, SecuritySend, SecurityReceive, GetLBAStatus

\* FormatNVM: SES=0(비파괴) 1개만. Sanitize: SANACT=4(Exit Failure) 1개만.

---

## 출력 디렉터리 구조

```
output/pc_sampling_v6.0/
├── fuzzer_YYYYMMDD_HHMMSS.log
├── coverage.txt
├── corpus/
│   └── seed_NNNN.bin
├── crashes/
│   ├── crash_<cmd>_<opcode>_<md5>
│   ├── crash_<cmd>_<opcode>_<md5>.json
│   ├── crash_<cmd>_<opcode>_<md5>.dmesg.txt
│   ├── replay_<tag>.sh
│   └── replay_data_<tag>/
│       └── data_NNN.bin
└── graphs/
    ├── command_comparison.png
    ├── mutation_chart.png
    ├── coverage_heatmap_1d.png
    ├── edge_heatmap_2d.png
    ├── {cmd}_cfg.dot/.png
    ├── coverage_growth.png       (* Ghidra 연동 시)
    ├── firmware_map.png          (* Ghidra 연동 시)
    └── uncovered_funcs.png       (* Ghidra 연동 시)
```

---

## 크래시 발생 후 처리

1. stuck PC 읽기 (`read_stuck_pcs()` — PCSR 반복, halt 없음)
2. dmesg 캡처
3. FAIL CMD 상세 출력 (cmd/opcode/nsid/cdw2~15/data/mutations)
4. crash 파일 저장 (.bin / .json / .dmesg.txt)
5. replay .sh 자동 생성 (setpci 포함, sudo bash로 즉시 재현 가능)
6. UFAS 펌웨어 덤프 (`./ufas` 존재 시)
7. NVMe 드라이버 unbind (`/sys/bus/pci/drivers/nvme/unbind`)

재연결:
```bash
echo '<BDF>' > /sys/bus/pci/drivers/nvme/bind
```

---

## 정적 분석 커버리지 연동

퍼저와 같은 디렉터리에 `basic_blocks.txt` / `functions.txt` (Ghidra `ghidra_export.py` 생성)를 두면 자동 로드.

```
[StatCov] BB: 12.3% (4567/37120) | funcs: 234/1820 (12.9%)
```

그래프 3종 자동 생성:
- `coverage_growth.png` : BB_cov% / funcs_cov% 성장 곡선 + 상단 wall-clock time 이중 X축
- `firmware_map.png` : 함수 공간 전체 맵 (커버=초록 / 미커버=회색)
- `uncovered_funcs.png` : 미커버(빨강) + 부분 커버(주황) 함수 Top-25 × 2

> v6.0 커버리지 향상: 3코어 동시 수집으로 Core 1/2 코드 경로까지 포함.  
> 특히 NVMe 인터럽트 핸들러(Core 1)와 DMA 엔진(Core 2) 코드 커버리지가 v5.x 대비 대폭 증가 예상.

---

## 버전 이력 요약

| 버전 | 주요 변경 |
|------|-----------|
| **v6.0** | **OpenOCD PCSR 비침습 샘플링**, **3코어 동시 수집(Core0/1/2)**, **pylink 제거**, OpenOCDPCSampler, 튜플 단위 idle 포화 판정, OpenOCD 자동 재시작 |
| v5.6 | 시각화 개선: coverage_growth 이중 X축, command_comparison RC 오류율 4번째 subplot, uncovered_funcs 부분커버 구분, 1D 히트맵 컬러바, mutation_chart 신규, 주기 갱신 |
| v5.5 | 시드 템플릿 분리(nvme_seeds.py), CLI 인자 정리, FWDownload 32KB 기본값 |
| v5.4 | SetFeatures 기본 승격, APST calibration 버그 수정, SetFeatures NSID 수정, LBA 자동 감지 |
| v5.3 | idle 시간 최적화: L1_SETTLE 0.05s, DIAGNOSE_SAMPLE_MS=10ms, window-ratio 조기 감지 |
| v5.2 | Power Combo (NVMe PS + PCIe L/D-state 30개 조합), APST/Keep-Alive 자동 비활성화 |
| v5.1 | PM Rotation(`--pm`), Basic Block 커버리지(Ghidra), 시각화 그래프 3종 |
| v5.0 | J-Link JTAG/SWD auto-detect, diagnose() 수렴 기반 idle 유니버스 수집 |
| v4.7 | FUA 비트 수정(CDW12[29]), FWDownload `--fw-bin` |
| v4.6 | passthru timeout 분리, crash 시 nvme driver unbind |
| v4.5 | Calibration, Deterministic stage, MOpt mutation scheduling |
