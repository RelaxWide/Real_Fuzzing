# v11.5 — [Device Info] 추가 항목과 [QTMGR] 보고

설정: `fuzzer_config.json` 최상위 `qtmgr`. 잘못된 값은 시작 시 `[FATAL]`.

## [Device Info] (시작 시 + 주기 재출력)
태그가 `[DevInfo]` → `[Device Info]`. `Model`·`Serial` 다음에 아래 줄, 그 뒤에 기존 줄(Vendor ID ~ PCIe)이 이어진다. FW 는 `FW Revision` 한 줄만(기존 `Firmware` 줄 제거).

| 줄 | 값 |
|---|---|
| `Density` | `eDensity_<공칭>` — NSZE × LBA 크기(사용자 용량)를 가장 가까운 공칭 용량(16GB~128TB)으로. 예: 1,000,215,216 × 512B → `eDensity_512GB`, 3,907,029,168 × 512B → `eDensity_2TB` |
| `FW Revision` | id-ctrl FR |
| `Application` | `e` + `qtmgr.application` (기본 `ePC`) |
| `CTRL` | `e` + `qtmgr.ctrl[제품 계열]` — BM9K1 `ePALAU`, PM9M1 `eSM2504XT`, BM9H1 `eSM2269XT`, P7·P9 `ePS2251_U21` |
| `FormFactor` | `e` + `qtmgr.form_factor` (기본 `eM_2`) |
| `OEM` | 제품명이 `<계열>_<OEM>` 이면 `e<OEM>`(`PM9M1_HP` → `eHP`, `BM9K1_LENOVO` → `eLENOVO`), 아니면 `eBRAND` |
| `RBUF` | VU 명령 2개 응답 버퍼 앞 8자리 hex(예 `10 23 20 26 …`(MMDD YYYY) → 연도를 앞으로 `20261023`, YYYYMMDD). 실패하면 빈칸 |

제품 계열 = `products.<제품>.family`(생략 시 제품명). PM9M1·PM9M1_LENOVO·PM9M1_HP 는 `PM9M1`, BM9K1 계열은 `BM9K1`.

### RBUF VU 명령 (`qtmgr.rbuf`)
**시작 시 첫 Device Info 에서 한 번만** 보내고, 주기 재출력·[QTMGR] 는 그 값을 다시 쓴다. 모든 제품에 보낸다.
```
nvme admin-passthru /dev/nvmeN --opcode=0xc1 --cdw10=0x4 --cdw12=0x1 --data-len=16 --timeout=30000 --input-file=<퍼저 폴더>/sig2.bin -w
nvme admin-passthru /dev/nvmeN --opcode=0xc2 --cdw10=0x4 --cdw12=0x23000003 --data-len=512 --timeout=30000 -r -b
```
- `sig2.bin` 은 퍼저 실행 파일과 같은 폴더에 둔다(`sig_file` 상대경로 기준). 없으면 명령을 보내지 않고 빈칸.
- 둘째 명령 응답(raw) 앞 `digits`(8)자리 = 앞 4바이트 hex. 값이 바이트당 숫자 두 자리(BCD)라 글자로 읽지 않는다. 버퍼 순서 MMDD YYYY 를 YYYYMMDD 로 바꿔 찍는다.
- 퍼징 송신 경로(가드·cmd#·회계)를 거치지 않는 시작 시 보조 명령이다. 시간 초과(timeout_ms+5s)면 nvme-cli 종료를 기다리지 않고 빈칸(D-state 대비).

## [QTMGR] (캠페인 끝, 1회)
- crash(timeout·FW hang·PM preflight 실패·예외 주입 보존)면 **덤프가 끝난 뒤, 로그를 crash 폴더로 복사하기 전** —
  crash 폴더의 로그 사본에 보고가 들어간다(PC 모니터링 전).
- crash 없이 끝나면(시간 종료·Ctrl+C) 종료 요약·차트 뒤. Dmesg/UFAS Path 는 `N/A`.

| 줄 | 값 |
|---|---|
| Tester | `qtmgr.tester` (기본 `RS0000-0`, 형식 `RS\d{4}-\d+`) — PC 마다 json 에서 바꾼다 |
| Slot | `qtmgr.slot` (기본 `0`, 숫자) — 로그 첫 줄 SLOT 과 같은 값 |
| Test Case | `--pm` 없으면 `Fuzzing`, 있으면 `Fuzzing with PM` |
| Product | `e` + 제품 계열 (`ePM9M1`, `eBM9K1`, `eBM9H1`, `eP7`, `eP9`) |
| OEM | 위 OEM 에서 `e` 없이 (`HP`, `LENOVO`, `BRAND`) |
| Density | `512 GB`, `1 TB` 형식 |
| Form Factor | `M_2` |
| FW Rev / FW Build / MN / SN | Device Info 의 FR / RBUF / Model / Serial |
| TTF | 퍼징 시작부터 장애 감지 시각(crash) 또는 종료 시작 시각까지 — 덤프·차트 시간 제외. 60분 미만 `45 min`, 이상 `3.2 hours` |
| Temp ('C) | 마지막 `nvme smart-log` temperature(°C). 없으면 `N/A` |
| Chamber ('C) | `qtmgr.chamber` (기본 `Not Chamber`) |
| Dmesg Path | crash 폴더의 `dmesg_<ts>_at_crash.txt`(절대경로) |
| UFAS Path | 그 crash 의 UFAS·JLINK·RDDump 덤프가 crash 폴더에 남긴 파일(도구 출력 .log 제외). 한 덤프가 10개 넘게 만들면 폴더 |

## 제품 이름 변경
`PM9M1_LNB` → `PM9M1_LENOVO`. json 키가 바뀌어 **v11.4 이하에서 `--product PM9M1_LNB` 는 더 이상 쓸 수 없다**(`PM9M1` 과 같은 프로필이므로 `PM9M1` 또는 v11.5 `PM9M1_LENOVO`).

## crash 폴더 정리 (v11.5)
- dmesg 는 덤프 전 선저장한 `dmesg_<ts>_at_crash.txt` 하나만 남긴다(덤프 후 `dmesg_<ts>.txt` 는 만들지 않는다).
- `crash_<명령>_<opcode>_<hash>.json` 은 crash 폴더에 넣지 않는다(쓰지 않는 파일) — `crashes/` 루트에만 남는다.

## 로그 파일 (v11.5)
- 이름: `output/fuzzer_<YYYYmmdd_HHMMSS>_log.txt` (예전 `fuzzer_<ts>.log`). LLM 전용 로그 `output/llm/llm_<ts>.log` 는 그대로.
- 첫 줄: `[<타임스탬프>] [INFO] [ TEST LOCATION : { TESTER:RS0000-0, BOARD:0, SLOT:0, PORT:0 } ]` — json `qtmgr.tester/board/slot/port`.
  사내 로그 파서가 정규식에 맞는 값만 받는다: TESTER `RS\d{4}-\d+`, BOARD `\d+`, SLOT `\d+`. 맞지 않으면 시작 시 `[FATAL]`.
- 둘째·셋째 줄: `[<타임스탬프>] [INFO] CONFIG FILE : Fuzzer.json`, `[<타임스탬프>] [INFO] PROJECT : PC_NVME_` — json `qtmgr.config_file/project`(보고용 값, 실제 설정 파일은 fuzzer_config.json).
- 모든 줄의 타임스탬프를 `[]` 로 감싼다(파일·LLM 로그·터미널): `[2026-10-28 18:53:51.502] [WARNING] …`.
