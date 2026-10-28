# v11.5 — [Device Info] 추가 항목과 [QTMGR] 보고

설정: `fuzzer_config.json` 최상위 `qtmgr`. 잘못된 값은 시작 시 `[FATAL]`.

## [Device Info] (시작 시 + 주기 재출력)
태그가 `[DevInfo]` → `[Device Info]`. `Model`·`Serial` 다음에 아래 줄, 그 뒤에 기존 줄(Firmware ~ PCIe)이 이어진다.

| 줄 | 값 |
|---|---|
| `Density` | `eDensity_<공칭>` — NSZE × LBA 크기(사용자 용량)를 가장 가까운 공칭 용량(16GB~128TB)으로. 예: 1,000,215,216 × 512B → `eDensity_512GB`, 3,907,029,168 × 512B → `eDensity_2TB` |
| `FW Revision` | id-ctrl FR |
| `Application` | `e` + `qtmgr.application` (기본 `ePC`) |
| `CTRL` | `e` + `qtmgr.ctrl[제품 계열]` — BM9K1 `ePALAU`, PM9M1 `eSM2504XT`, BM9H1 `eSM2269XT`, P7·P9 `ePS2251_U21` |
| `FormFactor` | `e` + `qtmgr.form_factor` (기본 `eM_2`) |
| `OEM` | 제품명이 `<계열>_<OEM>` 이면 `e<OEM>`(`PM9M1_HP` → `eHP`, `BM9K1_LENOVO` → `eLENOVO`), 아니면 `eBRAND` |
| `RBUF` | VU 명령 2개 응답 앞 8바이트를 글자 그대로(예 `10282026`). 실패하면 빈칸 |

제품 계열 = `products.<제품>.family`(생략 시 제품명). PM9M1·PM9M1_LENOVO·PM9M1_HP 는 `PM9M1`, BM9K1 계열은 `BM9K1`.

### RBUF VU 명령 (`qtmgr.rbuf`)
**시작 시 첫 Device Info 에서 한 번만** 보내고, 주기 재출력·[QTMGR] 는 그 값을 다시 쓴다. 모든 제품에 보낸다.
```
nvme admin-passthru /dev/nvmeN --opcode=0xc1 --cdw10=0x4 --cdw12=0x1 --data-len=16 --timeout=30000 --input-file=<퍼저 폴더>/sig2.bin -w
nvme admin-passthru /dev/nvmeN --opcode=0xc2 --cdw10=0x4 --cdw12=0x23000003 --data-len=512 --timeout=30000 -r -b
```
- `sig2.bin` 은 퍼저 실행 파일과 같은 폴더에 둔다(`sig_file` 상대경로 기준). 없으면 명령을 보내지 않고 빈칸.
- 둘째 명령 응답(raw)의 앞 `chars`(8) 바이트가 출력 가능한 글자가 아니면 빈칸(경고에 hex).
- 퍼징 송신 경로(가드·cmd#·회계)를 거치지 않는 시작 시 보조 명령이다.

## [QTMGR] (캠페인 끝, 1회)
- crash(timeout·FW hang·PM preflight 실패·예외 주입 보존)면 **덤프와 crash 폴더 수집이 끝난 직후**(PC 모니터링 전).
- crash 없이 끝나면(시간 종료·Ctrl+C) 종료 요약·차트 뒤. Dmesg/UFAS Path 는 `N/A`.

| 줄 | 값 |
|---|---|
| Tester | `qtmgr.tester` (기본 `TestPC01`) — PC 마다 json 에서 바꾼다 |
| Slot | 메인보드가 주는 물리 슬롯 번호(`/sys/bus/pci/slots`), 없으면 PCIe BDF |
| Test Case | `--pm` 없으면 `Fuzzing`, 있으면 `Fuzzing with PM` |
| Product | `e` + 제품 계열 (`ePM9M1`, `eBM9K1`, `eBM9H1`, `eP7`, `eP9`) |
| OEM | 위 OEM 에서 `e` 없이 (`HP`, `LENOVO`, `BRAND`) |
| Density | `512 GB`, `1 TB` 형식 |
| Form Factor | `M_2` |
| FW Rev / FW Build / MN / SN | Device Info 의 FR / RBUF / Model / Serial |
| TTF | 퍼징 시작부터 — 60분 미만 `45 min`, 이상 `3.2 hours` |
| Temp ('C) | 마지막 `nvme smart-log` temperature(°C). 없으면 `N/A` |
| Chamber ('C) | `qtmgr.chamber` (기본 `Not Chamber`) |
| Dmesg Path | crash 폴더의 `dmesg_*.txt` 전부(절대경로) |
| UFAS Path | 그 crash 의 UFAS·JLINK·RDDump 덤프가 crash 폴더에 남긴 파일(도구 출력 .log 제외). 한 덤프가 10개 넘게 만들면 폴더 |

## 제품 이름 변경
`PM9M1_LNB` → `PM9M1_LENOVO`. json 키가 바뀌어 **v11.4 이하에서 `--product PM9M1_LNB` 는 더 이상 쓸 수 없다**(`PM9M1` 과 같은 프로필이므로 `PM9M1` 또는 v11.5 `PM9M1_LENOVO`).
