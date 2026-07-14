# PC Sampling SSD Firmware Fuzzer v8.7

OpenOCD PCSR 비침습 샘플링 + `nvme-cli` passthru 기반 Coverage-Guided + State-Aware Fuzzer.

> v8.7 = v8.6 기능 전체 보존 **− PCSR always-on 계측(완전 제거)**. always-on(세션 내내 연속
> PCSR 폴링)이 **host OS freeze 와 연관**됨이 확인되어 제거하고, **windowed(명령마다 start/stop)
> 단일 경로**로 복귀. 옵션 입력 불필요(`--no-always-on` 도 제거). v8.6 의 진단/안전/옵션 기능
> (vmon · 그래프 fork 격리 · `--ignore-opcodes` · `--no-erase` · status SCT/SC)은 모두 유지.

---

## v8.7 핵심: PCSR always-on 제거 → windowed 단일 경로

### 왜 제거했나 (host OS freeze)
긴 캠페인 중 **Ubuntu 가 통째로 freeze**(dmesg: `alloc_vmap_area` non-canonical GPF +
`vmap_area_lock` soft-lockup, `Comm: Python3`)되는 현상이 **v8.4(windowed)에선 없고 always-on
도입 후 발생**. PCSR 은 SSD 코어를 halt 안 하는 "비침습"이지만, **그 한 번의 읽기도 호스트의
OpenOCD telnet·USB 디버그 스택을 동작**시킨다("비침습"은 *SSD* 기준이지 *호스트* 기준이 아님).
always-on 은 이 디버그 트래픽을 **명령 사이에도 세션 내내 연속**으로 만들어 host 부하를 상시화 →
freeze 와 연관. (USB→vmalloc 메커니즘은 미확정이나, "v8.4 OK, always-on freeze" 가 always-on 을
직접 지목.) → 비침습이라도 안전하지 않다고 판단, **always-on 을 제거**.

### 무엇이 바뀌었나
- **windowed(v8.4 방식)가 유일 동작**: 명령마다 `start_sampling`(샘플 스레드 1개 생성) →
  명령 실행 중 PCSR 샘플 → `stop_sampling`(스레드 종료). **명령 사이엔 OpenOCD/USB idle.**
  per-command 신규 판정은 `evaluate_coverage`(`current_trace − global_coverage`). 기존과 동일.
- **제거된 심볼**: `_sampling_worker_always_on` / `_fold_bg` / `_bg_pcs` / `_win_active` /
  `_prefill_active` / `_prefill_pcs` / `_ensure_worker` / `begin_prefill` / `end_prefill` /
  `--no-always-on` CLI + `no_always_on` config / `save_coverage` 의 `_fold_bg` 호출.
- **start_sampling/stop_sampling 은 v8.4 와 byte-동일**(검증: `diff` 차이 0).
- **prefill 샘플링은 v8.4 `_pf_sampler`(유한 구간 전용 스레드) 방식으로 복원**. prefill 은 시작 시
  1회·유한 구간이라 별도 reader 스레드를 잠깐 띄워도 host 부하 누적이 없다(세션 내내 도는
  always-on 과 무관). 수집 PC 는 기존대로 **static BB/func 에만** 반영(guidance global 제외).
- `_stop_worker` 는 **windowed sample_thread 정지용으로 단순화 유지** → POR/reconnect 직전 소켓
  경합 방지(NullSampler no-op 짝과 함께 호출부 호환).

### 영향
- **샘플링은 SSD 비침습(PCSR) 그대로** — SSD 동작/커버리지 측정 방식 불변.
- always-on 이 노렸던 "명령 사이 백그라운드 FW 활동 커버리지"는 포기하나, 그 정보 대부분은 명령
  실행 중 샘플링으로도 잡히고, **host freeze 위험 제거가 우선**.
- halt/jlink_halt/null 샘플러는 원래 windowed 라 영향 없음.

---

## v8.6 기능 (v8.7 에 유지): 차트 fork 격리 + vmalloc/taint 진단

### 주기 matplotlib 차트 → fork 자식 격리 (python3 segfault 차단)
PM9M1 장시간 런에서 `GRAPH_REFRESH_INTERVAL`(5000) exec 마다 5종 matplotlib(C 확장) 차트를 메인
루프에서 반복 생성 → 인터프리터 힙 손상 → **python3 segfault(core dumped, device 정상)** 로 fuzzer
가 죽던 문제.
- `_generate_graphs_isolated()`: `os.fork()` 자식이 **COW 로 self 상태 전체를 받아** 차트만 그리고
  `os._exit` → matplotlib/numpy 가 죽어도 **부모(fuzzer) 생존**(데이터 직렬화 불필요).
- `_reap_graph_child()`: 자식 회수 + **시그널 종료(SIGSEGV/SIGABRT) 시 `[Graph] ⚠️` 경고 로그**.
  논블로킹(이전 자식 살아있으면 이번 주기 skip), 종료 시 block 회수(좀비 방지).
- `_warm_matplotlib()`: 부모에서 1회 선import → fork 자식 import 락 회피. Py3.7+ 의 fork 시
  logging/import 락 자동 재초기화와 함께 멀티스레드 fork 데드락 위험 최소화. fork 실패 시 인프로세스 폴백.

### vmalloc/메모리 + kernel taint 진단 (vmon)
host freeze 원인 구분용 순수 진단(/proc 읽기만 — 디바이스/프로브/커버리지 무영향).
- `_read_kernel_taint()` / `_read_tainted_modules()`: `/proc/sys/kernel/tainted` 디코드 +
  `/proc/modules` 의 O/P/E/F taint 모듈 → out-of-tree 모듈(ZFS·J-Link 등) 특정.
- `_vmon_sample()`: **메인 루프에서 `VMON_EXEC_INTERVAL`(10000) exec 마다** `/proc/meminfo` 의
  `VmallocUsed` 추세(계단식 상승=고갈 vs 평탄→급사=손상) + Slab/PageTables/MemAvail 로깅, taint
  변화 감지. **백그라운드 스레드 아님**(동시성/소켓 경합 0). **`/proc/vmallocinfo` 는 `vmap_area_lock`
  을 잡으므로 절대 미접근**(meminfo 만).
- **`[VMon]` 은 파일 로그 전용**(터미널 미노출). `[Taint]`(시작/taint 변화)는 중요하므로 터미널 노출.
- `--no-vmon` 으로 비활성.

> 진단으로 밝혀진 것(현장): freeze 시 `VmallocUsed` 는 평탄(고갈 아님 = 손상) · `Tainted: P O` =
> ZFS 모듈(단 풀 미사용·스택에 ZFS 프레임 없음 → 코어 커널 vmalloc 버그와 동급 후보) · kdump 는
> 이 락-데드락 유형을 못 잡음(자동 재부팅 안 됨) → netconsole/화면영상이 확실한 캡처 수단.

---
## v8.5 핵심: PCSR always-on 계측  *(⚠️ v8.7 에서 제거됨 — host freeze 연관. 아래는 이력)*

기존(v8.4)은 명령마다 샘플링 스레드를 start/stop 하는 **윈도우 모델**이라 ① 명령 사이(mutation·
scheduling·state-monitor·IO-WL·PM 전환) ② 조기 포화로 끊긴 명령 후반 의 백그라운드 FW 활동
(GC·housekeeping·인터럽트)을 놓쳤다. v8.5는 **비침습(PCSR)일 때만** 상시 워커 1개로 전환한다.

- **상시 워커 1개**(`_sampling_worker_always_on`)가 세션 내내 가동:
  - 윈도우 활성(`_win_active`, 명령 실행 구간) → `current_trace`(per-command attribution).
  - 윈도우 비활성(명령 사이) → 신규 PC를 `_bg_pcs`(워커 전용 set)에 누적 → total coverage 에 포함.
  - 조기 포화 종료 없음 → 윈도우 길이는 명령 지속시간으로 자연 결정(후반 활동도 포착).
- **per-command 신규 판정은 그대로**: `evaluate_coverage()`의 `current_trace − global_coverage`.
  윈도우 중엔 워커가 `global_coverage`를 안 건드리므로 diff 정확. 명령 사이 백그라운드가 발견한 PC는
  어느 명령의 크레딧에도 안 잡혀(= total↑, per-command 판정은 깨끗).
- **락-free**: 워커는 `global_coverage`를 **mutate 하지 않고 멤버십 read 만** 한다. `_bg_pcs`는 메인
  스레드가 `_fold_bg()`(참조 재할당 스냅샷→union)로 안전하게 `global_coverage`에 합친다
  (`start_sampling`/`save_coverage` 시점). → 워커/메인 set 동시변경 경합 원천 차단.
- **POR/reconnect 경합 방지**: `_stop_worker()`를 `_reinit_target`/`_reconnect`/`_power_cycle_ssd`/
  `_recover_after_unsupported_skip`/`_handle_timeout_crash`에서 호출 → 디버그 소켓을 만지기 전 워커 정지.
  복구 후 다음 명령의 `start_sampling`이 lazy-재가동(`_ensure_worker`). 연속 read 실패 시 워커가
  `openocd_error` set 후 자가 종료 → 다음 명령에서 재가동.
- **분기 기준**: `_always_on = (config.sampler_type == 'pcsr')`. halt/jlink_halt/null 은 기존 윈도우
  모델 그대로(코어 halt가 명령을 굶기지 않게).

### prefill 샘플링 통합 (둘째 소켓 reader 제거)
`--prefill` 중 별도 샘플 스레드를 두면 always-on 워커와 **같은 telnet 소켓을 동시 read**해
`[OpenOCD] 파싱 실패 (read_all_pcs echo 섞임)` 충돌이 났다. → 소켓 reader 는 상시 워커 1개만 유지하고,
워커에 prefill 모드(`_prefill_active`)를 둬 그 구간 PC를 `_prefill_pcs` 버킷에 모은다. `_prefill_drive`는
`begin_prefill()`/`end_prefill()`만 호출, 수집분은 종료 후 **static BB/func 에만** 반영
(guidance `global_coverage` 제외 — fuzzing이 GC 경로 재도달 시 new-PC 크레딧 유지, `idle_pcs`와 동일 정책).

## v8.5 신규 옵션

### `--ignore-opcodes` (denylist, timeout 무시)
지정 opcode가 **timeout(hang)** 나면 크래시로 안 치고 POR 복구 후 계속(`_recover_after_unsupported_skip`
재사용). `_handle_timeout_crash` 진입 시 **repro 게이트보다 먼저** 검사. `actual_opcode`(변이 후 실제
전송 opcode) 기준. status-code 실패는 원래 크래시 아님 → 무관. `repro-opcode`(allowlist)의 정반대.
용도: 알려진 hang opcode 하나만 흘려보내고 나머지는 정상 크래시 헌팅. (자주 timeout 나면 매번 POR라
처리량 저하 → 대량은 `--exclude-opcodes`가 효율적.)

### `--no-erase` + `excluded_opcodes` 누수 수정 (전체 소거 차단, 데이터 보존)
**문제**: `--exclude-opcodes`가 명령 선택 풀(`self.commands`)과 초기 Format/Sanitize one-shot을 막지
못해, `--all-commands` 시 (1) 시작 시 FormatNVM 1회로 데이터 전체 소거 (2) 메인 루프 random_gen이
Format/Sanitize 선택 가능 → 데이터 보존 불가였다.
- **누수 수정**: `excluded_opcodes`가 이제 `base→self.commands`까지 필터 → random_gen 선택 차단 +
  초기 one-shot 게이트(`any(name=='FormatNVM' in self.commands)`) 자동 False → 1회 리셋 스킵. (시드
  생성·opcode 변이는 이미 excluded 존중.) 빈 풀 방지 가드 포함. → `--exclude-opcodes`가 전 경로 차단.
- **`--no-erase`**: 전체 소거 명령 FormatNVM(0x80)/Sanitize(0x84)를 excluded에 자동 추가. 기존 데이터
  보존용. **Write/WriteZeroes/Deallocate 등 부분 덮어쓰기는 그대로 동작.**
- 사용: `--all-commands --no-erase` (= `--exclude-opcodes 0x80,0x84`).
- **주의**: 부분 소거(WriteZeroes 0x08/Deallocate 0x09/WriteUncorrectable 0x04)는 타겟 LBA 범위를
  지우므로 여전히 데이터 손상 가능. 전부 막으려면 `--exclude-opcodes 0x80,0x84,0x08,0x09,0x04`. 정말
  보존이 중요하면 스크래치 드라이브 권장.

## v8.5 버그 수정: always-on 도입으로 깨진 static-coverage 일관성

always-on 백그라운드 PC는 `_fold_bg`로 `global_coverage`에만 들어가고 `_update_static_coverage`를
거치지 않는다. 이로써 불변식 "**PC∈global_coverage ⟹ 그 BB∈`_sa_covered_bbs`**"가 깨졌다.
`_update_static_coverage`에 **"PC-새것 diff"**(`current_trace − global_coverage`)를 주던 곳들은,
백그라운드로 이미 global에 든 PC가 빠져 그 BB/func이 static에 **영영 안 들어가** 통계가 정체했다.

- **증상**: `[+][Edge-Cov]`에서 `new_BB`는 값이 있는데 `total_BB`가 그만큼 안 늘어남(같은 BB를 매
  명령 재카운트).
- **수정**: 해당 호출들을 **"밟은 전체"(`current_trace`)** 로 변경(`_update_static_coverage`는 멱등):
  - `_account_command` BB 브랜치 + func/PC-only(else) 브랜치
  - PM 슬롯 4곳: `forced_idle`/`pcie_bit`/`clkreq`/`power_combo` (`_pm_new_cnt`는 "new PCs" 로그용으로
    유지 — global과 일관).
- **영향 없음 확인**: 나머지 `_update_static_coverage` 호출은 이미 full-set 인자(calibration `all_seen`,
  prefill 버킷, idle universe, boot sweep[워커 기동 전]).

### 동작(가이던스) 영향 — BB 모드에서 중요
BB 파일 로드 시(BB 모드) `_account_command`는 corpus 판정을 **BB 기준으로 덮어쓴다**:
`is_interesting = len(_cur_bbs − _sa_covered_bbs) > 0`, `new_pcs = 그 개수`. 즉 `_sa_covered_bbs`는
리포트가 아니라 **fuzzing 가이던스**다.
- **수정 전(버그)**: `_sa_covered_bbs` 과소 → `_new_bbs` 과대 → `is_interesting` 과잉 발동 → **이미 본
  BB만 밟은 명령도 corpus에 추가(코퍼스 오염)**, `new_pcs` 부풀어 energy/favored/스케줄링 왜곡.
- **수정 후**: 정확 → corpus는 실제 신규 BB에만 성장, 스케줄링 정확(= always-on 이전 가이던스로 복원).
- **PC 모드**(BB 파일 없음): 가이던스는 PC 기준(`global_coverage`, 항상 정확)이라 **동작 차이 없음** —
  func/PM static 수정은 리포트(func%/플롯)만. PM 커버리지는 "corpus 판정 제외"라 PM 수정도 리포트만.

> BB 모드 사용자는 수정 전 실행의 corpus/커버리지 곡선이 과대평가였을 수 있음 → 본격 캠페인은
> 수정본(v8.5/v9.0)으로 재실행 권장.

### 남는 의도된 divergence (허용)
순수 백그라운드 BB(어떤 명령·PM 윈도우에서도 안 밟히고 명령 사이에만 실행)는 `global_coverage`
(PC 총계)엔 있지만 BB/func 총계엔 없다 → PC 총계 vs BB% 가 약간 어긋날 수 있음(허용 범위).

---
## v8.4 핵심: device-aware IO 워크로드 엔진

mutation 기반 Write/Read는 (1) 흩어진 단일 블록 (2) 상당수 LBA 범위초과로 거부 (3) 소량이라
capacity/GC/WL/read-disturb 계열 state 신호(`sec_free_blocks_pct` 등)가 **휴면**한다. v8.4는
**fuzz `fuzz_gap`(기본 100) 명령 사이에 rc=0 보장 Write/Read `block_size`(기본 100) 블록을 주입**해
SSD 내부 동작(GC·wear leveling·read disturb·SLC flush·매핑/배치)을 의도적으로 자극한다.

- **rc=0 보장**: SLBA+(NLB+1)≤nsze, (NLB+1)×lba≤MDTS — 경계는 Identify(`_get_nsze`/`_get_mdts`/
  `_detect_lba_size`)에서 **런타임 자동 유도**. nsid 고정, opcode/force_admin/data_len override 없음,
  flags(FUA/LR/PRINFO)=0. → mutation 거부 원인 전부 제거. (mdts=0=무제한 → `mdts_fallback_bytes` cap.)
- **14 패턴** (`io_workload.patterns`, round_robin):
  - load-class(state Δ 검증): `seq_write`/`rand_write`/`overwrite_churn`/`hot_cold`/`read_disturb`/`mixed_rw`
  - structural(new-PC coverage 검증): `pingpong_write`/`pingpong_read`/`subpage_rmw`/`single_lba_hammer`/
    `strided_write`(32-LBA 주기)/`reverse_seq`/`boundary`/`bursty_mixed_size`
- **state-aware 재사용**: 워크로드를 `source='workload'` 로 정상 회계 → every-100 state 캡처가
  결과 state 변화를 `state_corpus`(C2)에 수확·replay. `source!='c2'` 라 캡처 허용, `source!='c1'` 라
  C1/C2 reward·MOpt 무오염. `[+][State-Cov] [IO-WL:<pattern>]` 로 귀속 태깅.
- **개선**: ① 별도 state capture 없이 기존 every-100 재사용(비용 0) ② `read_disturb`/`pingpong_read`는
  타겟 1회 pre-write 후 read(prefill로 mapped면 skip — unmapped read의 zero-page 단축→disturb 0 방지)
  ③ 사전생성 랜덤버퍼 슬라이스(per-cmd urandom 회피, dedup 회피 유지) ④ `overwrite_churn`은
  prefill off면 "GC 미발생 가능" 경고.
- **prefill 시너지**: prefill로 가득 차면 overwrite_churn의 GC 유발이 정의상 보장.
- **활성화**: `io_workload.enabled`(기본 true), `--no-io-workload`/`--io-workload`. 검증은
  `[IO-WL]` 블록 로그 + `[+][State-Cov]` Δ + new-PC coverage(패턴 유효성 실증).
- **사용자 입력 불필요**: rc=0 경계는 런타임 자동. SLC/GC단위/read-disturb 임계/NAND page는 저가치 →
  수집 안 함(default). `working_set_frac`/`hot_window_bytes`/`gc_unit_bytes`/`strided_period_lbas`/
  `rand_buf_mb`는 튜너블 default.

PM9M1/BM9H1/P9 기존 fuzz·PCSR·state·PM 경로 불변(워크로드는 독립 주입 슬롯).

---

## v8.4 안전성·정확성 수정 (세션 후속)

### 1. mutation 으로 바뀐 실제 opcode/타입 기준 timeout 재해석
`opcode_override`/`force_admin` 으로 device 에 전달되는 실제 명령이 원본 `cmd` 와 달라져도
timeout 이 원본 `cmd.timeout_group` 으로 평가되던 버그. 예: Write(8s)가 Format(0x80)으로 변형되면
펌웨어는 수십초 Format 실행 중인데 8s 만에 가성 crash 오판(반대로 Format→빠른 명령은 과대기).
- `_OPCODE_TO_CMD` 역참조 맵((opcode, admin/io)→NVMeCommand) 추가.
- `effective_tg` 를 실제 `(actual_opcode, actual_type_val)` 기준으로 해석. 변형 없으면 `eff_cmd is cmd`
  → 동작 보존. 매핑 없는 미지 opcode 는 `command` 기본값. DeviceSelfTest STC 분기도 `eff_cmd.name` 기준.
- `[NVMe]` 로그가 실제 적용 `effective_tg` 표시(원래 `cmd.timeout_group` 와 불일치하던 것 수정).

### 2. FWDownload/FWCommit 컨트롤러 스코프 전송 (NSID=0)
FWDownload(0x11)/FWCommit(0x10)이 `needs_namespace` 기본값(True)이라 `--namespace-id=<ns>`(예:1)가
실려, 컨트롤러 스코프 펌웨어 명령이 **Invalid Field in Command(rc=2)** 로 거부 → seq-acc
FWDownload→FWCommit 이 첫 FWDownload 부터 실패(FW.bin 제공 여부 무관). → 두 명령에 `needs_namespace=False`
추가 → `actual_nsid=0`. (APST/KeepAlive NSID 수정과 동일 부류.)

### 3. SecuritySend 잠금성 Security Protocol(SECP) 전송 차단 — device 잠금 방지
`nvme ... --opcode=0x81 --cdw10=0xef000100`(SECP=CDW10[31:24]=0xEF ATA Security SET PASSWORD)이
device I/O 를 영구적으로 잠그는 현상. SECP 단위 차단(특정 SPSP 만 막으면 LOCK/ERASE/FREEZE 가 남음).
- `BLOCKED_SECURITY_SEND_SECP`(config `strategy.blocked_security_send_secp`) — `_send_nvme_command`
  chokepoint 에서 SecuritySend(0x81) + SECP∈차단셋이면 `RC_SKIP`. opcode 변이로 0x81 이 돼도 net.
- **차단**: TCG `0x01~0x06`(Opal/Pyrite/Enterprise/Ruby — Locking SP Activate·C_PIN set→잠금, PSID
  revert 외 복구 불가) + ATA `0xEC`(Device Server Password)/`0xEF`(ATA Security).
- **허용(무해)**: `0x00`(info)·`0xEA`(NVMe)·`0xED`(SA capabilities)·`0xEE`(IKEv2). 벤더 `0xF0~0xFF`는
  잠금 위험 있으나 fuzz 가치 높아 기본 미차단(필요 시 config 추가).
- SecuritySend 스키마 SECP valid 를 안전값(`[0x00,0xEA]`)만 남김(의도적 생성 방지). **SecurityReceive
  (0x82)는 read-only 라 무해** → 미적용(상태 관측에 정상 사용). 잠금은 비밀을 알아야 풀려 복구 불가라
  "실행 후 복구"가 원리적으로 안 됨 → **차단이 유일 방법**.

### 3.5. FWDownload 멀티청크 timeout 시 FAIL CMD 시드 불일치 수정
FWDownload 는 `self._fw_chunks` 원본 청크들을 순서대로 전송하는데, 회계/리포트는 대표 시드
(`mutated_seed`)로 `_account_command` 를 호출 → 청크 N 이 timeout 나면 `[NVMe TIMEOUT]`(실제 청크 N)
과 `!! FAIL CMD !!`(mutated_seed: cdw10=NUMD/cdw11=OFST/data 전부 다름)가 **불일치**. crash 저장·
replay 태그도 어긋남. → 실제 실패한 청크(`_acct_seed`/`_acct_data`)로 회계하도록 수정 → 로그·FAIL
CMD·crash·replay 가 timeout 유발 청크와 일치. (다른 경로(일반/replay/workload/calibration)는 전송
seed == 회계 seed 라 원래 정상.)

> **설계 메모(의도된 동작, 버그 아님)**: FWDownload 는 FW.bin 제공 시 원본 청크를 그대로 전송하며
> **변이하지 않는다**(직전 계산된 `mutated_seed` 는 버려짐 — 유효 펌웨어를 내려야 FWCommit 이 정상
> 활성화/CRC 경로를 타기 때문). 따라서 real-FW 에선 FWDownload 파싱 경로(NUMD/OFST·malformed
> chunk·opcode)는 fuzz 되지 않는다. 반면 **FWCommit 은 변이됨**(FS/CA/BPID + cdw/opcode/data).
> FW.bin 없는 dummy FWDownload 는 일반 경로라 변이됨. (real-FW 청크 변이는 검토 후 미적용 — 현행 유지.)

### 3.6. NVMe 완료 status 추가 출력 (rc=SC 만 → SCT 포함 full status)
`nvme passthru` 의 프로세스 exit code(rc)는 8비트 절단으로 **status 하위 8비트 = SC(Status Code)만**
남고 SCT(Status Code Type, bits[10:8])·DNR/More 는 사라진다 → 같은 SC·다른 SCT 가 한 rc 로 충돌
(예: SC=0x80 이 CONFLICTING_ATTRS(SCT=1)·WRITE_FAULT(SCT=2) 둘 다 rc=128). nvme-cli 는 stderr 에
`NVMe status: <NAME>(0xVAL)` 로 full status 를 출력하므로 이를 파싱해 함께 로깅한다.
- `_parse_nvme_status()`(stderr/stdout regex) + `_fmt_nvme_status()` → `[NVMe RET] rc=N
  status=0xVVVV SCT=n(이름) SC=0xSS [NAME]`. rc>0 일 때만(성공 rc=0 은 status 없음). 판정 로직 불변.
- **NVMe status 없는 rc>0**(errno/내부 실패, 예: rc=1 `Invalid argument` — NVMe 제출 전 거부)은
  `msg="<stderr 첫 줄>"` 로 원문 표시 → rc=1 이 SC=0x01(Invalid Opcode, NVMe 완료에러)인지 errno
  실패인지 로그로 구분됨. (rc=1 에 status 가 안 붙던 건 버그 아님 — 완료 status 자체가 없는 케이스.)
- timeout 은 완료(CQE) 자체가 없어 status 없음 → 변경 없음.

### 4. Namespace Detach 자동 재부착 + Delete 차단 — fuzzing 정지 방지
스키마 valid 는 mutation 가이드일 뿐 send net 이 없어, 일반 cdw 비트플립/opcode 변이가 SEL=1 에
도달 가능. SEL=CDW10[3:0]. **admin 일 때만** 적용(IO 0x0D ReservationRegister/0x15 ReservationRelease 무영향).
- **Detach**(NamespaceAttachment 0x15, SEL=1): NS 보존(컨트롤러에서만 분리) → 실행 허용 후 rc=0 이면
  즉시 `_reattach_namespace()` → `nvme attach-ns -n <nsid> -c <CNTLID>` + `ns-rescan` 로 device 복구.
  CNTLID 는 시작 시 Identify Controller 스냅샷. config `auto_reattach_ns`(기본 on).
- **Delete**(NamespaceManagement 0x0D, SEL=1): namespace 영구 파괴(데이터 소멸 + 재생성 시 NSID 변경 →
  device 경로 깨짐)라 복구 어려움 → send-time 차단(`block_ns_delete`, 기본 on). 표준상 Create/Delete 는
  OACS bit3 로 함께 게이팅(둘 중 하나만 막는 제품 없음) — 제품이 지원·재생성 OK면 toggle off.
- 시작 시 **OACS[3](NS Mgmt 지원 여부) 로깅** — 미지원 제품은 두 명령을 펌웨어가 애초에 거부(무해),
  지원 제품에서만 가드가 의미. stats: `blocked_ns_delete`/`ns_reattach_ok`/`ns_reattach_fail`.

### 거부/제외 메커니즘 4층 (참고)
| 층 | 단계 | 입자도 | 내용 |
|----|------|--------|------|
| L1 명령 집합 | 시작 | 명령명 | 기본 비파괴 6종 / `--commands` / `--all-commands` |
| L2 생성 제외 | 시드·변이 생성 | opcode | `excluded_opcodes`(`--exclude-opcodes`) + 시드 `_DESTRUCTIVE`(Format/Sanitize) |
| L3 전송 가드 | `_send_nvme_command` chokepoint | opcode / 서브필드 | `BLOCKED_ADMIN_OPCODES`(큐 0x00/01/04/05·AER 0x0C·Doorbell 0x7C) · `BLOCKED_SECURITY_SEND_SECP` · NS Delete · (NS Detach 는 실행+복구) |
| L4 런타임 거부 | 실행 중 | 명령 결과 | `unsupported_skip`(v7.8 EngineErrInt, J-Link dump 필요 → PM9M1/BM9H1 만) |

명령 차단/제외는 **세 제품 공통**(config `products` 에 명령 override 없음). 제품 차이는 *명령 거부* 가
아니라 state 관측 범위(P9 LID 0xDF 제외)·런타임 EngineErrInt skip(P9 미동작)·timeout 값.
Sanitize 는 미차단(긴 timeout 흡수).

---

**v8.3 핵심: 모든 사용자 설정값·경로를 `fuzzer_config.json` 으로 외부화.**
코드 상단에 흩어져 있던 상수/타임아웃/주소/확률/경로 + `PRODUCT_PROFILES` 를 JSON 한 파일로 모았다.
모듈 로드 시 JSON 을 읽어 **같은 이름의 전역**에 주입 → `FuzzConfig` 기본값/argparse default 가
자동으로 JSON 값을 따른다. JSON 은 **버전 비종속 공유 파일**이라 `.py` 를 버전업 복사해도 그대로
재사용된다(매 버전 상단 재편집 불필요). **동작은 v8.2 와 byte-동등**(81 상수 + PRODUCT_PROFILES +
72 FuzzConfig 필드 1:1 검증, 출력 폴더의 버전 문자열만 다름).

v8.2 P9 profile 정리, v8.1 J-Link halt 샘플러, v8.0 제품 일반화, v7.x 기능 모두 유지.

---

## v8.3 변경사항 (JSON 외부화)

### 설정 파일 `fuzzer_config.json`
- 위치: fuzzer 스크립트와 같은 디렉토리(기본). `--config PATH` 로 교체.
- 16진수는 `"0x.."` 문자열로 둬도 로더가 int 로 변환. `null`→None, 배열→list/tuple.
- 없으면 명확한 fatal 에러로 중단(기본 파일을 repo 에 동봉).
- 우선순위: **JSON 기본값 → 제품 profile override → CLI 인자 override(최우선)**.
- **제품별 timeout override**: `globals/timeouts` 는 기본값, 각 제품의 `nvme_timeouts`(+선택적
  `nvme_passthru_timeout_ms`/`nvme_kernel_timeout_sec`)가 그 위를 덮어쓴다. 제품마다 다른 값 가능.
  생략 시 global 사용. (현재는 3제품 모두 global 과 동일하게 시드 — 필요 시 제품별로 편집.)

### JSON 섹션
`globals`(FW주소·OpenOCD/J-Link·PCSR·DPIDR·NVMe device) · `paths`(fw_bin·pmu_script·ufas_binary·
jlink_dump_script·debug_package_dir·parser_script·engine_errint_logs) · `timeouts` · `sampling` ·
`diagnose_idle_calibration` · `fuzzing` · `mutation` · `power` · `visualization` ·
`runtime_hw`(clkreq 핀/전압·fw_xfer/slot·prefill_bs·boot_sweep·settle_sweep·nvme_lba_size) ·
`products`(PM9M1/BM9H1/P9) · `strategy`(blocked_admin_opcodes·builtin_sequences·pcie_pm_fuzz_targets·
clkreq_fuzz_modes).

### 구현
- 로더 `load_user_config()` + `_early_config_path()`(import 시점 `--config` 선파싱) + `_cfg_hexnorm()`.
- 모듈 상수 정의가 `_CFG[...]` 참조로 변경(이름 유지 → 나머지 코드 무수정).
- 메서드 본문에 박혀 있던 경로(`ufas`/`run_smi_mem_dump_*.sh`/`DebugPackage`/parser/event log)는 신규
  명명 상수(`UFAS_BINARY`/`JLINK_DUMP_SCRIPT`/`DEBUG_PACKAGE_DIR`/...)로 승격 후 JSON 주입.
- 코드 유지(외부화 제외): `OUTPUT_DIR`(버전 종속), `CMD_SCHEMAS`/`NVME_COMMANDS`(명령 구조 정의),
  `POWER_COMBOS`(range 생성식), 파생/런타임값(`_PAGE_SIZE` 등).

### 제품별 State 관측 필드 (state_fields)
- `fuzzer_config.json` 의 `state_fields` 섹션에 **세트별** 정의: `r8`(PM9M1/BM9H1, 25필드) /
  `p9`(P9, 22필드 = r8 에서 LID 0xDF `df_*` 3개 제외). 제품의 `state_fields` 키가 세트명을 가리킨다.
- P9 는 LID 02h(SMART)·01h(err_status)·SecRecv(SECP=0xFE/SPSP=0x3D) 유지, **LID 0xDF 제외**
  (P9 에 없는 페이지). NVMeStateMonitor 가 제품 세트로 구성돼 해당 명령만 수행한다.
- `state_fields.py` 는 더 이상 import 하지 않음(정의는 JSON 으로 이전). 세트 추가/편집은 JSON 에서.

### 주기적 전체 State 출력 (터미널)
- 10000 exec 마다 `_log_state_snapshot()` 이 **모든 state 필드(smart/vendor LID/SecRecv) 명령을
  수행하고 값 전체를 출력**. v8.3: 터미널 필터에 `[State-Snap]`/`[SMART]` 추가 → 파일 로그뿐 아니라
  **터미널에도** 표시(PM9M1·P9 공통).

### P9 timeout (예시 기본값)
`products.P9.nvme_timeouts`: 예외(Format NVM 300s, Async Event Request `aer` 600s)를 빼고 전부 30s
(`command/flush/selftest_*/verify` = 30000). 그룹 미지정 명령은 `command`(30s) 로 폴백.

### 새 제품/설정 추가
`fuzzer_config.json` 의 `products` 에 레코드 추가, 또는 각 섹션 값 편집 — **코드 수정 불필요**.

---

## 지원 제품

| 제품 | interface | core | coverage 샘플러 | UFAS | J-Link dump | 상태 |
|------|-----------|------|-----------------|------|-------------|------|
| **PM9M1** | SWD | 3 (R8) | OpenOCD PCSR (비침습) | ✅ | ✅ | 정상 |
| **BM9H1** | JTAG | 2 (R8) | OpenOCD PCSR (비침습) | ✅ | ✅ | 정상 |
| **P9** | SWD | R5 단일 | **J-Link halt (pylink)** | ❌ | ❌ | v8.1: `sampler_type='jlink_halt'`. `--product P9` 단독 동작. 튜닝: `P9_BRINGUP.md` |

```bash
sudo python3 pc_sampling_fuzzer_v8.1.py --product PM9M1 --nvme /dev/nvme0n1   # PCSR (변경 없음)
sudo python3 pc_sampling_fuzzer_v8.1.py --product P9    --nvme /dev/nvme0n1   # J-Link halt 자동
# pylink 필요: pip3 install pylink-square (install_fuzzer_deps.sh 에 포함)
```

---

## v8.1 변경사항

### 1. 배경 — OpenOCD telnet halt 의 desync 문제

P9 는 **DBGPCSR 미구현 + ETM 트레이스 핀 없음** → 비침습 PC 샘플링 불가. halt→PC→resume 가
유일한 방법이다. v8.0 의 `OpenOCDHaltSampler` 는 이를 OpenOCD telnet 으로 했는데:

- OpenOCD `halt` 는 코어가 멈출 때까지 내부적으로 최대 5초 폴링.
- 그런데 fuzzer 의 telnet 소켓 read 타임아웃은 **2초**(`_SOCK_TIMEOUT`).
- halt-ack 이 2초를 넘으면 `_telnet_cmd('halt')` 가 프롬프트 없이 빈 값 반환 → 이어진
  `reg pc` 가 desync 되어 `''` → 그 상태로 `resume` 이 들어가 **실제 실행 안 됨**
  → 단일 R5 컨트롤러 코어가 halt 로 굳음 → NVMe 명령이 무한 hang(커널 타임아웃 30일).

`--go-settle` 을 올려도(샘플 간격만 늘림) halt-ack 지연 자체는 안 줄어 해결 안 됨.

### 2. 해결 — `JLinkHaltSampler` (pylink 직접 제어)

`OpenOCDPCSampler` 를 상속하되 **연결 계층과 PC 읽기만 pylink 로 교체**. 샘플링 worker /
diagnose / 회계 / 저장 / 커버리지 평가 인프라는 그대로 상속(코드 재사용, 메인 루프 무변경).

| 동작 | 구현 |
|------|------|
| 연결 | `pylink.JLink(); open(); set_tif(SWD); exec_command("CORESIGHT_SetIndexAPBAPToUse=0"); connect("Cortex-R5", speed=4000)` |
| PC 읽기 | `JLINKARM_Halt → halted() 폴링(≤50ms) → ReadReg(PC) → JLINKARM_Go()`. 전부 블로킹 API → **telnet desync 원천 차단** |
| resume | 항상 `JLINKARM_Go()`. **`restart()` 절대 안 씀**(CPU 리셋 — 살아있는 SSD 손상 방지). go 실패 시 None 반환 |
| PC 레지스터 인덱스 | connect 시 `register_list()` 에서 R15/PC 자동 탐지. `--pc-reg-index` 로 강제 지정 가능 |
| 스레드 안전성 | pylink 단일 세션 → 모든 호출을 `_jlink_lock` 으로 직렬화(worker/메인 스레드 동시 접근 방지) |
| halt 상한 | halted() 폴링 ~50ms 상한 → 못 멈추면 None. 연속 실패는 base 의 `_CONSECUTIVE_FAIL_LIMIT(10)` → 복구 신호 |

DLL 함수(`_dll.JLINKARM_Halt/ReadReg/Go`)를 캐싱해 wrapper 오버헤드 회피(tight halt 루프 가속).

### 3. 제품/설정 와이어링

- **P9 profile**: `sampler_type` `'halt'` → **`'jlink_halt'`**. 신규 필드 `jlink_speed=4000`,
  `jlink_ap_index=0`, `pc_reg_index=None`(자동 탐지).
- **샘플러 선택**(`NVMeFuzzer.__init__`): `'jlink_halt'` → `JLinkHaltSampler` 분기 1개 추가.
- **CLI**: `--sampler` 에 `jlink_halt` 추가, `--pc-reg-index N`(PC 레지스터 인덱스 override) 추가.
- **`import pylink`**: try/except 가드 — pylink 없는 PM9M1/BM9H1 호스트는 무영향, P9 선택 시에만
  필요(미설치면 connect 에서 안내 메시지).

### 4. USB 점유 충돌 처리

P9 는 pylink 가 J-Link USB 를 **in-process 단독 점유**. JLinkExe 를 spawn 하거나 OpenOCD 가
USB 를 가졌다고 가정하는 경로를 sampler 경유로 우회(isinstance 가드 2곳):

- `_shutdown_openocd_for_jlink`: J-Link 샘플러면 early-return(OpenOCD 없음).
- 크래시 후 PC 모니터 루프: JLinkExe subprocess 대신 `sampler.read_stuck_pcs()`(pylink 핸들 경유).
- 크래시 stuck PC 읽기(`_reinit_target`/`read_stuck_pcs`)는 이미 sampler 메서드 경유 → 자동 처리.
- P9 profile 은 `enable_ufas=False`/`enable_jlink_dump=False` 라 덤프/UFAS 본체는 이미 skip.

### 5. 코드 영향 범위 (v8.0 → v8.1)

| 사이트 | 변경 |
|--------|------|
| `import pylink` (try/except) | 신규 (가드) |
| `FuzzConfig` | `jlink_speed`/`jlink_ap_index`/`pc_reg_index` 추가 |
| `PRODUCT_PROFILES['P9']` | `sampler_type='jlink_halt'` + 3 필드 |
| `JLinkHaltSampler` 클래스 | **신규** (~150줄). connect/_read_all_pcs/_openocd_alive/_reconnect/_reinit_target/close override + OpenOCD 메서드 no-op |
| `NVMeFuzzer.__init__` 샘플러 선택 | `'jlink_halt'` 분기 추가 |
| `_shutdown_openocd_for_jlink` | J-Link 샘플러 early-return 가드 |
| 크래시 PC 모니터 | J-Link 샘플러는 `read_stuck_pcs` 경유 |
| CLI `--sampler`/`--pc-reg-index` | choices 추가 / 신규 옵션 |
| `install_fuzzer_deps.sh` | `pylink-square` 추가 |

**PM9M1/BM9H1 동작 불변** — PCSR 경로(OpenOCDPCSampler) 코드는 손대지 않음.

---

## 검증

- `python3 -c "import ast; ast.parse(...)"` 문법 OK.
- `--help` 에 `--sampler {pcsr,halt,jlink_halt,null}` / `--pc-reg-index` 노출 확인.
- `--product P9` → `sampler_type='jlink_halt'`, `JLinkHaltSampler` 인스턴스화/`_pcsr_addrs=[0x80030000]`/
  invalid mask(SWD DPIDR) 확인. connect 전 `_openocd_alive()=False`, `_read_all_pcs()=None`(graceful).
- pylink 2.0.0 설치 확인.

평가 환경에서 할 일은 `P9_BRINGUP.md` 참조 (J-Link halt 실측: idle universe 수렴, NVMe timeout,
PC 레지스터 인덱스 확인).
