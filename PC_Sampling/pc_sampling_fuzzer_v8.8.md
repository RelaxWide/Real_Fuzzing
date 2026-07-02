# PC Sampling SSD Firmware Fuzzer v8.8

OpenOCD PCSR 비침습 샘플링 + `nvme-cli` passthru 기반 Coverage-Guided + State-Aware Fuzzer.

> v8.8 = v8.7 기능 전체 보존 **+ 주기 차트 생성을 `os.fork()` → '완전 독립 subprocess'로 교체**
> (호스트 OS logless 즉시 재부팅 트리거 제거). 부수로 timeout-crash 종료 시 pylink 세션
> segfault 수정, `FAIL CMD` 의 `data_len` 을 실제 전송 transfer length 로 수정, 시작 배너를
> sampler-aware 로 정리. **fuzzing/샘플링/state/PM 경로 자체는 v8.7 과 동일.**
>
> ※ 구 `pc_sampling_fuzzer_v9.0.py`/`.md` 는 **삭제됨**. v9.0.py 는 v8.8 의 버전 문자열만 바꾼
> 복사본이었고, v9.0.md 가 예고한 RAG/LLM 통합(`RagBridge`/`--rag`/`seed_class`)은 코드로 구현된
> 적이 없다. RAG 는 실제 major 버전으로 재도입 예정이며 스캐폴딩(스키마·서비스 설계)만 `rag/`
> 에 남아 있다. **현재 최신 동작 코드는 이 v8.8 이다.**

---

## v8.8 핵심: 주기 차트 생성 `os.fork()` → 완전 독립 subprocess

### 왜 바꿨나 (host OS logless 즉시 재부팅)
장시간 캠페인 중 **호스트(Ubuntu)가 로그 한 줄 없이 즉시 재부팅**되는 현상이, `GRAPH_REFRESH_INTERVAL`
주기에 차트를 생성하는 `os.fork()` 자식과 상관됨이 실측 확인됐다. 원인은 **거대 퍼저 프로세스의
fork 그 자체**다:

- 프로세스가 방대한 주소공간을 갖고(코퍼스/커버리지/히스토리) → fork 시 **COW 페이지 테이블 복제**가 큼.
- 모든 FD 상속(OpenOCD telnet 소켓·J-Link USB·nvme subprocess 파이프·로그 파일).
- **멀티스레드 상태에서의 fork**(샘플러 데몬 스레드 등) — POSIX 상 fork 후엔 async-signal-safe 만
  허용되나 matplotlib(C 확장)/numpy 는 그렇지 않아 자식 상태가 불안정.

즉 v8.6/v8.7 이 도입한 "fork 자식에서 차트 격리"(python3 segfault 는 막았음)가, **호스트 커널을
불안정하게 만드는 새 트리거**였다. (메모리 노트 `os_reboot_chart_fork.md` 의 검증 결론과 일치.)

### 무엇이 바뀌었나
- **fork 완전 제거.** 차트에 필요한 데이터만 pickle 스냅샷으로 디스크에 쓰고, **같은 스크립트를
  `--render-charts <snap.pkl>` 인자로 새 인터프리터(subprocess)에서 재실행**한다. 새 프로세스는
  COW 복제·FD 상속·멀티스레드 fork 가 전혀 없다.
- **렌더 프로세스는 디바이스/OpenOCD/J-Link 를 일절 초기화·접근하지 않는다.** `NVMeFuzzer.__new__`
  로 `__init__` 을 우회하고 스냅샷 데이터 속성만 주입한 뒤 차트 메서드(`_generate_all_charts`)만 돈다.
- **관련 심볼**:
  - `_snapshot_chart_data()` — 차트 5종이 읽는 속성만(`_CHART_SNAPSHOT_ATTRS` 19종 +
    `sampler.global_coverage` + config 3필드) pickle 가능한 dict 로 스냅샷.
  - `_snap_copy()` — 샘플러 데몬 스레드가 `global_coverage` 등을 동시 갱신 중일 때 "changed size
    during iteration"(torn-read) 를 재시도로 회피하는 안전 얕은 복사.
  - `_generate_graphs_isolated()` — 스냅샷 → pkl 기록 → `subprocess.Popen([sys.executable,
    __file__, '--render-charts', snap], close_fds=True)`. stdout=DEVNULL, stderr→`.chart_render.log`.
  - `_reap_graph_child()` — Popen 논블로킹/블로킹 회수 + 임시 pkl 정리. 시그널 종료(SIGSEGV/SIGABRT)
    나 rc≠0 이면 `[Graph] ⚠️` 경고(로그로 렌더 실패 가시화, 본체는 계속).
  - `_render_charts_from_snapshot()` + `if '__main__'` 최상단의 `--render-charts` 분기 — 렌더
    전용 진입점(argparse/디바이스 초기화 전에 즉시 처리 후 `SystemExit`).
- **누적 방지**: 이전 주기 렌더가 아직 살아있으면 이번 주기는 건너뜀(`[Graph] 이전 차트 렌더 아직
  실행 중`). 종료(정상 shutdown) 시 `_reap_graph_child(block=True)` 로 마지막 렌더를 대기 회수.
- **폴백**: 스냅샷/pkl 기록/Popen 기동 실패 시 인프로세스(`_generate_all_charts`)로 폴백(임시 pkl 정리).
- `_warm_matplotlib()`(부모 선import)는 남아 있으나, 이제 fork 가 아니라 인프로세스 폴백 경로에서만
  의미가 있다(subprocess 렌더는 자체 인터프리터라 부모 워밍 불필요).

### 영향
- **차트 데이터/모양·fuzzing/샘플링/state/PM 경로 전부 불변.** 바뀐 건 "차트를 언제·어느 프로세스가
  그리느냐"뿐. 차트는 이제 fuzzer 와 완전히 분리된 프로세스가 pkl 만 읽고 그린다.
- **호스트 재부팅 트리거 제거**가 목적. 차트 렌더 프로세스가 죽어도(matplotlib/numpy C 크래시)
  fuzzer 본체·호스트 모두 무영향(rc 경고만).

---

## v8.8 부수 수정

### 1. timeout-crash 종료 경로 pylink 세션 segfault 제거
timeout 크래시 후 stuck-PC 모니터링을 끝내는 분기(`[MONITOR] 모니터링 종료`)가 **샘플러 `close()` 를
호출하지 않아**, 열린 J-Link 세션(JLinkARM DLL 의 ctypes 핸들)이 인터프리터 종료 시 순서 없이
finalize 되며 **`Segmentation fault (core dumped)`** 를 유발했다(P9/`jlink_halt` — 모니터링 종료
직후 크래시). → 이 분기에도 `self.sampler.close()` 추가. `close()` 는 코어를 `go`(resume)시킨 뒤
세션을 정상 종료하므로 안전하다. **단 정상 종료와 달리 APST/keepalive/timeout 복원은 하지 않는다**
(crash 상태 보존 — 진단용).

### 2. `FAIL CMD` 의 `data_len` = 실제 전송 transfer length
`!! FAIL CMD !!` 블록의 `data_len` 이 `len(fuzz_data)`(호스트 입력 payload)로 찍혀, **read 등
응답형 명령**은 입력 버퍼가 비어 항상 `0` 으로 나왔다 → replay `.sh` 가 쓰는 값(예: 512)과 불일치.
→ 실제 device 로 전송된 transfer length(`_cmd_history` 마지막 nvme 항목의 `data_len`, replay 와
동일 소스)를 `data_len` 으로 보고하고, 입력 payload 는 별도 `in_buf` 줄로 분리 표기.
```
  data_len  : 512 bytes (전송 transfer length)   # replay .sh 와 일치
  in_buf    : 0 bytes (호스트 입력 payload)        # read 등 응답형은 0
```

### 3. 시작 배너 sampler-aware
예전 배너는 sampler 종류와 무관하게 항상 `OpenOCD ... openocd_config` 를 출력해, `openocd_config`
키가 없는 J-Link 제품(P9)이 기본값 `r8_pcsr.cfg` 로 **오표기**됐다. → 배너 `Sampler:` 줄을
`no_jlink` / `jlink_halt`(device·speed·AP·pc_reg, "OpenOCD 미사용") / `halt` / `pcsr` 분기로
분리해 실제 샘플러에 맞는 정보만 출력.

---

## v8.7 이하 (전부 v8.8 에 그대로 유지)

세부는 각 버전 md 참조. 요지만:

- **v8.7**: PCSR **always-on 계측 완전 제거** → windowed(명령마다 start/stop) 단일 경로. always-on
  (세션 내내 연속 PCSR 폴링)이 host OS freeze(`alloc_vmap_area` GPF + `vmap_area_lock` soft-lockup)
  와 연관됨이 확인됨. prefill 샘플링은 v8.4 `_pf_sampler`(유한 구간 전용 스레드)로 복원.
  `--no-always-on` 옵션도 제거. (v8.5 가 도입했던 always-on 은 이 v8.7 에서 롤백된 상태.)
- **v8.6**: 주기 matplotlib 차트를 fork 자식에서 격리(인프로세스 segfault 차단) — **v8.8 에서 이
  fork 방식 자체가 subprocess 로 대체됨**. vmalloc/kernel-taint 진단(vmon): 10000-exec 마다
  `/proc/meminfo`·tainted 로깅(`[VMon]` 파일전용, `[Taint]` 터미널). `--no-vmon` 으로 끔.
- **v8.5**: (always-on 은 v8.7 에서 제거) `--ignore-opcodes`(특정 opcode timeout 을 크래시로 안 치고
  POR 복구 후 계속), `--no-erase`(FormatNVM/Sanitize 전체소거 차단 + `excluded_opcodes` 가 명령
  선택 풀까지 필터).
- **v8.4**: device-aware IO 워크로드 엔진 — fuzz 100 명령 사이에 rc=0 보장 Write/Read 블록(14 패턴)을
  주입해 GC/WL/read-disturb/SLC 를 자극, `source='workload'` 정상 회계로 every-100 state 를 C2 수확.
  + 세션 후속 안전성 수정(effective_tg timeout 재해석 · FW cmd NSID=0 · SecuritySend SECP 차단 ·
  NS Detach 자동 재부착/Delete 차단 · NVMe full status SCT/SC 로깅).
- **v8.3**: 모든 사용자 설정값·경로를 `fuzzer_config.json` 으로 외부화(버전 비종속 공유 파일).
- **v8.2**: P9 profile 정리(J-Link 에서 안 쓰는 OpenOCD/PCSR/UFAS 키 제거).
- **v8.1**: P9 전용 J-Link(pylink) halt 샘플러(`JLinkHaltSampler`) — OpenOCD telnet halt 의 소켓
  desync 를 in-process pylink halt/register_read/`JLINKARM_Go` 로 대체.
- **v8.0**: 제품 추가 P9(Cortex-R5·SWD). 모든 target-specific 값을 `PRODUCT_PROFILES` 로 일반화.
- **v7.x**: State-Aware(NVMeStateMonitor / dual interesting) · Phase 1/2/3 · SequenceSeed corpus ·
  S1/S2 perturb · 시각화 · `--unsupported-skip`/`--no-jlink`.

---

## 지원 제품

| 제품 | interface | core | coverage 샘플러 | UFAS | J-Link dump | 상태 |
|------|-----------|------|-----------------|------|-------------|------|
| **PM9M1** | SWD | 3 (R8) | OpenOCD PCSR (비침습) | ✅ | ✅ | 정상 |
| **BM9H1** | JTAG | 2 (R8) | OpenOCD PCSR (비침습) | ✅ | ✅ | 정상 |
| **P9** | SWD | R5 단일 | **J-Link halt (pylink)** | ❌ | ❌ | `sampler_type='jlink_halt'`. 튜닝: `P9_BRINGUP.md` |

```bash
sudo python3 pc_sampling_fuzzer_v8.8.py --product PM9M1 --nvme /dev/nvme0n1   # PCSR (비침습)
sudo python3 pc_sampling_fuzzer_v8.8.py --product P9    --nvme /dev/nvme0n1   # J-Link halt 자동
# pylink 필요: pip3 install pylink-square (install_fuzzer_deps.sh 에 포함)
# 차트 렌더 subprocess 는 fuzzer 가 자동 spawn(--render-charts 는 내부 전용, 수동 사용 X)
```

---

## 검증

- `python3 -c "import ast; ast.parse(open('pc_sampling_fuzzer_v8.8.py').read())"` 문법 OK.
- `FUZZER_VERSION == "8.8.0"` (현재 최신 — v9.0 은 삭제됨).
- `--render-charts <snap.pkl>` 분기가 argparse/디바이스 초기화보다 먼저 실행되어 렌더만 하고 종료.
- 차트 렌더가 이제 별도 프로세스라, 렌더 크래시 시 `.chart_render.log` + `[Graph] ⚠️` 경고만 남고
  fuzzer 본체·호스트 무영향.

평가 환경 P9 bring-up(J-Link halt 실측: idle universe 수렴, NVMe timeout, PC 레지스터 인덱스)은
`P9_BRINGUP.md` 참조.
