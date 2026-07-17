# HANDOFF — segfault / kernel memory corruption 조사 (미확정, 진행중)

> 목적: "동작 중 segfault/bus error + dmesg `pagealloc: memory corruption`" 조사 기록.
> **아직 근본원인 확정 안 됨.** 지금까지 배제한 것·확정한 것·유력 가설·다음 테스트를 남긴다.
> 작성 시점 최신 코드: `pc_sampling_fuzzer_v9.3.py` @ commit `72710f8`.

---

## 0. 증상 (관측된 것)

- 퍼저 실행 중 **segfault / bus error / GPF** 로 프로세스 사망. 크래시 위치가 **매번 다름**:
  - `PyObject_GetAttr`, `PyObject_IsTrue`, `_PyEval_EvalFrameDefault` (python3.8 내부)
  - `libc-2.31.so` GPF (malloc/free/memcpy류)
  - python3 "trap stack segment" (SIGBUS, 스택 손상)
  - **nvme-cli 자식 프로세스**가 쓰레기 주소로 점프(별개 exec 프로세스 손상)
- **dmesg 커널 로그**: `check_poison_mem: N callbacks suppressed`, **`pagealloc: memory corruption`**,
  `__kernel_unpoison_pages`/`prep_new_page` 콜스택, `page dumped because: corrupted page details`.
  → **커널이 free 페이지가 덮어써진 걸 검출**(page poisoning). 이건 fuzzer segfault "이전에" 이미 뜸.
- 크래시 시그널·위치가 비결정적 = **메모리 손상**이 어딘가에서 나고, 다음에 그 메모리를 건드리는
  곳에서 터지는 패턴(비국소).

---

## 1. 핵심 판정 근거: `pagealloc: memory corruption`

- **커널 페이지 레벨 손상** = (a) 하드웨어 RAM, (b) DMA-capable 디바이스(NVMe/J-Link)가 free 페이지에
  씀, (c) 커널/드라이버 버그 — 셋 중 하나. **파이썬(유저스페이스) 코드는 커널 free 페이지를 못 망가뜨림.**
- 따라서 **fuzzer의 파이썬 코드 자체가 근본원인일 수 없음.** NVMe/J-Link 명령이 유발하는 **디바이스 DMA
  손상** 또는 하드웨어가 유력.

---

## 2. 배제한 것 (증거와 함께)

| 후보 | 배제 근거 |
|---|---|
| **faulthandler(내가 추가한 진단도구)** | **오히려 크래시 유발원이었음.** bab8f6a(--no-jlink) 무사고 vs 내 faulthandler 얹은 버전 크래시. `--no-jlink` 실행경로 차이 중 유일한 활성 신규코드가 faulthandler. → 제거(58aeca0). ⚠️ 이전 세션에서 내가 "분석"한 gdb/faulthandler 스택 상당수가 이 도구가 만든 크래시였을 수 있음. |
| **재-calibration(2fb417b)** | 제거(41a070f) 후에도 `--no-jlink` 크래시 지속 → 트리거 아님. (단 stateful SSD에 명령 반복은 부적절해 제거 자체는 유지.) |
| **io_patterns 버스트 / FFM** | bab8f6a(=io_patterns 이미 포함)가 `--no-jlink` 무사고 → 버스트 아님. |
| **data_len↔CDW 의도적 불일치** | 정당한 퍼징 동작 + **v9.1 이전부터 있던 오래된 기능** → v9.1에서 갑자기 나는 것 설명 못 함. |
| **차트/matplotlib 인프로세스** | snapshot pickle 정상(폴백 안 뜸), gdb가 차트 프레임 한 번도 안 잡음, 차트는 오래된 코드. |
| **알려진 커널-손상 admin 명령(큐/doorbell/AER/lockdown)** | `BLOCKED_ADMIN_OPCODES=[0x00,01,04,05,0C,7C,24]` + send-time 단일 chokepoint(9214, actual_opcode+passthru_type) → **확실히 차단됨**(정적 검증). |

### 방법론 주의 (중요)
- **재부팅 없는 버전 bisect는 누적 손상으로 오염될 수 있음.** 단 사용자 실측 순서는 **v9.3(fresh,첫)→크래시,
  v9.2/v9.1→크래시, v8.8/v9.0→무사고** = 나중에 돌린 게 오히려 무사고 → **누적/열 아님, 버전 의존 진짜.**
  (v9.0은 길게 안 돌려봐서 완벽 확정은 아님. **v8.8 무사고가 가장 단단한 기준.**)

---

## 3. 확정한 것 (정적 코드 검증)

### 3-1. 버전 경계 = v8.8(무사고) → v9.0(LLM 도입) → v9.1(LLM 확장)
- v8.8: blind 퍼징(LLM 없음/약함). **무사고.**
- v9.0: **LLM(RAG) 도입.**
- v9.1: 스키마 [:20] 캡 제거(→48), 구조적 data_hex, SC-status 조준. **LLM 탐색 대폭 확장.**
- v9.0→v9.1 **명령 전송/버퍼/DMA/passthru 코드는 무변경**(diff 확인). 바뀐 건 **LLM 명령 생성 범위**뿐.

### 3-2. 기본 명령 세트는 6개뿐 (`--all-commands` 없이)
- `NVME_COMMANDS_DEFAULT` = **Identify, GetLogPage, GetFeatures, SetFeatures, Read, Write**.
- exotic 명령(VirtMgmt 0x1C, MigrationSend 0x41, ControllerDataQueue 0x45, FWCommit 0x10,
  FWDownload 0x11, NamespaceAttachment 0x15, CapacityMgmt 0x20 등)은 `--all-commands` 뒤 gated.
- **사용자는 `--all-commands` 안 씀.**

### 3-3. ★ LLM은 enabled-set을 우회한다 (핵심 gap, 코드 확정) ★
- `_llm_schema_dict()`(3128): **전체 NVME_COMMANDS(30개)를 LLM에 노출**(enabled 6개 아님).
- `_llm_make_seed()`(4989): `cmd = _NAME_TO_CMD.get(name)` → **전체 30개에서 조회**(self.commands 아님).
  `is_dangerous`만 통과하면 corpus 주입 → 전송.
- `is_dangerous`(rag_schema.py): **FormatNVM/Sanitize(destructive) + blocked_admin_opcodes +
  locking SECP + NS-delete만** 차단. **exotic 명령(VirtMgmt/MigrationSend/ControllerDataQueue/
  FWCommit/FWDownload/NamespaceAttachment/CapacityMgmt/DirectiveSend/Abort)은 안 막음.**
- **결론: `--all-commands` 없이도 LLM은 exotic admin 명령을 생성·실행할 수 있다.**
  (`--all-commands`는 blind 선택 풀만 제한, LLM 경로는 우회.)

---

## 4. 유력 가설 (미확정)

**LLM이 enabled-set을 우회해 exotic admin 명령(VirtMgmt/MigrationSend/ControllerDataQueue/FWCommit 등,
컨트롤러 상태/DMA 조작 명령)을 실행 → SSD 펌웨어/커널 소유 NVMe 전송로(큐/DMA)를 손상 → `pagealloc`
커널 페이지 손상 → 유저스페이스 프로세스로 전파돼 segfault/bus error.**

정합성: 커널 DMA 손상 ✓, 특정 명령 아님(여러 exotic) ✓, admin+io 둘 다 ✓, `--all-commands` 불필요 ✓,
**v8.8(blind, 6개만) 무사고 / v9.0+(LLM) 크래시** ✓, 버전 의존(v9.0 도입, v9.1 확장) ✓.

**단 "그 exotic 명령이 실제로 커널을 손상시킨다"는 아직 미확인.** gap(LLM 우회)은 정적 확정, 인과는 테스트 필요.

### 대안 가설 (아직 열려있음)
- **하드웨어(불량 RAM/열/전원)**: `--no-jlink`로도 크래시하면 이쪽. memtest86+ 로 확진 필요.
  (nvme-cli 별개 프로세스 손상은 소프트웨어로 설명 어려워 하드웨어도 배제 못 함. 단 버전 의존이 강해
  순수 랜덤 하드웨어와는 안 맞음.)
- **IOMMU off**: 켜져 있으면 디바이스 DMA가 mapped 영역 밖으로 못 나감(오버플로 시 DMA fault).
  꺼져 있으면 임의 물리페이지 손상 가능. → `dmesg | grep -i 'iommu\|DMAR'` 확인 필요.

---

## 5. 다음 테스트 (확정용, 우선순위)

1. **`--no-rag`(LLM off) 장시간** → v8.8처럼 무사고면 **LLM이 원인 확정**(blind는 exotic 안 보냄).
   여전히 크래시면 LLM 아님 → 하드웨어/드라이버/DMA 쪽.
2. **LLM 로그 상관**: `output/pc_sampling_v9.3.0/llm/` 에서 **LLM이 실제로 VirtMgmt/MigrationSend/
   ControllerDataQueue/FWCommit 등 exotic 명령을 제안·전송했는지**. 찍혀 있으면 gap 발화 확인.
   그리고 `pagealloc` dmesg 타임스탬프 ↔ 퍼저 로그 직전 명령 상관.
3. **하드웨어 배제(병행)**: `dmesg|grep -iE 'mce|edac'`, `memtester`/memtest86+, `sensors`,
   `nvme smart-log`(온도/throttle), `dmesg|grep -i iommu`.
4. **콜드 리부팅 후 fresh 단일 실행** → 다시 한동안 깨끗하다 시간지나 터지면 누적/열, 바로 터지면 코드/디바이스.

---

## 6. 수정 후보 (원인 확정 후)

- **`_llm_make_seed`가 `self.commands`(enabled)로 조회하도록 제한** → LLM도 사용자가 켠 명령만 제안
  (`--all-commands` 존중, blind와 동일 안전경계). **가장 깔끔.**
- 또는 커널-손상 exotic 명령을 `is_dangerous`/blocklist에 확대(VirtMgmt/MigrationSend/ControllerDataQueue/
  FWCommit/CapacityMgmt/NamespaceAttachment 등).
- (독립) J-Link halt 샘플러 서브프로세스 격리는 v9.4(`pc_sampling_fuzzer_v9.4.py`, commit bd2742e)에
  이미 구현·스캐폴딩 검증됨(하드웨어 미검증). 단 이번 crash 는 `--no-jlink`에서도 나므로 pylink 격리로는
  해결 안 됨 — **접어둔 상태.**

---

## 7. 이번 세션 코드 변경 (main, 커밋됨)

| commit | 내용 | 상태 |
|---|---|---|
| 20ab3b2 | J-Link DLL 콜백 NULL 해제 시도 | **오판 → 52c0a04로 원복** |
| 52c0a04 | 위 원복 | |
| bd2742e | v9.4: halt 샘플러 서브프로세스 격리 | 구현·스캐폴딩 검증, 하드웨어 미검증, **접어둠** |
| b49c4ac→2fe28e0 | 시작 로그 코드 스탬프 `[CODE] sha=<12>` (버전 미노출) | **유지** |
| 41a070f | 주기적 재-calibration 제거 | **유지**(stateful SSD 부적절) — 단 crash 트리거는 아니었음 |
| 58aeca0 | **faulthandler 제거** | **유지**(진단도구가 크래시 유발) |
| 72710f8 | NVMe 활성 namespace 자동 감지(n1 부재→glob) | **유지** — rc=22(EINVAL) 해소. 사용자 SSD는 `/dev/nvme0n2`. |

### 실행 참고
- 현재 sha 확인: 로그 상단 `[CODE] sha=...`.
- J-Link 포함 실행 = 평소 명령에서 **`--no-jlink`만 제거**. namespace는 자동 감지(또는 `--nvme /dev/nvme0n2`).
- 크래시 진단은 **core dump**(`ulimit -c unlimited`)로 — faulthandler는 실행을 오염시키므로 재도입 금지.

---

## 8. 반성 / 다음 세션 주의
- 이번 조사에서 여러 번(NULL콜백/v9.4격리/재-cal/data_len) **크래시 데이터 없이 추측으로 단정**해 헛다리.
  특히 **faulthandler(진단도구)가 스스로 크래시를 유발**해 그 위 분석이 오염됨.
- 교훈: **추측 패치 전에 (a) 재현이 코드/버전인지 하드웨어/환경인지부터 가르고(--no-rag, memtest, 콜드부팅),
  (b) 진단은 실행 비침습 방식(core dump)으로**, (c) 정적으로 확정 가능한 것(가드/우회경로)부터 코드로 확인.
- **가장 유력·정적확정된 실마리 = §3-3 LLM enabled-set 우회.** 다음 세션은 **§5-1(--no-rag) + §5-2(LLM 로그
  상관)로 이 가설부터 확정/기각**할 것.
