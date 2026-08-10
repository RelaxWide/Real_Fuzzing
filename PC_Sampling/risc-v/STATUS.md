# SF-E76 브링업 — 현황 (자립 문서)

> 2026-08-10. **이 문서 하나로 이어받을 수 있게 쓴다.**
> 상세 이력 `BRINGUP_riscv_v10.md` / 외부 검토 `feedback.md` / 실행법 `README.md`

---

## 0. 목표

**J-Link Plus + cJTAG 로 SF-E76 SSD 펌웨어의 코드 커버리지를 트레이스 기반으로 추출.**
halt/PC 샘플링은 **안 한다**(T32 도 그 방식이 아님이 확인됨).

기존 `pc_sampling_fuzzer_v9.7.py` 의 NVMe·코퍼스·변이·LLM·replay·POR 는 전부 재사용.
새로 만들 것은 **커버리지 수집 계층**뿐.

---

## 1. 확정된 사실

### 1.1 연결 (실측)

```
인터페이스   cJTAG, TIF=7, 10MHz     ← 1000kHz 로 낮추면 활성화 자체가 실패
DPIDR        0x11013913
               DESIGNER = 0x489  = SiFive
               VERSION  = 3      = DPv3  → ADIv6 / CoreSight SoC-600
               ⇒ AP 를 APSEL 이 아니라 **주소**로 지정한다
J-Link       Plus, FW V13 / 소프트웨어 **V9.66** (V9.12 → 업그레이드 완료)
```

**동작하는 설정 (pylink + exec_command, connect 前 주입):**
```
SetcJTAGInitMode = 0
set_tif(7) / set_speed(10000)
CORESIGHT_AddAP = Index=0 Type=APB-AP Addr=0x10000     # APBAP1
CORESIGHT_AddAP = Index=1 Type=APB-AP Addr=0x20000     # APBAP2
CORESIGHT_AddAP = Index=2 Type=AXI-AP Addr=0x30000     # AXIAP1
CORESIGHT_AddAP = Index=3 Type=AHB-AP Addr=0x40000     # AHBAP1
CORESIGHT_AddAP = Index=4 Type=APB-AP Addr=0x50000     # APBAP3
CORESIGHT_AddAP = Index=5 Type=APB-AP Addr=0x60000     # APBAP4
CORESIGHT_SetIndexAPBAPToUse = 0
CORESIGHT_SetCoreBaseAddr    = 0x81480000   # 또는 0x81481000
connect('RISC-V')
```
> AP 주소는 T32 `SYStem.CONFIG.APBAP1.Base DP:0x10000` 등에서 옴.
> `CORESIGHT_AddAP` 의 `Index` 는 **J-Link 내부 맵 번호**이지 APSEL 이 아니다.

**JLinkScriptFile 경로는 폐기** — cJTAG 스캔을 깨뜨린다(`IRPrint=0x..0000`).

### 1.2 코어 / DM

| 코어 | DM (COREDEBUG.Base) | 코드 영역 |
|---|---|---|
| hcore / CMCore / Fcore0 / QCore | `0x81480000` | **`0x0 ~ 0x21BFFF`** (≈2.2MB) |
| Ncore | `0x81481000` | 위 매핑에서 **제외** — 다른 코드/메모리 |

코드 영역 근거: `attach.cmm` 의 `MAP.BOnchip 0x0++0x21BFFF` (= 쓰기 불가 영역 선언).
→ **커버리지 필터 · 디코더 디스어셈블리 범위 · Ghidra 로딩 base 로 그대로 쓴다.**

⚠ SEGGER 명시 한계: **"Multiple debug modules (DM) are not supported"** — J-Link 은 DM 하나만.

### 1.3 ★ T32 커버리지 메커니즘 (`NexusTracedatadump.cmm` 실물)

```
TE control        ESB:0xFD000000     bit1 = enable
TF control /
ETB base          ESB:0xFD180000     ← 둘이 같은 주소
  +0x1C  write ptr   (bit0 = wrap 플래그)
  +0x20  read ptr
  +0x24  data        (읽을 때마다 자동 증가)
버퍼              32KB (0x7FFF)
출력              Data.SAVE.Binary → .bin  (원시 Nexus 바이트)
```

**절차:** TE disable → TF disable → write ptr 로 wrap 판정 → read ptr 설정
→ data 반복 읽기 → 파일 저장. **halt 가 어디에도 없다.**

**`ESB:` 가 세 가지를 확정한다** (TRACE32: `E`=실행 중 접근, `SB`=System Bus/SBA):
1. **SBA 가 이 칩에 구현돼 있다** (SiFive Insight 에서는 optional)
2. **커버리지 수집에 halt 불필요** — 계획의 핵심 전제 확인
3. ★ **DM 은 정상 동작한다.** SBA 는 DM 의 일부다 →
   **우리 `dmactive` 실패는 칩 한계가 아니라 우리 설정 문제**

**J-Link 의 N-Trace 지원이 없어도 된다** — 스크립트는 순수 레지스터 read/write 다.
필요한 건 "그 주소에 32비트 접근" 하나뿐.

### 1.4 퍼저 구조 (여기서 정해짐)

```
TE enable → NVMe 명령 1개 실행 → TE disable → 버퍼 드레인 → 디코드 → 그 명령의 커버리지
```
명령당 32KB 면 충분. **halt 가 없어 ARM 제품의 호스트 프리즈 문제가 원천적으로 없고,
부분맹(halt under-sampling)도 사라진다** — 완전한 분기 트레이스.

### 1.5 J-Link 버전 의존성 (문서 확인)

`RISCV_Set*BaseAddr` 의 `MemTypeToUse`: **0=Core / 1=DMI / 2=SBA**
- **DMI 접근 V9.56+**, **SBA 접근 V9.62+**
- V9.12 에서는 Core access(=halt 필요)뿐이었다 → **V9.66 으로 해소됨**

---

## 2. 현재 블로커

```
Timeout waiting for debug module to become active     ← dmcontrol.dmactive 안 올라옴
Failed to power-up DAP                                ← 그 위 계층에서 이미 실패 가능
```

DMI 위치까지는 인식(DPIDR / AP map / CoreBase). **DM 이 active 로 응답하지 않는다.**

### 가설과 상태

| | 가설 | 상태 |
|---|---|---|
| A | 디버그 인증/잠금 | **약함.** Spec p30: 미인증 상태에서도 `dmactive` 는 읽기·쓰기 가능해야 한다 |
| B | DMI aperture 주소·매핑 오류 | **유력.** CoreBase 는 T32 해석에서 온 추정 |
| C | DM 전원/클럭 게이팅 (ARM DAP 전원과 별개) | 유력 |
| D | 잘못된 DM (둘 중) | 가능 |
| **E** | **AP 6개 등록이 J-Link 열거를 깨뜨림** | **미검증** ← `probe_dap.py` |

### 시험 결과 (2026-08-10)

```
probe_dm.py          DM aperture 직접 읽기 → 전부 실패
                     (connect 실패 시 memory_read32 가 안 되므로 예상 범위)
probe_trace_regs.py  [A] connect+memory_read32, [B] CoreSight AP 직접 → 모두 실패
                     E76 device 지정 시: connect 1차 "Could not find supported CPU",
                     2차 성공, 그래도 [A][B] 실패
```

> ⚠ **`[B]` 실패는 증거가 약하다.** CoreSight AP 직접 접근은 **우리 코드로 한 번도
> 성공한 적이 없다**(예전에도 전부 `0x80000000`/0). "트레이스 블록이 MEM-AP 에 없다"
> 인지 "우리 코드가 원래 안 된다" 인지 **구분되지 않는다.**

---

## 3. 도구

| 파일 | 목적 | 상태 |
|---|---|---|
| `sfe76_link.py` | **연결 계층 정식 모듈.** checked API(`connect_checked`/`halt_checked`/`read_pc`/`resume_checked`) | 사용 중 |
| **`probe_dap.py`** | **DP 계층만** — DPIDR / 전원 ACK / **AP 등록 개수(0·1·6) 비교** | ← **다음 실행** |
| `probe_trace_regs.py` | 트레이스 레지스터에 MEM-AP 로 닿는지 | 실패 (위 주의 참조) |
| `probe_dm.py` | DM aperture 직접 읽기 + `dmstatus` 디코드 | 실패 |
| `verify_halt_pc.py` | halt/PC/resume (**보조 트랙**) | halt 실패로 막힘 |
| `diagnose_connect.py` | 첫 connect 실패 원인 (후보별 프로세스 격리) | 보조 |
| `backup/` | 역할 끝난 도구 + 각각이 밝혀낸 것 | 참고 |

**종료 코드:** 0 정상 / 2 connect / 3 halt / 4 PC / **5 resume 실패(보드 복구 필요)** / 6 불충분

---

## 4. ⚠ 지켜야 할 원칙

1. **한 handle = 한 설정.** 조합을 섞으면 (a) 한 번 붙은 뒤 전부 거짓 성공(24개 중 23개)
   또는 (b) 조합마다 close 하면 전부 실패. **둘 다 실측으로 겪었다.**
2. **첫 `connect()` 는 실패한다** (현재 도구/보드 조건 한정). bounded retry 3회는 **임시 우회**.
3. **halt 후 반드시 resume + 확인.** 단, **halt 가 애초에 실패했으면 resume 실패는 거짓 경보**다
   (`restart()` 는 halt 상태가 아니면 no-op 으로 False 반환).
4. **APB 메모리 접근 ≠ RISC-V DMI 레지스터 접근.** `dmcontrol 0x10` 은 DMI 주소이지
   byte offset 이 아니다. aperture 레이아웃 확보 전 `base+0x10` 식 접근 금지.
5. `connect()` 무예외 종료 ≠ 성공. **트랙별 실제 산출물**(halted 상태 / bitmap 변화 /
   raw trace)로 판정한다.

---

## 5. 폐기된 결론 (반복 금지)

| 한때 결론 | 실제 |
|---|---|
| `0x81480000` 은 연결 실패 | 틀림 — 항상 첫 자리였을 뿐. **순서 문제** |
| T32 재시도 루프 = 연결 불안정 | 틀림 — 첫 connect 가 구조적으로 실패하는 것 |
| 두 DM 모두 접근 가능 | 과함 — connect 후보 통과일 뿐 |
| resume 실패 → 보드 복구 필요 | 거짓 경보 — halt 가 안 돼 멈춘 적이 없었다 |
| halt/PC/resume 이 v10.0 착수 조건 | 틀림 — **T32 커버리지는 halt 방식이 아니다** |
| ~~JLinkScript 로 CoreSight API 사용~~ | 현재 훅·호출 순서에서 동작 안 함. **cJTAG 스캔도 깨뜨림** |
| DPIDR = `0x6BA0009D` | 구버전/깨진 경로의 값. **실제는 `0x11013913`** |

---

## 6. 다음 할 일

### P0 — 지금

**`sudo python3 probe_dap.py`**
DP 계층만 본다. **AP 를 6개 등록하는 것이 방해인지**(가설 E)를 가른다.
6개 중 실재가 확인된 AP 는 **하나도 없다.**

| 결과 | 다음 |
|---|---|
| AP 0개는 ACK, 6개는 실패 | **AP map 을 줄인다** — 정보 없이 고칠 수 있는 경우 |
| DPIDR 유효 + ACK 없음 | 전원 인가가 진짜 블로커 → T32 초기화가 답 |
| ACK 성공 | 문제는 그 위(AP 주소 / DM) |
| DPIDR 무효 | cJTAG 계층 회귀 → 타깃 전원 사이클부터 |

### P1 — T32 `attach.cmm` 에서 확보 (확인된 것 제외)

- ~~`SYStem.Up` 직전 시퀀스~~ → **확인 완료: `DynUTLoad.cmm` 의 재시도 루프뿐, 커스텀 없음**
- **`SYStem.CONFIG` 전부** — 특히 `DMI` / `DEBUGMODULE` / `DMBASE` 항목.
  **`COREDEBUG.Base` 말고 별도 DM 지정이 있으면 우리 CoreBase 가 틀린 것**
- **SBA / ESB 활성화 설정** — T32 는 SBA 를 쓰는데 그 전제 조건이 어딘가에 있다
- **TE 켜기·필터 설정** — 덤프 스크립트에는 **끄기만** 있다. 다른 파일에 있을 것
  (`TECTRL` 전체 비트, **BTM vs HTM**, **주소 범위 필터** ← 32KB 엔 거의 필수, sync 주기)

### P2 — 벤더 질문 (아주 짧아졌다)

> 1. **RISC-V DM 의 DMI aperture base** 와, DMI 레지스터가 그 안에서 어떻게 매핑되는지(stride)
> 2. **DM 전원/클럭에 별도 인에이블이 필요한지** (ARM DAP `CDBGPWRUPREQ` 와 별개인지)
> 3. DM 이 둘인데 **어느 것이 유효하고 각각 어느 AP 뒤**인지
> 4. **펌웨어 이미지 + 심볼(ELF)** — 디코더의 하드 의존성
> 5. NVMe 명령을 처리하는 코어는? (`hcore` 추정)

### P3 — 커버리지 파이프라인 (블로커 해소 후)

```
1. ETB 포인터 로직 구현      T32 스크립트와 동일 순서. J-Link 은 32비트 read/write 만
2. raw Nexus 바이트 덤프     .bin
3. 디코더                    Nexus 메시지 + 디스어셈블리 → PC 시퀀스
4. PC → BB/함수 매핑         ★ 기존 퍼저에 이미 있음 (Ghidra RISC-V export 만 새로)
5. 집계/시각화               ★ 이미 있음 (BB%, func%, firmware_map)
```

**디코더 공수 줄이는 법:**
- SiFive 공개 디코더 확인 (GitHub `sifive/`)
- **T32 를 정답지로** — 같은 workload 의 raw `.bin` + T32 디코드 결과를 대조하며 개발
- **단계적** — Sync/간접분기 메시지는 **실제 주소를 그대로 담는다.** 디스어셈블리 없이
  뽑아 **부분 커버리지로 퍼저를 먼저 띄우고**, 완전 디코더로 나중에 교체

### 커버리지 매핑에 필요한 것 (확인됨)

| 가진 것 | 얻는 것 |
|---|---|
| 바이너리만 | 실행된 주소/BB |
| + Ghidra | + 함수 경계 (이름은 `FUN_xxxx`) |
| **+ 심볼(ELF/map)** | **+ 진짜 함수 이름.** 디코드 정확도도 올라감(RVC 정렬) |
| + DWARF | + 소스 파일/라인 |

**소스만으로는 안 된다** — 칩에 올라간 **그 바이너리**가 필요하고, 빌드가 다르면 주소가 밀린다.

---

## 7. 게이트

| 주 트랙 (커버리지) | | 보조 트랙 (halt PC 샘플링) | |
|---|---|---|---|
| C0a T32 동작 확인 | ✅ | G0 cJTAG/DP/전원 | ⚠️ (DAP 전원 재확인 필요) |
| C0b 재현 artifact 보존 | 🔶 덤프 스크립트만 | G1 connect | ⚠️ 조건부 |
| **C1 메커니즘 식별** | ✅ **완료** | G2 halt | ❌ |
| C2 데이터 경로·하드웨어 | ✅ 온칩 ETB, 핀 불필요 | G3~G6 | ⬜ |
| **C3 J-Link 지원 가능성** | 🔶 명령은 있음, **접근 미확인** | | |
| **C4 raw 1회 회수** | ❌ ← **여기서 막힘** | | |
| C5 T32 결과와 교차 검증 | ⬜ | | |
| C6 퍼저 반복·복구·성능 | ⬜ | | |
