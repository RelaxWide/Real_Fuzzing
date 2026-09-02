# N-Trace 커버리지 계획 — 사내 Claude Code 인계

> ## ⚠️ 이 문서의 핵심 결론은 후속 실측으로 **반증되었다** (2026-09)
>
> 아래 §0 의 *"비침습 대안 전수 감사 완료(결론: N-Trace 유일)"* 및 *"폴링할 PC 소스가
> 하드웨어에 없음"* 은 **2026-08 시점의 결론**이며, 이후 **per-core PC 샘플 레지스터**
> (`TE + 0x1000×core + 0x17C`, bit0=valid)가 실측으로 발견되어 **더 이상 유효하지 않다.**
> 4개 코어 모두 ELF 와 offset=0 으로 100% 매칭 확인됨.
>
> **현재 방향은 PCSR 폴링**이다 → `docs/V10_BM9K1_PLAN.md` 를 볼 것.
> 이 문서는 N-Trace 경로의 기술 자료(ETB/SBA 덤프, Nexus 디코드)로서만 유효하다.

> 대상: 사내 Claude Code. 목적: SF-E76 RISC-V 컨트롤러에서 **비침습 코드 커버리지**를
> N-Trace 로 확보해 SSD 펌웨어 퍼저에 연동.
>
> **IP 경계**: 기밀 주소/레지스터 맵은 `sjtag_addrs.json` **한 파일에만** 있음(이 문서와
> 코드에는 placeholder/개념만). ELF·HTML·펌웨어 바이너리는 **사용자가 실행/열람**, 도구는
> 자기점검 수치만 회신. 이 경계를 유지할 것.

---

## 0. 현재 위치 (완료된 것)

- ✅ Secure JTAG(clavis PKC) 잠금해제 → J-Link connect **한 방에**(`run_debug.sh`).
- ✅ N-Trace **캡처**: 온칩 ETB(SiFive FIFO sink)를 **SBA(System Bus Access)** 로 덤프
  = `--trace-dump` → `trace.bin`(raw Nexus). 트레이스 레지스터는 MEM-AP 불가, SBA 로만.
- ✅ **비침습 대안 전수 감사 완료(결론: N-Trace 유일)**:
  - abstract dpc-while-running(§4.9.2, RISC-V 판 PCSR) = `--pc-probe` 실측 **cmderr=2
    not-supported**(E76 는 abstract 레지스터 접근 자체 미구현 → progbuf=halt 필요).
  - SBA/HSS 는 비침습이나 폴링할 **PC 소스가 하드웨어에 없음**(PC 비메모리맵 + TE
    레지스터맵에 current/last-PC 레지스터 부재).
  - HPM=위치없음, ITM=계측필요, ARM DWT PCSR=RISC-V 미지원, SNAP류=pre-silicon.
  - halt 기반 샘플링은 SSD 워치독/호스트 타임아웃 **가성 hang** 위험 → 안 씀.

**따라서 방향은 N-Trace 로 확정.** 아래는 속도 문제를 엔지니어링으로 흡수하는 단계별 계획.

---

## 1. 설계 원칙 (속도 저하를 흡수하는 핵심)

1. **타깃(펌웨어)은 안 느려짐** — `trTeInstStallEna=0` 이면 인코더가 코어 실행에 무간섭
   (무침습). 부하는 오직 **추출(트레이스 뽑기) + 디코드**.
2. **hcore 1개만** 트레이스 — TE 는 코어별(`te_base + 0x1000*n`). 명령 경로 도는 코어만
   enable → 대역폭·디코드 절감. **5코어 전부 뜨지 말 것**(§Phase A 참고).
3. **데이터 자체를 줄임** — branch-only(data/timestamp off) + **주소 필터**(핸들러 영역만)
   + (선택)압축. 스펙(Trace Control Interface p14)도 "trace window/range 로 데이터 제한,
   특히 멀티코어에서"를 권장.
4. **추출을 퍼저와 비동기 분리** — arm 1회 → per-input 은 Wptr 경계 마킹만 → 백그라운드
   SBA 드레인 → **디코드는 별 프로세스(지연 허용)**. 퍼저 exec/sec 와 디코드 분리.
5. **overflow 는 lossy 수용** — `StallEna=0` 이라 넘쳐도 코어 안 멈춤, 커버리지만 일부 손실
   (퍼징엔 허용). **디코더는 overflow→resync 를 반드시 처리**.

---

## 2. Phase 0 — 실현성 실측 ✅ 구현됨

**질문**: 명령어 1개가 만든 트레이스가 32KB ETB 에 들어오는가?

### 구현된 모드 (`sjtag_unlock.py`)
- `--trace-arm [--trace-core N]`: 선택 코어 TE enable(**StallEna=0 명시 write**) + 다른
  코어 TE 는 끔(**단일소스 보장**) + 버퍼 클리어 + Wptr 베이스라인을 `.trace_state.json`
  에 기록. arm 시 **코어별 `trTeImpl`(+0x4) `trTeCompType==0x1` 탐색표**도 출력(어느
  코어에 TE 가 있나 = Phase A 대상 선별 근거). **코어 실행에 무간섭**.
- `--trace-delta`: arm 이후 **생성 바이트 수**(현재 Wptr − 베이스라인, **wrap 비트 마스킹
  + modulo-buffer**) 와 **overflow(wrap)** 여부 리턴.

### 고정 커맨드 wrapper (sudoers NOPASSWD)
- `run_sjtag_tracearm.sh [CORE]`, `run_sjtag_tracedelta.sh`
- sudoers 예:
  ```
  fuzzer ALL=(root) NOPASSWD: /…/risc-v/run_sjtag_tracearm.sh
  fuzzer ALL=(root) NOPASSWD: /…/risc-v/run_sjtag_tracedelta.sh
  ```

### 절차 (권장: 코어 선별까지 한 번에)
```
# (같은 전원사이클에서 이미 인증돼 있어야 함 — 아니면 먼저 sudo ./run_debug.sh)
for C in 0 1 2 3 4; do
  sudo ./run_sjtag_tracearm.sh $C     # 코어 C 만 켜고 arm
  #   … 대표 NVMe 명령 1개 실행 …
  sudo ./run_sjtag_tracedelta.sh      # 코어 C 의 생성 바이트/overflow
done
```
대표 명령 몇 종으로 반복.

### 판정 (도구가 문구까지 출력)
- **delta ≪ 32KB** (버퍼의 <50%) → per-op 정확 캡처 가능 → **Phase A**.
- **overflow / 과대(>50%)** → TE 트리거·주소필터로 창 좁히기(스펙 권장 완화책) → 관심
  함수/모듈 범위로 재시도.
- **delta=0** → 그 코어는 명령 경로 아님(또는 arm 실패/실행無). → **트래픽 있는 코어만
  Phase A 대상**으로.

### ⚠ Phase 0 주의
- `--trace-delta` 는 **창 내 해당 코어 전체 활동**(idle·타 태스크 포함)을 셈. delta 가
  크면 "명령이 무겁다"가 아니라 **배경 활동**일 수 있음 → 주소필터로 핸들러 영역만 격리 후
  재측정.
- **StallEna 비트 위치 검증 필요**: 도구는 `TECTRL bit13=StallEna`(RISC-V Trace Control
  Interface 표준)로 가정. arm 후 출력에 `StallEna bit13=1` 로 남으면 이 칩의 TECTRL
  비트맵이 다른 것 → **실기서 비트맵 확인**(bit13 이 아니면 stall=침습 위험).
- **TE enable 비트**: 실측(0x69→0x6F)에서 `bit1|bit2` 로 켜짐(active|enable|instTracing).
  도구가 이 조합을 씀. TE 가 enable 안 되면(Wptr 안 늚) 이 비트 조합을 실기서 재확인.

---

## 3. Phase A — 코어별 캡처 루프 (선별된 코어의 정확 커버리지)

**전제 정정**: "trace.bin 에 SRC 필드 없음"은 하드웨어 특성이 아니라 **한 번에 TE 1개만
켜기 때문**. `funnel_base` 가 있다는 건 여러 인코더를 한 sink 로 **합칠 수 있다**는 뜻
(합치면 SRC ID 로 구분). 시분할(1 TE)로 가면 단일소스라 SRC 불필요.

1. **대상 코어 = Phase 0 에서 트래픽 확인된 코어만**(5개 전부 아님). 입력을 코어마다
   replay 해야 하므로 대상이 적을수록 캠페인 비용이 준다.
2. **다른 코어 TE base**: `te_base + 0x1000*n`(이미 알려진 스트라이드) → `trTeImpl` 의
   `trTeCompType==0x1` 로 검증(도구가 arm 시 출력). "역산"이 아니라 **계산+검증**.
   스트라이드/맵이 다르면 SoC 트레이스 토폴로지 자료로 사용자에게 확인.
3. **⚠ funnel 라우팅(누락 주의)**: 코어 N 을 sink 로 보내려면 (TE N enable) +
   **(funnel 의 소스 N 입력 enable/route)** + sink 가 필요할 수 있음. 현재 `funnel_base`
   가 `sram_sink_base` 와 같은 주소로 적혀 있어(결합 블록? json 혼동?), **funnel 이
   소스선택 레지스터를 요구하는지 실기서 확인** 후 라우팅 스텝 추가.
4. 코어마다: `arm(해당 te_base)` → 대상 동작 실행 → `dump(sink)` → 디코드. 5코어 아니라
   **선별 코어** 순회(동시 아님, 링크 하나 시분할).
5. 코어별 커버 블록 집합을 **누적(합집합)**. 캠페인 진행될수록 코어별 정확 커버리지가 참.
6. **코어별 ISA 확인**: 코어마다 misa 다를 수 있음(hcore=RV32IMAC+U+X = 0x40901105).
   디코더가 코어별 ISA 를 맞춰야 함.

---

## 4. Phase B — 디코드 & 리포트 (`trace_cov.py`, 신규)

- **입력**: `trace.bin`(raw Nexus **BTM**/HIST) + 해당 코어 **ELF**.
- **ELF 인제스트**: `objcopy` + `readelf`(심볼/섹션/함수 경계).
- **RISC-V 디코더**: **RV32 + C(압축) 정확 처리**(misa=IMAC, C 포함 — "IMAC+C"는 중복
  표기; 요점은 16-bit RVC 명령 길이/분기분류를 정확히). 분기 분류: 직접 조건분기(HIST
  1비트 소모), 직접 점프(추론=바이너리로 따라감), 간접 점프/call/ret(간접 메시지의 주소).
- **BTM/HIST 재생**(용어: HTM 아님 — HTM 은 ARM): sync 메시지=full PC, indirect=압축주소,
  I-CNT=메시지 간 명령수, HIST=직접조건분기 결과 비트맵 → **정확 블록 복원**.
- **⚠ overflow/error 메시지 처리 필수**(lossy 선택의 필연): overflow 나면 그 창을 "부분
  커버리지"로 마킹하고 다음 sync 에서 **resync**. 안 하면 스트림 전체 디싱크.
- **⚠ 압축 vs 디코더 단순성**: `branch-predictor`/`jump-target-cache`/`repeated-history`
  압축은 대역폭을 줄이지만 디코더를 크게 복잡화. **처음엔 끄고**(단순 디코드) 대역폭은
  1코어+주소필터로 잡을 것. 필터로도 부족할 때만 압축 도입.
- **출력**: 코어별 **자체완결 HTML**(요약/함수표/블록맵) + **JSON**(누적/merge) +
  `--diff`(전후 비교).
- **1Core 상태**: sync+indirect 원리/디코드 검증 완료 → 이 단계에서 **HIST 반영**해 완성.
- **입도**: 우선 **block 집합**(가장 단순), 이후 edge.
- **IP 경계**: 도구만 작성. ELF/HTML 은 사용자가 실행/열람, 도구는 자기점검 수치만 회신.

---

## 5. Phase C — 퍼저 연동 (참고)

- **정정**: "실시간 per-exec 연동 불가"는 과한 표현. 정확히는 **JTAG 드레인+디코드 지연
  때문에 per-exec 실시간 피드백이 비현실적**. async(지연) per-input 은 원리상 가능하나,
  5코어 replay 까지 겹치면 비싸서 **periodic/캠페인 스냅샷이 실용적**.
- **의식적 결정으로 남길 것**: periodic 측정으로 가면 fuzzer 가 coverage-**guided** 가
  아니라 coverage-**measured** 가 됨(가이드 루프 약화). 그래도 캠페인 커버리지 누적 +
  흥미로운 입력 전후 `--diff` 로 스코프 조정은 유효.

---

## 6. 크로스컷 주의 (요약)

| # | 항목 | 요지 |
|---|---|---|
| 1 | **StallEna=0** | arm 시 명시 write(bit13 가정). 실기서 비트맵 검증. |
| 2 | **Wptr wrap** | +0x1C bit0=wrap. delta 는 마스킹+modulo. wrap=overflow. |
| 3 | **funnel/SRC** | 단일소스는 1 TE 만 켜서. funnel 소스라우팅 확인(누락 주의). |
| 4 | **코어 선별** | 5개 전부 아님. Phase 0 delta 로 트래픽 코어만. |
| 5 | **압축** | 처음엔 끔(디코더 단순). 필터로 대역폭 관리. |
| 6 | **overflow 디코드** | lossy → resync 처리 필수. |
| 7 | **인증 지속** | 트레이스 모드는 전원사이클당 latch 된 인증 세션 위에서만. |
| 8 | **용어** | `trTeImpl`(not trTeTmpl), **BTM**(not HTM), RV32IMAC(C 포함). |

---

## 7. 파일 맵 (이번 인계분)

| 파일 | 역할 |
|---|---|
| `sjtag_unlock.py` | `--trace-arm`/`--trace-delta`/`--trace-core`(Phase 0), `--pc-probe`(비침습 판정), 기존 unlock/trace-dump/status |
| `run_sjtag_tracearm.sh` / `run_sjtag_tracedelta.sh` | Phase 0 고정커맨드 wrapper(sudoers NOPASSWD) |
| `.trace_state.json` | arm↔delta 베이스라인 상태(런타임 산출물, 커밋 대상 아님) |
| `sjtag_addrs.json` | ★기밀 주소/레지스터 맵(LOCAL). `trace{te_base,funnel_base,sram_sink_base,mem_type}` 여기에 |
| `trace_cov.py` | (신규, Phase B) 디코더+리포트 — 사내 Claude Code 작성 |

## 8. 사내 Claude Code 가 이어서 할 일

1. **Phase 0 실행 → 판정** 회신(코어별 delta, overflow 여부, 트래픽 코어).
2. 판정에 따라 `--trace-arm` 에 **주소필터**(트TeComp/trTeInstFilters) 추가 — 필터 범위는
   `sjtag_addrs.json` 에서 받게. (핸들러 코어/주소 확정 후)
3. **Phase B `trace_cov.py`** 작성(BTM+HIST+overflow-resync, RV32C, block 집합, HTML/JSON).
4. Phase A **funnel 라우팅** 실기 확인 후 코어 순회 캡처 루프.
