# SF-E76 Secure JTAG unlock → 디버그 → 트레이스 커버리지

SiFive **E76** 기반 SSD 컨트롤러(4-hart, RV32 IMAC+U+X)를 대상으로:
**secure JTAG(PKC/ECDSA) 잠금 해제 → J-Link 디버그 접근 → 온칩 N-Trace 캡처**까지
J-Link Plus(V13.00) + pylink 로 수행한다. 상위 `PC_Sampling/` SSD 펌웨어 fuzzer 의
coverage-guided 루프에 **정확한 실행 커버리지**를 공급하는 것이 최종 목표.

이 문서는 **핸드오버용 정리**다. "어디까지 됐고 / 각 파일이 뭘 하고 / 다음에 뭘 해야 하는지".

---

## 1. 현재 상태 (2026-08)

### ✅ 완료 — secure JTAG 해제 → 디버그 → 트레이스 캡처

전 구간 실기 검증됨:
```
cJTAG warmup → 디버그 전원 → SJTAG PKC 인증(AUTH_PASS) → DM 활성(dmactive=1)
→ hart halt → misa=0x40901105 식별(progbuf) → JLinkExe 'RISC-V identified'
→ N-Trace 인코더 동작 확인 → 온칩 ETB 버퍼를 SBA 로 직접 덤프(trace.bin)
```
- **원스텝 실행**: `sudo ./run_debug.sh` → 인증→JLinkScript생성→JLinkExe autoconnect.
- **트레이스 하드웨어 동작 확정**: TECTRL enable, ETB write pointer>0(버퍼 데이터 있음),
  SBA(System Bus Access)로 ETB FIFO 를 읽어 raw Nexus 데이터 추출 성공.

### 🔜 다음 (핸드오버 대상) — 트레이스 디코드 + 커버리지 시각화

`trace.bin` 은 **raw Nexus(BTM/HTM) 메시지**라, 이걸 **실행 PC/커버리지로 디코드**해야 한다.
- **Ozone 은 막힘**: 이 SiFive sink 는 표준 CoreSight ETB 가 아니라 **FIFO 레지스터 인터페이스**
  (sink+0x24 Data 레지스터)라 J-Link 의 ETB 리더가 못 읽어 "No Data". Ozone 은 외부 .bin
  import 도 없음 → **Ozone 경로 불가**.
- **해야 할 일**: `trace.bin → 실행 PC 집합` 디코더 + `PC → 소스` 매핑 + 시각화.
  자세한 계획은 §6.

---

## 2. 파일 & 역할

| 파일 | 역할 |
|---|---|
| `run_debug.sh` | ★ 원스텝 오케스트레이터: 인증 → JLinkScript 생성 → JLinkExe connect |
| `sjtag_unlock.py` | 메인 툴 — 인증 + 진단(diag/scan) + DM(dm-*) + 트레이스(trace-*) + gen |
| `sfe76_link.py` | J-Link(pylink) 연결 계층. cJTAG init, DAP 전원, AP 맵, json 로더 |
| `dap_access.py` | ADIv6 DP/AP 원시 접근(MEM-AP read/write) — 주소 없는 표준 primitive |
| `sf_e76.JLinkScript.template` | JLinkScript 템플릿(placeholder). cJTAG init + DM 위치 + N-Trace 설정 |
| `sjtag_addrs.json` | ★ **모든 실주소**(AP맵/DM/트레이스/오프셋/상태비트/runtime). 코드엔 주소 없음 |
| `sjtag_addrs.example.json` | 위 템플릿(placeholder 값) |
| `test_sjtag_unlock.py` | 단위 테스트(HW 불필요). 57개 |

### 핵심 설계 원칙 — 주소 단일 출처
- **모든 SoC 실주소는 `sjtag_addrs.json` 에만** 있다. `.py`/`.sh`/`.template`/README 는 placeholder·
  json 필드명만 참조(주소 리터럴 없음).
- 목적: **사내 LLM 컨텍스트에서 `sjtag_addrs.json` 한 파일만 제외**하면 주소가 노출 안 됨.
  git 노출은 허용. (misa=0x40901105 은 주소가 아니라 공개 ISA 값이라 무방)
- 생성물 `sf_e76.JLinkScript`(실주소 채워짐)는 `.gitignore`.

---

## 3. 워크플로우 (실행법)

### 사전 1회 — 로컬 `sjtag_addrs.json` 채우기
`runtime.sjtag_base`(=SJTAG_BASE), `runtime.sign_tool`(서명 .exe 경로) 를 실기값으로.
(`tool_prefix`=wine, `word_order`=t32-negative, `ap_map`/`core_base`/`trace` 등은 이미 채워짐.)

### 원스텝 (인증 → connect)
```bash
sudo ./run_debug.sh              # base/tool 은 json runtime, wine env 는 스크립트 기본값
```
- **인증은 전원사이클마다** 재수행(challenge-response nonce 설계상 세션/전원 단위).
- 이미 인증됐으면 `NO_AUTH=1 sudo ./run_debug.sh`.
- 환경변수: `WINEPREFIX`(기본 /root/.wine32), `JLINK`(기본 JLinkExe; JLinkGDBServer 가능),
  `NO_AUTH=1`.

### 서명 도구(.exe) — 리눅스에서 wine
- `-s3 -f5`→공개키 34워드(정적), `-s1 -f5 <challenge>`→서명 34워드(세션마다 다름), 줄당 1 hex.
- root 용 win32 wineprefix 필요(PE32 라 i386): `wine32 wine64` 설치 + `/root/.wine32`.

---

## 4. 툴 레퍼런스 (`sjtag_unlock.py` 모드)

base/tool/word-order 는 안 주면 json `runtime` 에서 읽음. `--power both` 권장.

**인증**
- `--execute` — 전체 SJTAG PKC 인증(쓰기). 없으면 read-only probe. 성공 후 dm_activate+dm_scan
  이어서 실행. rc: 0/10/11 = AUTH_PASS 확보(각각 DM검증 수준 차이).

**전원/링크 진단 (read-only)**
- `--diag` — DAP 전원 req/ack + 6개 AP IDR 스윕 + sticky. (전원 ACK 실패해도 안 죽음)
- `--read-burst N [--burst-delay MS]` — REQUEST 34워드 × N회 읽어 transport 안정성/드롭 판별.
- `--scan [--scan-window]` — base 뒤 SJTAG 오프셋 live/dead 분류.
- `--analyze-pubkey` — (오프라인) 서명도구 -s3 2회로 정적키 동일성 + word-order 후보.

**DM (RISC-V Debug Module)**
- `--dm-scan` — DM AP 로 dmstatus(version 2/3) 실측.
- `--dm-activate` — dmcontrol.dmactive=1 로 DM 기동 후 dmstatus 확인.
- `--dm-halt` — hart halt → dmstatus.allhalted → misa 읽기(abstract 실패 시 **progbuf** 폴백)
  → resume. J-Link identify 재현.

**트레이스 (N-Trace, SBA 경유)**
- `--trace-status` — TECTRL/TFCTRL enable + ETB Wptr/Rptr 실측(No Data 원인 판별).
- `--trace-dump [PATH]` — ETB 온칩버퍼를 SBA FIFO 로 덤프해 raw Nexus .bin 저장
  (NexusTracedatadump.cmm 이식). 기본 trace.bin.

**생성**
- `--gen-jlinkscript [PATH]` — (오프라인) json 값으로 `sf_e76.JLinkScript` 생성
  (SetcJTAGInitMode + CORESIGHT DM + RISCV_Set* 트레이스).

---

## 5. 기술 노트 (막혔다 풀린 핵심)

**인증 경로 (clavis.cmm 포팅)**
- SJTAG 는 APBAP3(json ap_map)에서 PKC/ECDSA P-521 challenge-response. 34워드 공개키 주입 →
  nonce+chipID challenge 읽기 → 서명 34워드 주입 → grant → AUTH_PASS. word-order 미확정이라
  `--word-order`(t32-negative 기본).

**콜드 DP warmup** — cJTAG 활성화 직후 DP 미동기라 첫 전원요청 write 가 안 먹음(CTRL/STAT=0).
  `prepare_session` 이 DP SELECT/DPIDR priming + req 주기적 재기입으로 warmup 내장.

**transport 견고성** — 일시적 STICKYERR(→CSW SUSPECT/TAR 잘림)를 rd/w/poll 에서 clear+재시도로
  자가복구. (없으면 34워드 주입 중 끊김)

**DM 접근** — DM 은 별도 AP(APBAP1, json core_base_main)의 memory-mapped 레지스터. dmactive=1 로
  깨워야 dmstatus 유효. **CSR 은 abstract 직접접근 미지원(cmderr=2) → progbuf 경유**(progbufsize=16).

**JLinkExe connect** — `SetcJTAGInitMode=1`(SiFive short-form, 없으면 TAP 스캔 IRPrint=0 →
  'Failed to identify') + `CORESIGHT_AddAP/SetCoreBaseAddr`(DM 위치) + `-JTAGConf -1,-1`.

**SBA (System Bus Access)** — 트레이스 레지스터(json trace.* 주소)는 **MEM-AP 로 안 닿고 DM 의
  SBA 로만** 접근(T32 SB:, J-Link MemType=2). `sjtag_unlock.py` 에 sbcs/sbaddress0/sbdata0
  (DMI 0x38/0x39/0x3C) 경유 read/write + FIFO 버스트 구현(`_sba_*`).

**N-Trace / ETB (ViewNexusTracedump.cmm + NexusTracedatadump.cmm 유래)**
- SiFive N-Trace(Nexus 5001): TE(인코더, 코어당 하나) → funnel → 온칩 SRAM sink.
- 주소·mem_type 은 json `trace`(te_base/funnel_base/sram_sink_base/mem_type=2).
- **ETB 레지스터맵**(sink 기준): `+0x1C`=Wptr(bit0=wrap), `+0x20`=Rptr, `+0x24`=Data(읽으면
  자동 advance FIFO). TECTRL/TFCTRL `bit1`=enable. 버퍼 32KB(0x7FFF), 순환.

---

## 6. 다음 작업 — 트레이스 디코드 → 커버리지 (핸드오버)

**목표**: `trace.bin`(raw Nexus) → 실행 PC 집합 → 소스 매핑 → 시각화. 전부 리눅스/오픈소스.

**파이프라인 (T32/Ozone 불필요)**:
```
trace.bin → ① 디코드(Nexus→PC) → ② 매핑(PC→소스, addr2line/DWARF) → ③ 시각화(lcov→genhtml)
```

**① 디코드 (유일한 실작업)**:
- RISC-V N-Trace(Nexus 5001) BTM/HTM 파싱. 입력=trace.bin(+ 정확한 PC 복원엔 실행 코드 필요).
- **권장**: 밑바닥 구현 대신 **레퍼런스 디코더**(`riscv-non-isa/riscv-trace-spec` 의 te_codec)에
  맞춰 먹이기. `G:\RISC-V` 에 N-Trace Spec PDF 있음.
- **커버리지 목적이면** 전체 명령어 복원 없이 **브랜치 타깃 주소 집합**만 뽑아도 충분(더 간단).

**② 매핑**: 트레이스한 코어의 **ELF**(심볼)로 `addr2line -e core.elf 0x<PC>` → 함수/파일:라인.
  (코어마다 별도 ELF, 총 5개 — 트레이스 대상 코어 것 하나 사용.)

**③ 시각화**: PC 히트 → **lcov `.info`** → `genhtml` → HTML 커버리지 리포트(gcov 스타일).

**fuzzer 통합**: 시각화 불필요 — **실행 블록/PC 집합**을 상위 `PC_Sampling/` 루프에 연결(새 커버리지
  준 입력을 favored). per-input: 트레이스 arm(TECTRL enable) → 입력 전송 → dump → 디코드 → 집합.

**미구현 참고**:
- `--trace-dump` 는 **기존 버퍼**를 덤프한다. per-input 캡처하려면 **트레이스 enable(arm)** 이 필요
  (`--trace-arm` 미구현 — TECTRL/TFCTRL bit1=1 write). 인코더가 disabled 면 새 실행이 안 쌓임.
- SBA FIFO 버스트(`_sba_fifo`)는 파이프라인(sbreadonaddr+readondata) 기반이라, 대용량에서
  누락/타이밍 검증 필요할 수 있음(현재 32KB 덤프는 동작 확인).

---

## 7. 테스트
```bash
python3 -m unittest -v test_sjtag_unlock.py     # 57개, HW 불필요
```

## 8. 관련 문서 (로컬 `G:\RISC-V`)
- `SEGGER_UM08001_J-Link_J-Trace.pdf`, `SEGGER_J-Link_command_strings.md`(RISCV_Set*/SBA),
  `SEGGER_J-Link_cJTAG_specifics.md`(KEEPER), `RISC-V_N-Trace_Specification.pdf`(디코드),
  `SiFive_Trace_and_Debug.md`, `Arm_CoreSight_SoC-400.md`.
- T32 원본(사용자 제공): `clavis.cmm`(인증), `ViewNexusTracedump.cmm`(트레이스 컴포넌트 주소),
  `NexusTracedatadump.cmm`(ETB 덤프 절차).
