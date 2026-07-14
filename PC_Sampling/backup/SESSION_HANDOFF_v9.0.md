# SESSION HANDOFF — v9.0 (LLM-guided fuzzing + P9 안정화 세션)

> 이 파일이 현재 핸드오프다. 구 `SESSION_HANDOFF_v8.8.md`는 P9 halt bring-up 위주였고,
> 이 세션에서 그 위에 (1) P9 안정화 수정들 (2) v9.0 LLM-guided fuzzing 을 얹었다.

---

## 0. 현재 상태 한 줄
- **최신 = `pc_sampling_fuzzer_v9.0.py`** (`FUZZER_VERSION="9.0.0"`). v8.8 전체 보존 + LLM-guided.
- `--rag` off(기본) 또는 LLM 모듈 import 실패 시 **v8.8 과 byte-동등**.
- **미해결 최우선**: P9 캠페인 중 **호스트 OS freeze**(go_settle 10 에서도 발생) — 아래 4장.

---

## 1. v9.0 LLM-guided fuzzing (신규)

### 개념
기존 fuzzing 루프(변이-발송-측정)는 **무변경**. 스펙 아는 사내 LLM 을 **백그라운드 워커**로
돌려 신규 명령군 시드·멀티-명령 시퀀스를 시드 풀에 주기 주입하고 corpus 를 평가. 상세: `pc_sampling_fuzzer_v9.0.md`.

### 실배포 구조 = 2-PC Samba drop-box (중요)
- **온라인 PC (Windows/PowerShell)**: 사내 LLM 있음. `srag_llm_service.py` + `srag_llm_guide.py`(사용자
  실제 LLM, `generate_rag_response(user_prompt)->str`, system 프롬프트 "참고문서 기반 답변" 내장).
- **오프라인 PC (Linux, fuzzer)**: `pc_sampling_fuzzer_v9.0.py` + `rag/rag_bridge_client.py`(drop-box
  클라이언트, LLM 코드 없음 — 요청 파일 쓰고 응답 폴링).
- **연결**: Samba 공유 폴더 `rag/bridge/`(requests/·responses/). 오프라인 fuzzer 워커가 어댑터 호출
  → 어댑터가 공유폴더에 요청 write → 온라인 서비스가 폴링→LLM 호출→응답 write → 어댑터가 읽어 반환.
  워커 스레드라 fuzzing 안 멈춤. timeout 시 graceful skip.

### 파일 (rag/)
| 파일 | PC | 역할 |
|------|----|----|
| `rag_bridge_client.py` | 오프라인 | fuzzer 가 import(config module_path=`rag.rag_bridge_client`). drop-box 클라이언트 |
| `srag_llm_service.py` | 온라인 | 공유폴더 폴링 → 실제 LLM 호출. 상단 상수 LLM_MODULE="srag_llm_guide"/BRIDGE_DIR |
| `srag_llm_guide.py` | 온라인 | **사용자 실제 LLM**(repo 아님, 사용자 작성). generate_rag_response |
| `rag_schema.py` | 오프라인 | LLM 산출물 in-process 검증(SchemaBridge.from_dict) |
| `mock_llm.py` | dev | 하드웨어·LLM 없이 배선 테스트 |
| `test_llm.py` | 온라인 | srag_llm_guide 단독 점검(JSON 시드 나오는지) |

### 설정 (오프라인 `fuzzer_config.json` rag 섹션)
```
enabled:true, module_path:"rag.rag_bridge_client", func_name:"generate_rag_response",
pass_system_prompt:false   ← 사내 함수가 단일인자(user만)라 필수. fuzzer system 을 user 에 접어 보냄.
```
CLI: `--rag / --no-rag / --rag-module / --rag-func`. `sudo -E` 로 실행(env 전달).

### BRIDGE 경로 조율 (양쪽이 같은 물리 폴더)
- 오프라인 클라이언트 기본 `_BRIDGE = rag/bridge/`(무수정).
- 온라인 서비스 `BRIDGE_DIR` = 오프라인 rag/ 의 Windows 매핑 + `\bridge` (끝에 `\bridge` 필수).
- 즉 오프라인 rag/ 를 Samba 공유로 두면 **오프라인 파일 무수정, 온라인 BRIDGE_DIR 한 줄만** 수정.

### 안전 (3중)
`is_dangerous`(Format/Sanitize/lock/NS-delete drop) → `validate_and_repair`(reserved ENUM reject)
→ `_send_nvme_command` 발송 가드(`RC_SKIP`). LLM 은 새 발송 경로 추가 안 함.

### v9.0 관측/품질 보강 (테스트 세션 추가)
opcode-이진 신호가 캘리브레이션 후 죽는 문제 등 5개 보강 (전부 LLM 경로 안, off=v8.8 동등):
- **① 후보 신호**: `new_group_seeds`를 coverage-gap(미접촉 함수, SA 로드 전제) 주 타깃 + 명령은
  never-sent + under-explored(interesting 오름차순) 랭킹으로. "NOT exercised" 오해 라벨 제거.
- **② JSON 재시도**: 워커에서 응답이 JSON 아니면 교정 리프롬프트로 `json_retries`(기본 2)회 재요청.
- **③ 단계별 로그**: config `rag.debug=true` → `[LLM/raw]`(원본) `[LLM/parse]`(파싱) `[LLM/item]`
  (accept/dup/drop) `[LLM/stats]`(기여도). "LLM품질 / 파싱 / 주입"을 분리 확인 가능.
- **A dedup**: `_llm_seen` 시그니처(cmd+cdw+data)로 중복 시드/시퀀스 재주입 차단(cadence 낮을 때 corpus 폭증 방지).
- **B 기여도 요약**: `[LLM/stats]` 주기 출력 — corpus내 llm시드 수 / favored(컬링 생존=유용) / 누적 주입·drop·dup.
- **테스트값**: `fuzzer_config.json` rag 에 request_cadence=200, plateau=500, debug=true 적용(원복값은
  `_comment_TEST` 에 명시: 5000/20000/false). mock 로 재시도·dedup·로깅 동작 확인 완료.
- **시퀀스 강화(단일시드보다 상태의존 시퀀스가 LLM 강점)**: (a) `task_weights`(seeds:1/seq:2/eval:1)로
  시퀀스 라운드 비중 33%→50% (b) `seq_energy_boost`(2.5)로 SequenceSeed 의 /len 선택 페널티 상쇄
  (c) 시퀀스 프롬프트를 3~5단계 상태전이 체인 요청 + NVMe 패턴 예시로 강화 (d) plateau 시 시퀀스 우선.
  기본값(가중치 미설정=1:1:1, seq부스트 미설정=일반부스트)은 기존 동작 보존.
- **관측 결과(30k execs 테스트)**: 주입/dedup/필터 정상(seeds 55/seqs 6/dropped 12/dupes 19)이나
  favored=0(LLM 시드가 새 커버리지 못 뚫어 컬링). 판정 지표 = `[LLM/stats]` favored 추이 + total_BB 추이.
  favored 지속 0이면 컬링 보호/부스트 상향 필요. → 시퀀스 강화가 첫 대응.

### 검증 상태
mock 로 end-to-end(seeds/sequences 주입, 위험/무효 필터, graceful disable, drop-box 왕복, 단일인자
경로) 전부 통과. **온라인 `srag_llm_guide` 단독 test_llm.py → [PASS](JSON 시드 나옴) 확인됨.**
**실제 2-PC Samba 왕복(`rag/test_bridge.py`) → [PASS] 확인됨** — 온라인 LLM→Samba→오프라인
클라이언트 전 구간 실제 동작. (주의: 온라인 Windows 는 `python3`=Store 스텁이라 반드시 `python`
으로 실행. venv 도 `python3.exe` 미생성이라 python3 새어나감.)
**남은 것: fuzzer `--rag` 실장비 실행(하드웨어 필요) — 아래 절차.**

### fuzzer `--rag` 실행 절차 (다음 단계)
1. 온라인 PC: `python srag_llm_service.py` 띄워둠(`watching ...` 나오고 대기).
2. 오프라인: config `rag.enabled=true`(또는 `--rag`), `module_path=rag.rag_bridge_client`,
   `func_name=generate_rag_response`, `pass_system_prompt=false` 확인.
3. `sudo -E python3 pc_sampling_fuzzer_v9.0.py --product P9 ... --rag` (`-E`=RAG_BRIDGE_DIR env 전달).
4. 확인 포인트: 워커 스레드 기동 로그, RAG_REQUEST_CADENCE(기본 5000 exec)마다 요청, 응답 시드가
   `seed_class='llm_new_group'` 로 corpus 진입, 미탐색 명령군 `cmd_stats` exec 상승.
> freeze 조사 중이면 **freeze-repro 캠페인은 v8.8(--rag 없이) 로 깨끗하게 유지**하고, `--rag` 검증은
> 별도 실행으로 분리 권장(백그라운드 워커·Samba I/O 는 freeze 변수와 무관해야 판정이 깨끗함).

### 사용자 srag_llm_guide.py 주의 (해결됨, 기록용)
- 함수 4개(env+client 생성 / generate_response / retrieve_from_rag / generate_rag_response).
- 초기 실패 원인: (a) env+client 생성 함수를 모듈 레벨에서 호출 안 함(Jupyter 수동 실행에 의존)
  → 모듈 레벨로 이동. (b) `system_prompt` 를 주석처리해 NameError → 고정 상수는 모듈 레벨/함수 안에 살림.
- import 시 1회 setup(함수 밖 최상단), generate_rag_response 는 return(‑ print 아님).

---

## 2. 이번 세션 P9 안정화 수정 (v9.0 에 포함, 커밋됨)
- **펌웨어시간 워치독**: halt 프리즈를 실측·차감해 '진짜 펌웨어 N초'로 crash 판정(+halt_fwtime_margin_sec).
- **halt 노이즈 억제**: pylink warn/error 핸들러로 'could not be halted' → debug. 10-연속 오분류 제거.
- **under-sampling health 모니터**: coverage 정체+halt 실패를 NVMe timeout 동반 여부로 (B)vs under-sampling.
- **FWCommit 코어 리셋 복구**: 성공 FWCommit(0x10) 후 J-Link 재연결(디버그 halt 손실 복구). target_connected().
- **RDDump**: timeout 2h config, PTY 실행(파이프 버퍼링·isatty 회피 → 툴 출력 스트리밍), 전 J-Link 해제.
- **go_settle/halt_poll 튜닝 노브**(config). [FWTime] ms 표기.

---

## 3. 남은 로드맵 (핸드오프 유지)
- v9.0 RAG 실장비 첫 왕복 검증 + 프롬프트 튜닝(JSON 산출률 낮으면 user prompt 지시 강화).
- edge coverage 포화 → state/시퀀스 기반(로드맵 Phase 1~5, 미착수).

---

## 4. 호스트 OS freeze — 결론: halt-vs-controller 타이밍 레이스 (근본원인 캡처 종료)

### 세션 최종 결론 (2026-07 갱신)
- **성격**: 특정 명령이 방아쇠가 아님. 로그 끊김 지점이 [NVMe RET]/[Stats-cov]/[admin-passthru] 제각각
  = halt 샘플러(별도 스레드)가 컨트롤러 활동과 우연히 겹치는 **타이밍 레이스**. 메인스레드 로그는 red herring.
- **go_settle로 튜닝 불가**: freeze까지 명령수 1ms=25만·37만 / 5ms=44만 / 10ms=18만·9만 — 같은 설정서도
  2배+ 분산, n=1~2. go_settle↔freeze 상관이 노이즈에 묻힘 (10ms가 오히려 최단 → "높이면 안전" 반증).
- **캡처 시도 전부 실패·종료**: kdump 캡처커널 2단계(부팅+makedumpfile) 무증거 실패, ramoops는 memmap `$`
  이스케이프 문제로 boot 반복 사망(헤드리스라 콘솔 못 봄). 커널 Call Trace 나와도 "nvme kworker가 wedge된
  컨트롤러 대기"라는 뻔한 확인뿐 → 조치 불가 → **근본원인 캡처 포기가 합리적.**
- **✅ 최종 확정 (2026-07)**: `--no-jlink` 로 **60만 execs 무이상** 확인 → J-Link halt 없으면 안정,
  있으면 1만~45만서 터짐 = **freeze 원인 = halt 샘플링(halt-vs-컨트롤러 타이밍 레이스). 조사 종료.**
- **결정**: (1) default `go_settle_ms=5` (freeze 아닌 샘플링 품질 기준) (2) corpus 체크포인트+재부팅 자동재시작
  으로 freeze를 "리부팅 1회 비용"으로 흡수 (3) **생산적 J-Link 캠페인 = 희소 샘플링(go_settle↑로 halt 수↓
  → 레이스 기회↓, 커버리지 해상도와 트레이드오프) + 복원력**. RAG 실검증은 J-Link 필요(커버리지 피드백)라
  이 복원력 위에서 돌려야 함.

### (구 기록) 증상
P9 캠페인 중 **호스트 Ubuntu 가 logless freeze**(dmesg 확인 불가). 이전 관측: `soft lockup
kworker/u64:3 stuck 26s`, `RIP: 0033:0x1`(유저스페이스 CS + 주소 0x1 = 네이티브 제어흐름 붕괴).

### 지금까지 가설/조치
- go_settle 1→64% 얼음→freeze. 5 로 복원→"없어졌다" 보고. **그런데 10(15% 얼음)에서 재발** →
  **halt duty cycle 만으론 설명 안 됨.** 원인 미확정.
- 유력 사슬: 퍼저가 **halt 도중 네이티브(pylink/JLinkARM DLL) segfault(RIP 0x1)로 죽음** → R5 코어가
  halt 로 굳음 → SSD 컨트롤러 정지 → 호스트 kworker 스핀 → freeze. NVMe 커널 timeout 30일이라 자가복구 X.
- **핵심 미확보 증거**: segfault core dump `bt`(어느 pylink 호출이 0x1 로 튀는지), kernel 쪽 로그.

### 다음에 확인할 것 (아래 5장에 상세)
1. go_settle=10 이 **실제 적용됐는지** 배너 확인.
2. **core dump + netconsole/pstore** 로 증거 확보(logless 라 준비 없이는 매번 무증거).
3. `--no-jlink` 이분법(halt 원인인지).
4. `--rag`/v9.0 관련인지(백그라운드 워커·Samba I/O 새 변수).
5. freeze 직전 명령(FWCommit·PM·특정 opcode).

### 5. 로그 위치
`output/fuzzer_*.log`. 배너에 `Sampling: ... go_settle=Nms` 로 실제값 확인 가능.
