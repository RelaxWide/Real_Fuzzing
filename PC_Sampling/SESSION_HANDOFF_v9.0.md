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

### 검증 상태
mock 로 end-to-end(seeds/sequences 주입, 위험/무효 필터, graceful disable, drop-box 왕복, 단일인자
경로) 전부 통과. **온라인 `srag_llm_guide` 단독 test_llm.py → [PASS](JSON 시드 나옴) 확인됨.**
**남은 것: 실제 2-PC Samba 왕복 → fuzzer `--rag` 실행.**

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

## 4. 미해결 최우선 — 호스트 OS freeze (go_settle 10 에서도 발생)

### 증상
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
