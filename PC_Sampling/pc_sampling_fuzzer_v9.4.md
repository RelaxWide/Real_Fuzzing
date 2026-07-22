# pc_sampling_fuzzer v9.4

> per-version 규칙: `v9.4.py` = `v9.3.py` byte-copy + 아래 편집만. 베이스라인 v9.3 은 불변.
> (참고: 이전의 "J-Link 프로세스 격리 v9.4" 는 크래시 원인이 J-Link native 가 아니라 호스트
> kernel debug 계측이었음이 밝혀져 폐기 → `backup/pc_sampling_fuzzer_v9.4_shelved.*`.
> 자세한 경위는 `HANDOFF_crash_investigation.md`.)

## 한 줄 요약

v9.3 위에 **커버리지 소스 라벨링 + SC discovery-count(안 A) + 3축 성장 데이터 persist**를 넣고,
그 데이터를 읽어 그리는 **별도 오프라인 그래프 파일**(`coverage_growth_plot.py`)을 추가했다.

## 설계 결정 (왜 이렇게)

- **커버리지 축은 3개**: `edge-cov`(코드), `state-cov`(FTL/telemetry 상태), `sc-cov`(펌웨어 응답).
  각 축은 이미 전용 `[+]` 로그가 있음(`[+][Edge-Cov]`, `[+][State-Cov]`, `[+][SC-depth]`).
- **소스는 직교 태그**: `origin(mutation|llm) × form(cmd|seq|iowl|replay)`. `[+][Seq-Acc]`·`[+][PM-Cov]`
  는 별도 축이 아니라 seq/pm 이라는 **소스로 얻은 edge/state** 라서 태그로 흡수.
  (v9.4 fix: 시퀀스 경로는 `_account_command` 에 시퀀스 내부 개별 `Seed` 가 넘어와
  `isinstance(SequenceSeed)` 로는 `seq` 를 못 잡았고, edge 는 seq_sink 분기가 `_cov_credit` 를
  아예 안 불러 by_src 에서 누락됐음. → 호출부가 `seq_member` 플래그를 넘겨 `form='seq'` 확정 +
  seq_sink 분기에 edge 크레딧 추가.)
- **축마다 분모 성질이 다르다(정직하게 혼합, 억지 통일 안 함):**
  - `edge` = **%** — Ghidra 정적분석이 전체 BB/func 를 주므로 분모 존재(`_sa_total_bbs`/`_sa_total_funcs`).
  - `sc` = **discovery-count (안 A)** — 분모/스펙테이블 없이 **누적 distinct `(cmd, status)`**. 스펙은
    계속 변해 per-command status 테이블 유지가 비현실적이라 분모를 안 씀(= AFL 방식의 발견 카운트).
  - `state` = **discovery-count** — 누적 distinct state 시그니처(`_state_seen`, `causes` 기준).
    (v9.4 fix: 이전엔 `len(state_corpus)` 를 썼으나 `_cull_state_corpus`(dedup+cap 50)로
    감소·톱니가 나서 "누적"이 아니었음 → cull 무관한 단조 집합으로 교체.)
- **구 `SC-depth(0~3)` 위상 변경:** 0~3 은 "분모가 없어서" 쓰던 거친 진행 서수(`_sc_depth`, 스펙
  아님·구조적). SC 커버리지는 이제 discovery-count 가 담당하고, 0~3 은 프론티어 진입 판정용
  **보조 마일스톤**으로만 남음(`[+][SC-depth]` 로그, is_interesting 보상).
- **그래프는 별도 파일(오프라인):** 인프로세스 matplotlib 반복 렌더가 인터프리터 힙을 손상시킨
  전례가 있어, 퍼저는 데이터(jsonl)만 쓰고 렌더는 분리 프로세스가 한다.

## 변경 상세 (`pc_sampling_fuzzer_v9.4.py`, 라인 근사)

| 위치 | 내용 |
|---|---|
| **119** | `FUZZER_VERSION = "9.4.0"` |
| **~3488** | 초기화: `self._sc_seen: set`(안 A 누적), `self._state_seen: set`(state 누적, cull 무관 — v9.4 fix), `self._cov_by_src: dict`(소스별 누적), `self._cov_growth_hist: list` |
| **~5206** | 헬퍼 `_cov_src_tag(seed, source, seq_member=False) -> 'origin/form'`(v9.4 fix: `seq_member` 로 `form='seq'` 확정), `_cov_credit(src, axis, n)` |
| **~5663** | `_account_command` 내 `_ns`(status) 처리부: distinct `(track_key, _ns)` 신규면 `_sc_seen` 추가 + `_cov_credit(src,'sc')`(src 에 `seq_member` 전달) + **`[+][SC-Cov] cmd=.. src=.. status=.. total_sc=N`** 로그 |
| **~5820** | v9.4 fix: seq_sink 분기(시퀀스 member interesting)에서 `new_pcs>0` 시 `_cov_credit(src(seq_member=True),'edge',new_pcs)` — 시퀀스 edge by_src 누락 해소 |
| **~5856** | `[+][Edge-Cov]`/`[+][SC-depth]` 로그에 `src={_edge_src}` 추가, edge 신규 시 `_cov_credit(src,'edge',new_pcs)`(단일 명령 경로) |
| **~5914** | 상태출력 주기마다 3축 스냅샷 → `_cov_growth_hist` append + **`output_dir/coverage_growth.jsonl`** 에 한 줄 append. static 없어도 sc/state 는 기록. `state_count`=`len(_state_seen)`(v9.4 fix) |
| **~6018** | v9.4 fix: `state_corpus.append` 지점에서 `_state_seen.add('|'.join(sorted(causes)))` — cull 무관 누적 |

### v9.4 ledger (관측 전용 — 궤적 불변, v9.5 Phase 0 데이터 토대)

퍼징 결정 로직은 이 값을 **하나도 읽지 않는다**(순수 관측). v9.5 의 matched-contrastive
feedback·bandit reward·transition 재현성 측정이 읽을 데이터를 미리 깔아둔다.

| 위치 | 내용 |
|---|---|
| `Seed`/`SequenceSeed` | `prov_id: Optional[int]` 필드 추가(LLM 제안 계보 id) |
| 초기화(`_sc_seen` 옆) | `_run_id`, `_prov_counter`, `_ledger_fh`, `_prop_fh`, `_cg_warned`, `_ledger_dropped`, `_ledger_wwarn`, **`_credit_seed`**(iteration 계보 소스) |
| 헬퍼(`_cov_credit` 뒤) | `_run_id_get()`, `_prov_next()`, `_ledger_write()`/`_proposal_write()`(lazy jsonl). write 실패 → `_ledger_record_dropped()`(유실 카운트 + 최초 1회 warn) |
| main loop | iteration 최상단 `self._credit_seed = None` 리셋 + det/seq-continuation/base 각 분기에서 **실제 소스 corpus 시드**를 `_credit_seed` 에 세팅(계보 귀속 전용, 스케줄 미참여) |
| `_llm_apply_result` | 수용된 LLM 시드/시퀀스/**io_patterns descriptor** 에 `prov_id` 부여 + `llm_proposals.jsonl` 기록. 시퀀스는 멤버 전원 동일 `prov_id`. workload 는 descriptor `prov_id` 를 버스트 전 명령 + **read pre-write**(`_wl_prewrite_read_targets(prov_id=...)`)까지 전파 |
| `_account_command` 상단 | `_led_sc` 선캡처, `_led_new_sc` 플래그 |
| `_account_command`(timeout 처리 前) | **주목할만한 실행만** → `outcome_ledger.jsonl`. **prov_id 귀속**: 실행시드 직접 보유 시 `prov_source='direct'`; 없으면 **iteration `_credit_seed`** 에서만(`'parent'`). **source 로 추론 안 함** — det/random(source='c1' 이나 `_select_seed` 미경유)의 stale 오귀속·c2 replay 뒤 정당 선택 누락 둘 다 제거. **mutation 경로 무수정** |
| `coverage_growth.jsonl` | 무음 `except: pass` → 최초 1회 warn(`_cg_warned`). 스냅샷 row 에 `run_id`+`ledger_dropped` 추가 |
| `_calibrate_seed` | calibration 은 `_account_command` 우회 → 개별 record 없음. **요약 outcome**(`kind='calibration'`: runs/stability/new_pcs/cal_timeout) 을 prov_id 보유·신규발견·timeout 시 1줄 기록 → proposal 평가 데이터 구조적 누락 해소 |

산출물(`output_dir/ledger/`, run 타임스탬프별 파일):
- `outcome_ledger_<ts>.jsonl` — 한 줄=주목 실행 1건: `{run_id, exec, elapsed_s, cmd, src, seed_class,
  prov_id, prov_source, rc, sc, sc_depth, sc_depth_adv, sc_new, new_pcs, interesting, source}`
  (+ calibration 요약: `kind='calibration', runs, stability, cal_timeout`)
- `llm_proposals_<ts>.jsonl` — 한 줄=수용된 LLM 제안 1건: `{run_id, prov_id, task,
  kind(seed|seq|workload), exec, elapsed_s, seed_class, command|members|pattern, ...}`
- **조인**: `outcome.prov_id == proposal.prov_id`. `prov_source`: `direct`(실행시드 직접) / `parent`
  (iteration `_credit_seed`) / `null`(미귀속). **한계(정직)**: `prov_id` 는 **직접 계보만** 설명 —
  device-state carryover·corpus 경쟁·splice(두 부모)·corpus_eval 재가중 같은 **간접효과는 귀속 불가**
  (campaign A/B 몫). 전체 계보 전파(mutation/splice)·`selected` 이벤트·horizon/감쇠 reward 는 v9.5.

### 소스 태그 taxonomy

- `origin`: `llm`(= `_is_llm_seed`, seed_class 가 'llm*') / `mutation`(그 외 — 스펙 모르는 전통 변이 경로)
- `form`: `iowl`(source=='workload') / `replay`(source=='c2') / `seq`(`SequenceSeed`) / `cmd`(그 외)
- 예: `src=llm/cmd`, `src=mutation/cmd`, `src=llm/iowl`(LLM-지시 IO 워크로드 — 겹침이 명확히 드러남)

### `coverage_growth.jsonl` 스키마 (한 줄 = 한 스냅샷)

```json
{"exec": 12000, "elapsed_s": 2400.0,
 "bb_pct": 41.2, "func_pct": 55.7,        // static 없으면 null
 "sc_count": 37,                          // 누적 distinct (cmd,status)
 "state_count": 12,                       // 누적 distinct state 시그니처(_state_seen, cull 무관)
 "by_src": {"mutation/cmd": {"edge": 900, "sc": 15, "state": 0},
            "llm/cmd":   {"edge": 120, "sc": 18, "state": 0},
            "llm/iowl":  {"edge": 2,   "sc": 4,  "state": 0}}}
```

## 그래프 파일 (`coverage_growth_plot.py`, 신규)

퍼저와 분리 실행. `coverage_growth.jsonl` 을 읽어 입력 폴더에 PNG 3장 생성:
- `coverage_growth_axes.png` — **G1 small-multiples**(3단, X 공유): edge=% / sc=count / state=count
- `coverage_growth_normalized.png` — **G2 self-정규화 겹침**(각 축 ÷ 최종값): 성장 모양·포화 타이밍
- `coverage_growth_by_source.png` — **G3 소스 stacked**(edge/sc): 누가 성장을 만들었나

```bash
/home/ssd/gdbfuzz/.venv/bin/python3 PC_Sampling/coverage_growth_plot.py output/<run_dir>/
#   [--x exec|time]  X축 전환. matplotlib 필요(.venv). 플롯 텍스트는 ASCII(폰트 한글 글리프 없음).
```

## 검증 상태

- `py_compile` OK (v9.4.py, coverage_growth_plot.py)
- 합성 `coverage_growth.jsonl` 로 3장 렌더 확인 — edge% 포화 + sc/state discovery 상승이 정상 표시
- **ledger 스모크 OK** — 헬퍼(`_run_id_get`/`_prov_next`/`_ledger_write`/`_proposal_write`)가 유효
  jsonl 2종을 생성하고 `outcome.prov_id == proposal.prov_id` 조인이 동작함을 스텁으로 확인
- **하드웨어 실측 미검증** (실제 run 의 jsonl 로 렌더·수치·ledger 귀속 확인 필요)

## 아직 안 한 것 / 다음 작업 (resume용)

- **v9.5 로 넘긴 것(동작 변경/트래픽 주입이라 버전 경계)**: boundary-capture harness(+no-op
  control), Phase 0 LLM 루프 수정(plateau starvation cap, FFM 단방향 판정 제거, recency/novelty
  stratified `corpus_eval`, matched-contrastive feedback), hard wear/brick guard 집행. v9.4 는
  **관측만**(궤적 불변) 유지 — ledger 는 그 정의에 맞아 v9.4 에 포함.
- **ledger 오귀속 정직성 수정 완료(v9.4)** — source 추론 폐기하고 iteration-local `_credit_seed`
  (det/seq/base 분기 세팅, 최상단 리셋)로 명시 귀속 → det/random stale·c2 뒤 정당선택 누락 둘 다
  제거. io_patterns descriptor+read pre-write 까지 prov_id 전파. calibration 요약 record 추가.
  ledger write 실패 유실 카운트(`_ledger_dropped`)+warn-once. plot `--run` 필터(기본 마지막 run).
- **staleness 버그 수정 완료(v9.4, 궤적 변경 1건)** — `_account_command` 의 v9.2 staleness 갱신을
  전역 `_last_selected` → iteration 소스 `_credit_seed` 로 교체. 기존엔 workload/c2/random 이 새 PC 를
  내면 `_select_seed` 미경유인데도 무관 corpus 시드의 감쇠를 리셋해 스케줄을 왜곡했음(v9.3 버그).
  **이 한 줄이 v9.4 의 유일한 궤적 변경** — 따라서 v9.4 는 "순수 관측 오버레이"가 아니라 "관측 +
  staleness 정직성 수정 1건"이다. **ablation 함의**: B0(mutation-only, `--rag` off)/B1(LLM)은 반드시 **동일 v9.4 코드**
  에서 `--rag` 토글로 비교(과거 v9.3 run 과 직접 비교 금지). 정상 c1 경로는 동작 동일(회귀 없음).
  `_last_selected` 는 이제 write-only(무해·잔존).
- **ledger 전체 계보 전파·인과는 v9.5** — `prov_id` 는 **직접 계보만** 설명(간접효과=campaign A/B).
  변이/splice 전 구간 전파, `parent_prov_ids`, `pull_id`, `selected` 이벤트, horizon+감쇠·opportunity
  정규화 reward, sibling/nearest-neighbor 매칭(matched-contrastive)은 v9.5 스케줄러 몫.
- **`trace_len`(halt 샘플 수) per-record 미포함** — ledger 가 `rc`+`src`+`sc` 는 남기지만 halt
  샘플 수는 아직. fast-fail 가설 확정용으로 `len(sampler.current_trace)` 를 record 에 추가 가능.
- **`[+][State-Cov]` 에는 src 태그 미추가** — state 발견은 명령 시퀀스 단위라 단일 소스 귀속이
  애매해서 제외. source-stacked 그래프의 state 도 비움(정직). 필요하면 IO-WL 패턴 태그
  (`_wl_active_pattern`) 정도로 근사 귀속 가능.
- **`rc` / `trace_len`(halt 샘플 수) per-command 진단 로깅 미구현** — 원 조사 맥락: "LLM 명령일 때
  halt PC 가 안 잡히는 것 같다"는 **fast-fail 가설**(exotic/invalid 명령이 즉시 거부돼 halt 창이
  0). 이걸 확정하려면 명령마다 `rc`+`len(sampler.current_trace)` 를 `src` 태그와 함께 찍으면 됨.
  현재는 `[+][SC-Cov]` 의 `status=` 로 "LLM 명령이 Invalid Opcode 등으로 거부되는지"만 부분 확인 가능.
  (구조상 halt 샘플링은 LLM 경로도 `_send_nvme_command`(무조건 start_sampling)+`_calibrate_seed`
  로 동일하게 탄다 — 스킵 아님. 관건은 명령이 너무 빨리 실패하는지.)
- **그래프 옵션 여지**: G4 rate(속도) 뷰, G5 마일스톤 오버레이는 미구현. sc 를 자기보정 %(관측
  universe 분모)로 보고 싶으면 별도 옵션 추가 가능.

## 파일

- `pc_sampling_fuzzer_v9.4.py` — v9.3 byte-copy + 위 편집
- `coverage_growth_plot.py` — 신규, 분리 그래프 렌더
- `fuzzer_config.json` — 무변경(공유 파일)
