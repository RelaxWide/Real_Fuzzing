# pc_sampling_fuzzer v9.5

> per-version 규칙: `v9.5.py` = `v9.4.py` byte-copy + 아래 편집만. 베이스라인 v9.4 는 불변.

## 한 줄 요약

v9.4(관측 층·ledger) 위에 **Phase 0 — LLM 피드백 루프 수리**를 얹었다. LLM 동작을 실제로 바꾸는
첫 버전: task 기아 제거 + 워크로드 성공 재정의 + corpus_eval 층화 + **matched-contrastive**(같은
명령의 한-필드-차이 쌍을 LLM 에 되먹임). v9.4 ledger 를 소비해 field-relation 학습을 유도한다.

## 설계 결정 (왜)

- **v9.4 는 "측정", v9.5 는 "그 데이터로 LLM 을 다르게 움직이는" 층.** 효과는 믿는 게 아니라
  ledger + ablation(B1 현재 LLM vs B2 Phase 0)으로 측정한다.
- **Phase 0 은 직접 레버만.** boundary-capture·wear guard·bandit·state-graph 등 인프라/후속은 v9.6+.

## 변경 상세 (`pc_sampling_fuzzer_v9.5.py`)

| 항목 | 위치 | 내용 |
|---|---|---|
| **119** | version | `FUZZER_VERSION = "9.5.0"` |
| 상수 | `RAG_LOG_RESPONSES` 뒤 | `RAG_MAX_CONSEC_TASK`(=3), `RAG_CONTRAST_MIN_DIFF`(=1) |
| **① plateau 기아 제거** | `_llm_maybe_submit` | plateau 여도 sequences/new_group 을 **무한 독점 금지**: 같은 task 를 `RAG_MAX_CONSEC_TASK` 회 연속 고르면 이번엔 가중 라운드로빈에 양보 → corpus_eval/io_patterns/new_group 기아 방지. `_llm_last_task`/`_llm_task_consec` 추적 |
| **② FFM 단방향 판정 제거** | `_run_llm_workload_burst` + `_llm_workload_feedback` | 버스트가 `ffm_trough`/`ffm_range`(양방향 이동)와 `new_states`(이 버스트가 만든 신규 distinct state 수)를 기록. 되먹임 판정: **new_states>0=SUCCESS / ffm_range>0=PARTIAL(FFM 하강=GC 완료도 진전) / 무변화=NO EFFECT**. FFM 방향(Δ)은 성공/실패 아닌 "어느 쪽으로 밀렸나" 정보로만 |
| **③ corpus_eval 층화** | `_corpus_eval_stratified_sample` + task builder | `corpus[:40]`(오래된-편향) → strata 표본(최근 LLM 8 / 최근 new-BB 8 / favored 6 / stale 6 / 나머지 random). 각 seed context 강화: `cdw11/data_len/favored/origin/last_status(SC)` 추가 |
| **④ matched-contrastive** | `_contrast_pool` + `_llm_contrastive_block` + new_group_seeds 프롬프트 | `_account_command` 가 device 응답(sc) 있는 실행의 (변이 필드→SC/BB)를 명령별로 기록(deque 64). 같은 명령의 **한 필드만 다른데 결과가 갈린** 쌍을 찾아(같은 `prov_id` + 최소 diff 우선) 대조 예시로 new_group_seeds 프롬프트에 주입 → LLM 이 "아무 성공/실패"가 아니라 **어느 필드 관계가 결과를 갈랐는지** 학습 |

### matched-contrastive 판정 규칙 (정직성)
- 두 변이의 결과가 같으면(같은 SC·같은 new_pcs) 대조 가치 없음 → 스킵.
- 다른 필드 수 ≤ `RAG_CONTRAST_MIN_DIFF + 1` 만 후보(너무 많이 다르면 인과 흐려짐).
- **같은 parent(`prov_id`) + 적은 diff** 우선 정렬 → "한 요인만 달라야 유용"이라는 리뷰 요건 충족.
- `prov_id` 는 v9.4 의 iteration-local `_credit_seed` 계보(같은 corpus 시드의 두 변이 = 같은 prov_id).

## v9.4 대비 동작 변화 (LLM 측)
- 전부 **LLM 동작을 실제로 바꾸는** 변경(v9.4 는 관측만이었음). 따라서 **B1(현재 LLM=v9.4) vs
  B2(Phase 0=v9.5)** ablation 으로 효과를 측정한다. `--rag off` 면 blind 경로는 v9.4 와 거의 동일
  (staleness/ledger 는 그대로) — ②의 워크로드 필드 기록만 추가되나 궤적 영향 미미.

## 검증 상태
- `py_compile` OK
- 기능 스모크 OK: 대조 쌍 탐색(최소 diff·같은 parent 우선), 층화(오래된 60개 속 recent-LLM 5/5·
  favored 3/3), 워크로드 되먹임(FFM 하강=PARTIAL, new_state=SUCCESS, 무변화=NO EFFECT)
- **하드웨어 실측 미검증**

## 아직 안 한 것 / 다음 (v9.6+)
- **full 계보 전파(`parent_prov_ids`, mutation/splice 체인) + `selected` 이벤트** — 현재 contrastive
  는 `prov_id`(corpus 소스 계보)로 충분히 동작. 전체 체인·selected 는 bandit(opportunity 정규화)
  용이라 v9.6.
- **contrastive 를 sequences task 에도** 확장(현재 new_group_seeds 만).
- **Gate 0**(boundary-capture + no-op control + hard wear guard), **dictionary/DSL/QD/bandit/
  state-graph/call-graph** — v9.6+.

## 파일
- `pc_sampling_fuzzer_v9.5.py` — v9.4 byte-copy + 위 편집
- `coverage_growth_plot.py`, `nvme_seeds.py`, `fuzzer_config.json` — 공유(무변경)
