# pc_sampling_fuzzer v9.6

> per-version 규칙: `v9.6.py` = `v9.5.py` byte-copy + 아래 편집만. 베이스라인 v9.5 는 불변.

## 한 줄 요약

v9.5 위에 **LLM 에너지 부스트 자동조정**을 넣었다. `llm_energy_boost = 1.5` 라는 **사람이 정한
고정 배수**를, CSFuzz 의 `p` 처럼 **구간 실측 yield 로 갱신**되는 값으로 바꿨다.

## 왜 (문제 정의)

v9.5 까지 LLM 계보 시드는 `seed_class` 만 보고 **항상 ×1.5** 를 받았다. LLM 이 실제로 커버리지를
뚫든 한 개도 못 뚫든 배수가 같았다.

**"개별 시드는 이미 동적이지 않나?" — 부분적으로만 그렇다.**
`_calculate_energy` 의 AFLfast explore 스케줄(`executions / exec_count`)은 **많이 실행된 시드**의
에너지를 낮춘다. 하지만 그건 *"얼마나 자주 실행됐나"* 이지 *"얼마나 성과를 냈나"* 가 아니다.
게다가 LLM 은 주기적으로 새 시드를 계속 주입하는데, 매번 `exec_count=0` → `MAX_ENERGY × 1.5`
로 들어온다. **성과가 0 이어도 프리미엄이 계속 갱신되는 구조**였고, 계보 수준의 되먹임이
어디에도 없었다.

| | 조정 주체 | 신호 |
|---|---|---|
| v9.5 개별 시드 | `exec_count` | "얼마나 자주 실행됐나" (탐색 균형) |
| v9.5 계보 배수 | **없음(상수)** | — |
| **v9.6 계보 배수** | **구간 yield 비교** | **"얼마나 edge 를 뚫었나"** |

## 설계 결정 (왜 이렇게)

- **CSFuzz 와 같은 층이 아니라 같은 *꼴*.** CSFuzz `p` 는 C1(edge corpus) ↔ C2(state corpus)
  라는 **서로 다른 목적** 사이 배분이다(reward 정의도 m1=edge 성공률 / m2=state 재현률로 다름).
  LLM vs mutation 은 목적이 같고(둘 다 edge 를 뚫는다) **시드가 어떻게 태어났는가**만 다르므로,
  제3의 corpus 가 아니라 **C1 안에서의 가중치**가 맞다. 갱신식만 CSFuzz 와 같은 꼴로 맞췄다.
- **LLM 을 별도 corpus(C3)로 분리하지 않은 이유:** `seed_class` 가 변이·splice 자식에게
  전파되므로(`# LLM 계보 태그 전파`), 분리하면 "LLM 시드의 변이 자식은 어느 풀 소유인가" 를
  정해야 한다. C3 에 남기면 C3 가 변이 시드로 채워져 arm 의 의미가 흐려지고, C1 으로 보내면
  누적 공로를 잃는다. 태그+가중치 방식은 이 질문 자체를 만들지 않는다.
- **분모(기회 정규화)가 이 변경의 핵심.** v9.4 `_cov_by_src` 는 **발견 수만** 셌다. 그러면
  "많이 뽑혀서 많이 찾은 것" 과 "잘 찾은 것" 을 구분할 수 없다.
- **분모는 '명령 실행 수'(비용 정규화).** 희소 자원은 선택 기회가 아니라 **장치 시간
  (명령 실행)** 이다. 선택 단위로 재면 16명령짜리 시퀀스와 1명령짜리 시드를 같은 비용으로
  취급하게 되어, 예산을 16배 쓰고 2배만 뚫은 경우도 '2배 효율' 로 보인다. 부스트의 목적은
  *주어진 실행 예산을 어느 출처에 배분할까* 이므로 비용 기준이 맞다.
  (검증: 같은 발견 30개인데 LLM 이 3000실행/mutation 이 500실행을 쓴 경우 → r=-0.714 로
   부스트 하락. 선택 기준이었다면 r=0 으로 '동등' 오판.)
  → 실측의 "부스트가 내려갔는데 LLM 실행 비중이 16%→65%" 는 왜곡이 아니라 **실제 신호**였다.
  LLM 계보가 예산을 그만큼 더 쓰고 있었다는 뜻이고, 성과가 그에 못 미치면 내리는 것이 맞다.
  선택 횟수는 진단용으로 로그에 `sel=` 로 함께 찍어 시퀀스의 예산 점유를 눈으로 보게 한다.
- **gain 은 edge 만.** sc/state 를 섞으면 단위가 달라 가중치를 사람이 정해야 하고, 그러면
  '사람 개입 제거' 라는 이 버전의 목적과 어긋난다.
- **분자도 `_select_seed()` 를 거친 것만.** `iowl`(LLM io_patterns 워크로드 버스트)과
  `replay`(c2, CSFuzz p 가 고름)는 corpus 에너지 가중치가 관여하지 않는 경로다. 그런데 둘 다
  `_account_command` 를 타므로 `llm/iowl`·`llm/replay` 로 **분자에는 잡히는데 `_select_seed` 를
  안 거쳐 분모는 안 는다** → `y_llm` 이 부풀어 부스트가 근거 없이 올라간다(시퀀스 문제의
  정반대 왜곡). 더 근본적으로는 **부스트가 제어하지 않는 성과로 부스트를 조정하는 범주 오류**다.
  → `form ∈ {cmd, seq}` 로 한정해 분자·분모의 모집단을 일치시킨다.
- **r 을 정규화**(`(y1-y2)/(y1+y2)`)한 이유: 절대 yield 는 런 전반에 걸쳐 크게 변한다(초반 높고
  포화 후 0 에 수렴). 비율은 스케일 불변이라 같은 학습률로 전 구간에서 동작한다.

## 변경 상세 (`pc_sampling_fuzzer_v9.6.py`)

| 위치 | 내용 |
|---|---|
| **125** | `FUZZER_VERSION = "9.6.0"` |
| 상수(`RAG_SEQ_ENERGY_BOOST` 뒤) | `RAG_BOOST_LR`(0.3) / `RAG_BOOST_MIN`(0.5) / `RAG_BOOST_MAX`(3.0) / `RAG_BOOST_MIN_SAMPLES`(200) |
| 초기화(`_cov_by_src` 옆) | `_llm_boost`(초기값=`RAG_ENERGY_BOOST`), `_boost_exec`, `_boost_gain`, `_llm_boost_hist` |
| `_account_command` | **분모** — `form ∈ {cmd, seq}` 인 **명령 실행 수**를 origin별로 카운트(소비한 장치 시간) |
| `_select_seed()` 3개 반환 지점 | **진단용** 선택 횟수 카운트(`_boost_count_selection`). 분모 아님 — 로그에 `sel=` 로 함께 표시해 시퀀스가 예산을 얼마나 먹는지 보이게 |
| `_cov_credit` | **분자** — `axis=='edge'` **이면서 form 이 `cmd`\|`seq`** 일 때만 `_boost_gain[origin]` 누적 |
| `_update_llm_boost()` (신규, `_update_csfuzz_p` 앞) | 갱신식 + 가드 + 로그 + 히스토리 |
| 10000-exec 블록 | `_update_csfuzz_p()` 와 나란히 `_update_llm_boost()` 호출 |
| `_llm_energy_adjust` | 상수 → `self._llm_boost`. 시퀀스는 기존 비율(`SEQ/ENERGY`)을 유지한 채 함께 이동 |
| `coverage_growth.jsonl` 스냅샷 | `llm_boost` 필드 추가(추이 시각화) |
| `RAG_DEBUG_EXEC` (신규 키) | `[LLM/exec]`(시드 선택마다 1줄, 고빈도)를 `RAG_DEBUG` 에서 분리, 기본 off |

### `[LLM/exec]` 를 분리한 이유
`[LLM/raw|parse|item]` 은 **LLM 요청 1건당**(≈5000 exec 마다)이라 `rag.debug=true` 로 상시
켜둘 만하다. 그런데 `[LLM/exec]` 는 **시드 선택 1회당** 이라 초당 수십 줄이 되어, 같은
스위치에 묶여 있으면 debug 를 켜는 순간 터미널이 이 줄로 덮인다. 게다가 v9.6 의
`[LLM-boost]` 가 `exec=llm/mutation` 집계를 주므로 평소엔 불필요하다.

### 갱신식

```
y_llm = gain_llm / exec_llm        # 선택당 새 edge 수
y_mut = gain_mut / exec_mut
r     = (y_llm - y_mut) / (y_llm + y_mut)          ∈ [-1, +1]
boost ← clip(boost × (1 + LR·r),  BOOST_MIN, BOOST_MAX)
```

### 가드 — 3중

**⓪ 미달 조건 두 가지**

| 가드 | 기본 | 막는 것 |
|---|---|---|
| `boost_min_samples` | 50 | 양 arm 각각의 **실행** 수 미달 → 표본 자체가 없음 |
| `boost_min_gain` | 5 | 양 arm **합계 edge** 미달 → 발견 1개 대 0개로 `r=±1` 이 튀는 것 |

선택 횟수만으로는 부족하다. 후반 yield 는 선택당 0.001 수준이라 50번 선택해도 기대 edge 가
0.05 개다. 이때 한쪽이 우연히 1개를 뚫으면 `r=+1` 로 부스트가 근거 없이 크게 흔들린다.
**"비교할 만한 발견이 실제로 있었나"** 는 표본 수와 다른 질문이다.
포화 구간(양쪽 0)도 이 가드에 걸려 창을 유지하므로, 나중에 발견이 생기면 누적된 표본으로
제대로 비교한다(기존에는 `r=0` 으로 갱신하며 창을 버렸다).

**① 미달 시 창을 비우지 않는다.**
boost 가 낮아지면 LLM 시드가 덜 뽑혀 표본이 **더** 안 모인다. 매 구간 리셋하면 "평가할 데이터가
없어 낮은 값에 영구 고착" 되는 내리막 나선에 빠진다. 누적시키면 시간이 걸려도 반드시 한 번은
공정하게 평가받는다.

**② 하한이 0 이면 안 된다.**
0 이 되는 순간 LLM 시드가 영영 안 뽑히고, 그러면 데이터도 안 쌓여 되돌아올 방법이 없다.
상한(3.0)은 반대로 mutation arm 이 고사해 **비교 대상 자체가 사라지는 것**을 막는다.

## 관측

```
[LLM-boost] 가중치 1.50 → 1.18 (-21%)  — LLM 효율이 mutation 의 0.17배
[LLM-boost]   LLM      : 명령   3,000회(선택 500회, 평균 6.0명령/선택) → 새 edge 30개 = 100명령당 1.00개
[LLM-boost]   mutation : 명령     500회(선택 500회, 평균 1.0명령/선택) → 새 edge 30개 = 100명령당 6.00개

[LLM-boost] 갱신 보류 — 실행이 아직 적음 (LLM 30회 / mutation 900회, 각 50회 필요). 계속 누적 중
[LLM-boost] 갱신 보류 — 발견이 적어 비교 불가 (새 edge 합계 1개, 5개 필요). 계속 누적 중
```

읽는 법:
- **`100명령당 N개`** — 이게 효율이다. 위 예는 LLM 1.00 vs mutation 6.00 이므로 LLM 이 1/6.
- **`평균 N명령/선택`** — 시퀀스가 예산을 얼마나 먹는지. LLM 6.0 은 한 번 뽑힐 때마다 명령 6개를
  쓴다는 뜻. 발견 수가 같아도 예산을 6배 쓰면 효율은 1/6 이다.
- **`가중치 A → B (±N%)`** — 조정 결과. 효율이 낮으면 내려가고, 다음 구간엔 덜 뽑힌다.
- 소수점 yield(`0.010000`)와 정규화 `r` 은 로그에서 제거했다 — 사람이 읽는 값이 아니다.
```
`[CSFuzz-p]` 와 대칭. `_llm_boost_hist` 와 `coverage_growth.jsonl` 의 `llm_boost` 로 추이 추적.

## 설정 (`fuzzer_config.json` → `rag`)

| 키 | 기본 | 뜻 |
|---|---|---|
| `llm_energy_boost` | 1.5 | **초기값**(기존 키 재사용). 첫 갱신 전까지 v9.5 와 동작 동일 |
| `boost_lr` | 0.3 | 학습률 |
| `boost_min` | 0.5 | 하한(0 금지 — 위 가드 ②) |
| `boost_max` | 3.0 | 상한 |
| `boost_min_samples` | 50 | 양 arm 각각의 최소 **명령 실행** 수(`cmd\|seq` 한정) |
| `boost_min_gain` | 5 | 양 arm **합계** 최소 edge 수 |

## 검증 상태

- `py_compile` OK
- **갱신식 단독 검증 6케이스**: LLM 우세(1.50→1.65) / 열세(1.50→1.35) / 표본부족(보류·창유지) /
  포화(양쪽 0 → 유지) / 하한 클립(0.52→0.50) / 상한 클립(2.95→3.00)
- **하드웨어 실측 미검증**

## 한계 (정직)

- **'LLM arm' 은 'LLM 이 만든 것' 이 아니라 'LLM 계보 전부'** 다. `seed_class` 가 변이 자식에게
  전파되므로, LLM 원본 몇 개가 잘 퍼지면 corpus 상당수가 `llm` 태그를 단다. 초기 시드
  (`found_at == 0`)는 epoch 리셋에서 항상 살아남으므로 mutation arm 이 완전히 마르진 않지만,
  실제 run 에서 `exec=llm/mutation` 비율을 확인해야 한다. 심하면 측정 대상을 **직접 제안분**
  (`prov_id` 보유 + 무변이)으로 좁히는 대안이 있다.
- **간접 효과는 귀속 불가.** v9.4 문서와 동일한 한계 — device-state carryover, splice(두 부모),
  corpus 경쟁, corpus_eval 재가중은 어느 arm 의 공로인지 나눌 수 없다.
- **이 메커니즘은 런타임 자원 배분 자동화이지 인과 증명이 아니다.** "LLM 이 정말 기여하는가" 의
  답은 여전히 **B0(`--no-rag`) / B1(`--rag`) campaign A/B** 의 몫이다.

## 아직 안 한 것 / 다음 (v9.7+)

- **bandit 전환** — Thompson sampling / UCB 로 가면 탐색-활용 균형이 원리적으로 보장되고
  `min_samples` 가드가 자연스럽게 녹는다. 지금은 CSFuzz 관용구(비례 제어)에 맞춰 두었다.
  거동 데이터가 쌓인 뒤 옮기는 것이 순서.
- **arm 분리** — 현재 `llm_cmd`/`llm_seq` 가 하나의 boost 를 공유(비율만 유지). 분모를 선택
  횟수로 맞춰 시퀀스 왜곡 자체는 해소됐으나, 둘의 성과 특성이 실제로 다르면 따로 조정하는 편이
  낫다. 다만 나누면 각 arm 의 표본이 반으로 줄어 추정이 나빠진다.
- **`llm_score` 처리** — LLM 이 `corpus_eval` 에서 자기 시드를 평가한 값(`<0.3 → ×0.5`)이 그대로
  남아 있다. 실측 기반 boost 가 생긴 지금은 순환 논리에 가까워, 제거하거나 실측 부족 시에만
  쓰는 보조로 강등하는 것을 검토할 것.
- **gain 에 sc 포함** — 가중치를 자동으로 정할 방법이 있으면(예: 각 축의 한계 수확 정규화)
  edge+sc 복합 지표로 확장 가능.

## 곁다리 수정 — crash artifact 를 dump 전에 확보

부스트와 무관하지만 v9.6 에서 같이 고쳤다.

**증상.** dump 가 제대로 안 돼서 중단하면 `crashes/crash_<ts>/` 안에 `replay_*.sh` 만 남는다.

**원인.** 저장 순서가 잘못돼 있었다.

| 단계 | 하는 일 | 저장 위치 |
|---|---|---|
| 3 | `_save_crash()` | `crashes/` **루트** ← 폴더 밖 |
| 3.5 | `_generate_replay_sh()` | `crash_<ts>/` |
| 3.7 | JLink / UFAS / RDDump | 수 분 소요, hang 가능 |
| 3.8 | `_collect_crash_artifacts()` | 이제서야 json·log·dmesg 를 폴더로 복사 |

dump 구간에서 중단하면 3.8 이 영영 실행되지 않는다. crash json 은 유실된 게 아니라
`crashes/` 루트에 흩어져 있었고, 로그·dmesg 는 복사 자체가 안 됐다.

**수정.**
1. `_save_crash(..., dest_dir=)` 추가 — 핸들러가 `crash_<ts>/` 를 넘겨 **처음부터** 최종 폴더에 쓴다.
2. `_snapshot_crash_context()` 신설 — 3.55 단계로 dump **직전**에 fuzzer 로그와
   `dmesg_<ts>_at_crash.txt` 를 선복사. crash 직후 dmesg 가 가장 값지므로 최종본과 파일명을 분리해 둘 다 남긴다.

이제 dump 를 포기해도 `crash_<ts>/` 안에 **crash json + replay + log + dmesg** 가 갖춰진다.
`_collect_crash_artifacts` 는 그대로 두었다 — dump 산출물 수집과 더 완전한 로그 덮어쓰기를 계속 담당한다.

## 파일

- `pc_sampling_fuzzer_v9.6.py` — v9.5 byte-copy + 위 편집
- `fuzzer_config.json` — `rag.boost_*` 4개 키 추가(공유 파일, v9.5 는 무시)
