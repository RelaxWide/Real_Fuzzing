# ROADMAP — LLM 커버리지 향상 방법론 (v9.6+ 계획)

> **상태(중요):** 이 문서는 **아직 구현되지 않은 v9.6+ 로드맵/설계 제안서**다. 여기 담긴
> §5~§12(dictionary / QD archive / bandit scheduler / state graph / call-graph / generator
> evolution 등)는 **전부 미구현**이다. v9.5 에서 실제로 구현된 것은 **Phase 0 뿐**(plateau
> starvation cap, FFM 재정의, corpus_eval 층화, matched-contrastive) — 현황은
> `pc_sampling_fuzzer_v9.5.md` 참조. 이 파일은 그 **다음 단계 계획**이다.
>
> 이 파일은 기존 제안서의 **§1~§4 와 스케줄러/스테이트그래프 본문은 그대로 두고**, 깨진
> §5(번호 충돌·잘림)와 이후 누락분을 재구성한다. 번호 재정렬:
> §5 Constant dictionary MVP / **§6 QD archive(신규 분리)** / §7 Task scheduler(구 §6) /
> §8 State graph(구 §7) / §9 Call-graph pilot / §10 Full generator evolution + contextual /
> §11 실험·ablation·지표 / §12 Novelty 포지셔닝·특허 경계.
> 모든 신규 guidance 는 **Gate 0(측정·재현성·wear guard) 통과를 조건**으로 한다.

---

## 5. Constant/data dictionary MVP

### 5.1 목표
Firmware 상수를 무차별 사전으로 넣지 않고, target 과 의미가 연결된 후보만 사용한다. 무차별
immediate 추출은 주소·loop count·mask·allocator size·컴파일러 생성 상수 같은 노이즈로 탐색
공간만 키운다.

### 5.2 추출 범위와 대상
범위(함수):
- 부분도달/미도달 target 함수, 그 nearest covered caller
- dispatch/validation 함수, payload parsing 함수
- SC-depth 1~2 명령 관련 함수 (핸들러에 닿았으나 필드에서 반송되는 지점)
- 위 함수의 xref 와 인접 BB

대상(값): compare immediate / switch value / bitmask / size·alignment constant / 문자열·log
identifier / table entry / descriptor length / CRC·checksum xref.

### 5.3 후보 필터
```
firmware constant
  → NVMe spec enum 과 교집합인가?
  → schema field 범위에 들어가는가?
  → target/validation 함수의 xref 인가?
  → 기존 accepted/rejected 값 주변인가?
```
통과한 상수만 사전 후보로 승격. LLM 의 역할은 **상수 생성이 아니라 field 의미 매핑**이다:
`{constant, candidate_field, confidence, evidence_xref}` 를 출력하고, confidence + xref 근거가
있는 매핑만 다음 단계로 넘긴다.

### 5.4 Deterministic neighborhood test (사전은 sampling 신호와 완전 독립이 아니다)
입력 생성은 결정적이지만 "이 상수가 실제로 유효했나"의 판정은 여전히 BB/SC/state feedback 에
의존한다. 따라서 각 후보 상수 `c` 를 필드에 대입해 **결정적 이웃 집합**을 만들고 응답 차이를
본다(REDQUEEN 식 — 입력값이 비교 operand 로 나타나면 분기를 뒤집는다):
```
neighborhood(c) = { c-1, c, c+1, c^bit, signed/unsigned 경계, length/count mismatch }
```
- 이 이웃이 **무작위 필드값 대비 차별적 SC/BB/state 반응**을 내면 → `confirmed`.
- 차이가 없으면 → `rejected`(사전에서 제외). LLM 매핑 confidence 만으로는 채택하지 않는다.

### 5.5 사전의 소비처와 기록
- confirmed 상수는 **§10 Generator DSL 의 `choose`/`around`/`boundary` 값 공급원**이 되고, 기존
  deterministic mutator 의 경계 변이 소스로도 쓰인다. (dictionary MVP 와 DSL MVP 는 병렬 트랙 —
  static extractor 를 먼저 만들면 DSL 값이 자연히 채워진다.)
- 각 엔트리는 `source_xref / target_func / confirm_status / run_id` 로 태깅해 재평가·소급분석 가능.
- dictionary 기반 변이도 예외 없이 **Gate 0 의 wear/brick guard 뒤에서** 전송된다.

---

## 6. Coarse Quality-Diversity (QD) archive

### 6.1 목적 (FSM 이 아니다)
FFM 단방향 최대화(현 workload feedback) 대신, telemetry 상태공간의 **서로 다른 영역을 유발한
입력을 보존**한다. QD 의 목적은 정밀 상태기계 구축이 아니라, 특정 고압 상태로의 탐색 편중을
막고 빈 영역을 채우는 것이다. **QD cell 과 §8 의 FSM node 는 raw feature 만 공유하고 추상화는
분리**한다(QD=다양성 위해 거칠게, FSM=Markov 일관성 위해 세밀+context).

### 6.2 Behavior descriptor
기존 telemetry 를 소수의 거친 bucket 으로. 초기엔 3~5 핵심 축만(전 필드 사용 시 archive 희소).
제품에 없는 필드는 제외하고 남은 필드로 key 구성.
```
QDCell = (ffm_bucket, free_blocks_bucket, slc_usage_bucket,
          reclaim_activity_bucket, power_state_bucket)   # 존재하는 축만
```

### 6.3 Archive 연산 (cell 당 다중 elite)
각 cell 에 목적이 다른 elite 를 함께 보존한다:
- 가장 **적은 명령**으로 그 상태에 도달한 descriptor
- 가장 **많은 새 BB** 를 낸 descriptor
- 가장 **재현성 높은** descriptor
- 가장 **낮은 write cost** descriptor

교체 규칙: 같은 cell·같은 목적 slot 에서 해당 목적 지표가 개선될 때만 갱신(예: min-command
slot 은 더 적은 명령으로 도달한 입력이 나오면 교체).

### 6.4 QD 주도 탐색 (빈 cell 채우기)
목표는 FFM 최대가 아니라 **비어 있는 cell/전이**를 채우는 것:
```
high FFM → low FFM,  low free_blocks → reclaimed,  idle → GC active,
GC active → recovery,  normal → power-interrupted → recovery
```
plateau 또는 scheduler pull 시, 인접한 빈/희소 cell 을 골라 LLM·generator·workload 가 그 방향
전이를 만들도록 지시한다.

### 6.5 Reward·scheduler 연동
새 cell 진입은 §7.4 reward 벡터의 `norm_new_qd_cells` 성분으로 들어간다. QD novelty 는 discovery
축이지 성공/실패 이분법이 아니다(FFM 단방향 제거의 귀결).

### 6.6 안전
QD 가 "새 cell 을 채운다"는 이유로 Gate 0 의 hard wear guard 를 넘어설 수 없다. cell 미충족이라도
wear budget 초과 시 그 descriptor 는 거부된다.

---

## 7. 비정상 환경을 고려한 Task Scheduler
*(기존 §6 본문 유지 — 요지만 재수록. arm 정의 7.1 / pull·reward window 7.2 / discounted·sliding
Thompson 7.3 / reward scalarization 7.4 / 적용 조건 7.5)*

핵심 보정만 재강조:
- **Bandit 전에는 starvation-free weighted round-robin + max-consecutive cap** 을 기준선으로.
- 표준 Thompson 은 stationary 가정 → 캠페인 단계마다 최적 task 가 바뀌므로 **discounted
  (γ≈0.95~0.99) 또는 sliding-window(최근 20~40 pull)** 로. 강제 탐색(ε=0.05 또는 arm 당 최소 1회/주기).
- **generated / admitted / selected / executed / productive 를 분리 기록** — LLM 산출물이 한 번도
  선택 안 됐으면 arm 실패가 아니라 seed 선택 문제.
- reward 는 **원본 벡터로 보존**, scheduler 에서만 bounded scalar 로. 가중치는 연구결과가 아니라
  ablation 대상 정책 파라미터. wear/brick 은 음수 reward 가 아니라 Gate 0 hard guard 로 처리.
- 고차원 contextual(task×command×state×operator) 는 표본 부족 → §10 으로 미룸.

---

## 8. Boundary-capture 기반 Probabilistic State Graph
*(기존 §7 본문 유지 — 관측단위 8.1 / no-op control 8.2 / raw record 8.3 / state encoder 8.4 /
probabilistic edge 8.5 / guidance 허용조건 8.6)*

전제 재확인: 기존 `state_corpus`/`_state_seen` 은 최대 100-command window + background 가 혼합돼
**edge 로 소급 해석 불가** → replay corpus·discovery count 로만 계속 쓰고, 그래프는 Gate 0 의
boundary-capture 데이터로 **새로** 만든다.

### 8.7 LLM sequence planning (잘린 부분 완성)
LLM 에는 **validated edge + underexplored/unstable frontier 만** 제공하고, 자유 명령열이 아니라
구조화된 plan 을 받는다.
```
Current node: S18
Validated outgoing:
  SetFeatures(FID=0x0c) → S22, p=0.81
  mixed_rw              → S18, p=0.92
Unstable (control 과 미분리 / entropy 높음):
  overwrite_churn → {S19:0.35, S21:0.30, S18:0.35}
Target: reach an unobserved outgoing transition from S22.
```
LLM 출력(구조화):
```json
{
  "target_node": "S31",
  "precondition_node": "S22",
  "sequence_template": [
    {"command": "SetFeatures", "fixed": {"fid": 12}},
    {"repeat": "Write", "count_range": [32, 512]},
    {"command": "GetLogPage", "mutate": ["lid", "lsp"]}
  ],
  "expected_sc_path": [0, 0, 0],
  "expected_state_change": ["free_blocks:-2^n", "reclaim:+2^n"]
}
```
LLM 은 **계획만**, 최종 변이·전송은 deterministic 계층이 수행하고 결과를 `expected_*` 와 대조해
outcome ledger 에 기록(§4.1). 예측과 관측이 반복적으로 어긋나면 그 계획 계열의 신뢰도를 낮춘다.

### 8.8 노드 abstraction 의 적응적 유지 (partition refinement)
같은 node/action 에서 post-state 분포가 지나치게 넓으면 원인별로 대응:
- **state aliasing** → 숨은 context(feature config·namespace·bg flag) 추가해 node **분할**
- **duration effect** → dwell-time bucket 추가
- **진짜 stochastic** → 확률 edge 유지
- **telemetry noise** → field 제거 또는 bucket 완화
반대로 특정 node 가 너무 희소하면 **병합**. 즉 재현성 낮으면 split, 희소하면 merge(적응적
상태 추상화).

### 8.9 Edge lifecycle 와 guidance 연동
```
observed(1~2회) → candidate(반복 중) → validated(control 과 분리·재현) → unstable(entropy↑/drift 미분리)
```
- **validated edge 만** LLM·scheduler guidance 에 사용. state-graph frontier 진전은 §7.4 reward 의
  한 성분이 되지만 validated edge 에 한한다.
- Gate 0-C 에서 edge 가 끝내 validate 되지 않으면 **state graph guidance 는 비활성**하고, replay
  corpus + discovery count 는 그대로 유지(실패해도 회귀 없음).

---

## 9. Ghidra call-graph / xref frontier pilot

### 9.1 정적 export 확장 (`ghidra_export.py` 현재 BB·함수만 export)
추가 산출:
```
calls.txt      : caller_entry callee_entry callsite
xrefs.txt      : function address constant|string
cfg_edges.txt  : src_bb dst_bb
```

### 9.2 정적 측도 자체가 불완전 (과신 금지)
Ghidra call graph 는 indirect call 누락, 잘못된 function boundary, tail call/thunk, stripped
firmware 의 오복구 위험을 가진다. 즉 정적 그래프도 근사다.

### 9.3 Distance 는 잡은 PC 하나로도 계산 가능 (부분맹은 false-negative)
halt sampling 이 중간 함수를 놓치면 주로 **false negative**(실제 가까워졌는데 진전 미관측 → 보상
지연 → 반복 union 에서 뒤늦게 발견)일 뿐, PC 를 하나라도 잡았다면 그 위치로부터의 정적 distance 는
유효하다. 따라서 call-graph guidance 는 불가능이 아니라 **희소·지연** 신호다.

### 9.4 Milestone admission (다축 병용 — 부분맹 보완)
다음 중 하나를 milestone 으로 인정하되, PC sampling 이 놓칠 수 있으므로 **SC/state milestone 과
반드시 병용**:
- target 까지 call-graph distance 감소
- unreached chain 의 다음 함수 진입
- 관련 SC-depth 증가
- 관련 constant/data reference 발견(§5 사전과 연결)

LLM 입력은 함수 이름 목록 대신 `target / nearest reached / unreached chain / 관련 상수 / best
existing seed` 형태로 준다.

### 9.5 왜 마지막인가 (정정된 근거)
"완전 coverage 가 아니면 DGF 불가"가 아니라, **동적 관측(부분맹 sampling)과 정적 그래프(불완전
복구)가 둘 다 불완전해 guidance SNR 검증이 필요**하기 때문. Gate 0 의 milestone 재관측률이 noise
를 이길 때만 pilot 진행. 기대: 희소·지연 신호.

---

## 10. Full generator evolution + high-dim contextual scheduler

### 10.1 MVP → evolution 으로 갈 때 추가되는 것 (완성형은 큰 작업)
DSL MVP(scalar CDW rule)는 기존 schema mutation 재사용으로 싸다. ELFuzz 식 진화까지는:
field 간 관계 제약 / count·length 일관성 및 **의도적 불일치** / typed payload builder / sequence
control flow / bounded repeat / generator mutation·crossover / fitness attribution / generator
versioning·replay / validation-failure feedback / deterministic RNG seed / **safety budget compiler**.
난이도: DSL MVP 낮음~중간 → structured payload 중간 → full evolution 중간~높음.

### 10.2 진화 루프
```
LLM 이 generator 4~8개 제안
 → 각 generator 에 작은 사전 budget
 → new BB / SC / state transition / QD cell / cost 측정
 → 상위 generator 를 LLM 에 부모로 제공
 → LLM 이 operator 교배·수정
 → plateau 에서 새 generator family 생성
```
LLM 호출 1회가 수천 변이로 증폭 — "출력이 실행수 대비 티끌" 문제의 실질 해답.

### 10.3 Fitness attribution
scheduler(§7.2)와 동일하게 generated/admitted/selected/executed/productive 를 분리해 generator
품질과 seed 선택 문제를 혼동하지 않는다. generator 별 reward 는 원본 벡터로 저장.

### 10.4 안전 (validator 단독 신뢰 금지)
```
LLM/DSL validation → write/wear budget → device-health guard → 기존 send-time brick guard → 전송
```
DSL validator 는 1차 방어일 뿐, **send-time brick guard 를 최종 backstop 으로 항상 유지**한다.

### 10.5 High-dim contextual scheduler
task×command-family×state×operator arm 은 표본이 충분히 쌓이고 generator versioning·rich ledger 가
갖춰진 뒤에만. 그 전엔 §7 의 단순 discounted bandit 을 유지.

---

## 11. 실험 · Ablation · 지표

### 11.1 Ablation 사다리 (새 순서에 정렬 — 각 단이 한 메커니즘만 격리)
```
B0  blind v9.4
B1  현재 LLM v9.4
B2  B1 + Phase 0 정리(ledger·matched contrastive·stratified eval·FFM 재정의·starvation-free)
B3  B2 + constant dictionary
B4  B3 + generator DSL MVP
B5  B4 + multi-objective reward + coarse QD
B6  B5 + discounted non-contextual bandit
B7  B6 + probabilistic state graph (Gate 0-C 통과 시)
B8  B7 + call-graph/xref frontier (SNR 검증 후)
B9  B8 + full generator evolution + contextual scheduler
```
Dictionary(B3)와 DSL(B4)은 병렬 가능(사전이 DSL 값 공급).

### 11.2 고정 조건
동일 command/time budget · 동일 초기상태 또는 동일 preconditioning · 설정별 반복 실행 · LLM
model/temperature 고정 · **blind vs LLM 실제 실행 명령 수 분리 기록** · 설정 간 **wear budget 동일**.

### 11.3 평가 지표
- BB coverage 최종값 + **AUC**(성장곡선)
- target frontier distance 변화
- distinct state / transition 수, distinct (cmd, SC) 수
- time-to-new-BB, commands-to-new-BB
- **LLM 호출당 new BB**, generator family 별 reward
- **write volume/TBW 당 new coverage**(효율·마모 정직성)
- **재현 가능한 transition 비율**, QD cell 충전 수
- 하드웨어 비결정성 고려: 다중 run 의 분산/CI 보고, nonstationarity 때문에 phase-segmented 지표 병행

### 11.4 Gate 0 최소 실험 (신규 guidance 前 필수)
```
동일 seed 를 동일 preconditioning 에서 10~20회 반복
 매회 SC / sampled PCs / telemetry signature 기록
 action 없이 동일 wall-clock 대기한 no-op control 기록(duration·dwell 매칭)
 sequence/workload replay 도 동일 방식 반복
계산: PC Jaccard·union saturation / SC 일치율 / post-state top-1 P / H(S'|S,a)
      / action effect vs no-op drift 분리도 / replay 당 write·time cost
```

---

## 12. Novelty 포지셔닝 · 특허 경계

### 12.1 주장 단계 (지금은 novelty 확정 이르다)
현 단계 정확한 표현은 **"기존 연구와 차별화 가능성이 높다"**. 최종 novelty 주장은 체계적
문헌조사 + 특허 claim 분석 + ablation 결과 이후에 한다.

### 12.2 차별점은 "조합"에 있다
- 실물 telemetry + NVMe SC 를 결합한 **복합 state 정의**(비가역 하드웨어)
- 부분맹 halt sampling 을 보완하는 **다축 semantic milestone**
- Ghidra **call-graph frontier × SSD state graph** 결합
- 비가역 SSD 를 위한 **brick-safe generator DSL**
- write/wear cost 를 포함한 **multi-objective policy**
- state 도달 **계획 vs 명령/payload generator** 의 계층 분리

### 12.3 특허 경계 (선행기술 스코핑 — 법률의견 아님)
"LLM generator" 나 "stateful fuzzing" 자체가 아니라 위 **구체 조합**에 차별점을 둔다. 관련
선행문헌(문서→driver 생성+coverage fitness, LLM 기반 protocol state inference, protocol state
machine 반복학습 등)과 겹치지 않도록: 실물 SSD telemetry+SC 복합 state / 부분맹 보완 다축
milestone / call-graph×state-graph 결합 / brick-safe DSL / write·wear 포함 multi-objective /
계층적 plan↔generator 분리 를 명시적 경계로 삼는다.
```
