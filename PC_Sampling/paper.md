# 논문 정리 (paper.md) — LLM-guided SSD 펌웨어 Fuzzer

> 목적: 나중에 논문 쓸 때 쓸 **포지셔닝·기여·평가·related work** 정리.
> 짝 문서: `LLM_strategies_and_paper_positioning.md`(LLM 전략·연구 novelty 각도). 이 문서는 **industrial 트랙 포지셔닝 + 정직한 평가**.

---

## 0. 결론 요약 (TL;DR)
- **연구(research) 트랙**: 약함 — 컴포넌트 대부분이 기존 기법의 조합/적응이라 **알고리즘 novelty로는 방어 어려움**.
- **Industrial / practice 트랙**: **강한 후보** — 실물 버그 확보 + 강한 제약 서사 + 안전/통합/telemetry.
- **핵심 판단**: **새 알고리즘은 필요 없다. 단, "우리 통합/적응이 없으면 이 버그를 못 찾는다"를 baseline으로 증명해야 한다.**

---

## 1. 트랙 결정 — Industrial
- 실제 평가에서 **버그/불량 확보됨**(가장 중요한 자산).
- Industrial은 **알고리즘 novelty가 아니라 실무 임팩트·시스템·교훈**을 봄.
- 앞서 약점이던 novelty(≈4.5/10)는 **거의 무관**해지고, 강점(안전 8.5 / LLM 8 / telemetry 8 / 관측성 8 / 복원력 7.5)이 headline이 됨.
- ⚠️ Industrial ≠ 낮은 바. **다른 바**(임팩트/시스템/교훈). "known 기법 조합 + 결과·통찰 없음" = desk-reject.

---

## 2. 기여(contribution) 정의 — 알고리즘이 아니라
Industrial novelty = **"이 하드 타깃에 이 조합을 처음 적용해 실제 결과를 냈다."** 기여는 개별 기법이 아니라:
1. **하드 타깃용 시스템/통합** — 알려진 기법을 **비자명하게** 엮어 실물에서 동작.
2. **실물 버그** — 임팩트(확보됨).
3. **도메인 제약에 맞춘 필수 적응** — CSFuzz state-cov→SSD telemetry, AFLNet식 응답피드백→NVMe SC(측정맹 하), 등.
4. **transferable 교훈.**

→ **기법이 known인 것은 결격이 아님.** 벤더 펌웨어/자동차/ICS fuzzing, 대규모 fuzzing 인프라 페이퍼 다수가 이 형태.

---

## 3. "그냥 known 기법 조합 아니냐" 방어 (핵심 한 수)
> **"이 버그들은 기존 도구를 그냥 적용해선 못 찾는다. [타깃 제약] 때문이고, 우리 적응이 그래서 필요했다."**

이 fuzzer에서 이 논리가 강한 이유(도메인 3대 제약):
- **측정맹**(하드웨어 트레이스 없음, halt 샘플링만) → 순수 coverage fuzzer 적용 불가 → 응답(SC)/telemetry 기반 적응 필요.
- **능력 불일치**(광고 OACS/ONCS ≠ 실구현) → 스펙만으론 조준 실패 → **응답 grounding** 필요.
- **비가역 브릭/잠금/마모** → 일반 fuzzer 돌리면 디바이스 사망 → **안전 아키텍처 없으면 fuzzing 자체가 불가능.**

→ "우리 적응/통합이 없었으면 이 버그를 못 찾았거나 디바이스를 브릭했을 것"을 보이면 known 기법이 **필수 적응**으로 승격.

---

## 4. 구현 강점/약점 (v9.3 채점, /10)
| 카테고리 | 점수 | 비고 |
|---|---|---|
| 안전(브릭/잠금 방지) | **8.5** ⭐ | 다층 send-time 가드, SECP allowlist, Lockdown/NS-delete |
| LLM 통합 | 8.0 | 2-PC bridge, 4 task, SC grounding/digest, 구조적 data |
| telemetry/state-cov | 8.0 | CSFuzz 버킷, FFM 파생, dynamic weight |
| 관측성/로깅 | 8.0 | 풍부한 진단 로그·그래프·per-version md |
| 복원력(freeze/reconnect) | 7.5 | 체크포인트+재시작, 모니터 재연결 |
| 전력/PM fuzzing | 7.5 | PCIe L1.2/D3, PM CSR |
| 변이 엔진 | 7.5 | AFL 계열 + NVMe-aware |
| 시퀀스/stateful | 7.5 | C2 replay, covered_pcs union(시퀀스) |
| corpus 관리(cull/energy) | 7.0 | AFL favored + staleness. (단일 covered_pcs union 보강함) |
| 커버리지 귀속/지표 | 7.0 | new_cov(하한), SC-depth |
| 크래시 탐지/triage | 6.5 | hung 펌웨어 덤프 불가(in-proc JTAG 미구현) |
| I/O 워크로드(FTL) | 6.5 | io_patterns/FFM 신규, 실장 검증 필요 |
| 커버리지 피드백(halt) | 6.0 | 확률적 under-sampling(하드웨어 한계) |
| **알고리즘 novelty** | **4.5** | 정직하게 약함 → industrial은 무관 |
| **(도메인 시스템 기여)** | **7.0** | industrial headline |
- 엔지니어링 평균 ≈ **7.3/10**.

---

## 5. 정직한 novelty 평가 (research 트랙 기준, 참고용)
| 컴포넌트 | novelty | 선행연구(반드시 인용) |
|---|---|---|
| SC-depth(응답→피드백) | 약함 | **AFLNet**(응답=상태피드백), AFLGo(distance) |
| LLM 시드/시퀀스 생성 | 없음 | ChatAFL, Fuzz4All, KernelGPT, TitanFuzz |
| LLM grounding/repair | 약함 | ChatAFL(repair), KernelGPT(spec+repair) |
| state-cov | 없음(재사용) | **CSFuzz** |
| staleness 에너지 | 약함 | **Entropic**(정보이득), AFLFast |
| io_patterns/FFM | 약~중 | 본인 **SDF-Fuzz** 확장 |
| 안전 가드 | 중(시스템) | 대부분 fuzzer는 재시작 가정 |
- SC-depth를 novelty로 밀면 AFLNet에 깨짐 → **AFLNet 인용 + 델타 명시**: *"AFLNet은 응답을 범주형 상태로. 우리는 (a) 서수적 처리깊이로, (b) 하드웨어 측정맹 하 코드커버리지 보완 신호로."*

---

## 6. 평가 설계 — "적응 필요성"을 baseline으로 증명 (industrial 핵심)
목표: **"우리 통합이 없으면 이 버그를 못 찾음"을 수치로.**
- **Baselines**: (a) 블라인드/AFL식 mutation-only, (b) 순수 coverage-guided(측정맹이라 신호 빈약함을 보임), (c) 스펙만 쓴 LLM(grounding 없이), (d) 가능하면 기존 SSD/NVMe fuzzer.
- **지표**:
  - **버그/불량 수** (baseline이 못 찾는 것 강조; 가급적 도메인-특화 상태를 요구하는 버그).
  - **커버리지**(BB/PC, new_cov는 하한임을 명시 + SC-depth로 보완).
  - **state-cov / 도달 내부상태**(FFM, GC/wear 발동).
  - **안전**: baseline이 브릭/잠금 유발 vs 우리는 가드로 회피(가드 카운터).
- **Ablation**(각 적응의 기여): SC grounding on/off, SC-depth on/off, io_patterns on/off, staleness on/off, 안전가드 on/off(→브릭율).
- **버그 케이스 스터디**: 대표 버그 2~3개를 "왜 도메인 통합이 있어야 도달하는가"로 서술(시퀀스/telemetry/전력 상호작용 필요).

---

## 7. 이기는 서사 (한 줄 + 확장)
> *하드웨어 트레이스가 없어 커버리지가 측정맹이고, 광고능력≠실구현이며, 브릭/잠금/마모로 비가역 손상되는 실물 프로덕션 SSD 컨트롤러 펌웨어에, LLM-guided fuzzing을 안전하게 통합·운영한 시스템과 그 과정의 엔지니어링 결정·교훈을 제시하고, 실물에서 N개 버그를 찾았다.*

구조(3단): **새 문제(제약 3종) → 그 제약을 푸는 통합·적응 → 실물 버그 + baseline 대비 + 교훈.**

**날카로운 교훈 후보(1개 이상 명시):**
- 측정맹 → **같은 입력 재실행이 (확률적) 새 커버리지**를 냄(반복이 낭비가 아님).
- 능력 불일치 → **응답(SC)이 광고 스펙보다 신뢰 가능한 ground truth**.
- 비가역성 → **fuzzing 예산이 시간이 아니라 디바이스 수명**(마모), 안전 아키텍처가 fuzzing의 전제조건.

---

## 8. Related work 체크리스트 (델타 좁히기 — 제출 전 필수)
- **응답/상태 피드백**: AFLNet, StateAFL, NSFuzz, SGFuzz, IJON.
- **LLM fuzzing**: ChatAFL(NDSS'24), Fuzz4All(ICSE'24), KernelGPT(ASPLOS'25), TitanFuzz/FuzzGPT, WhiteFox, CovRL-Fuzz.
- **에너지/효율**: AFLFast(CCS'16), Entropic(FSE'20), STADS(species estimation, 캠페인 잔여).
- **state-cov**: CSFuzz.
- **crash-consistency / storage 오라클**: Hydra, CrashMonkey, B3 (파일시스템+소스 기반 → 우리는 블랙박스 컨트롤러 + telemetry).
- **본인 선행**: SDF-Fuzz(TVDA/DRP/FFM) — io_patterns/FFM 델타를 "LLM-driven planning vs 휴리스틱"으로 구분.

---

## 9. (선택) research novelty를 원할 때의 후보 — 지금은 미구현
industrial이면 불필요. 만약 알고리즘 기여를 원하면 유일하게 신선한 후보:
1. **측정-인지 에너지 스케줄링**: 확률적/부분 커버리지 하에서 "같은 입력 재실행=측정 정보이득". 측정수렴 vs 커버리지소진 구분. (선택) species-estimation으로 미측정 커버리지 추정. → 결정적 커버리지 가정(Entropic/AFLFast)을 깸. **STADS(캠페인 잔여)와 델타 = per-seed × 하드웨어 측정맹.**
2. **telemetry 메타모픽 오라클**: LLM이 telemetry 불변식 합성 → silent bug 탐지. (crash-consistency 검증기와 델타 = 블랙박스 + LLM 합성 + telemetry.)
- ⚠️ 사용자 피드백: 위 두 개는 "실무적으로 의미 없어 보임" → 보류. **industrial 경로 우선.**

---

## 10. 제출 전 확보할 결과물 체크리스트
- [ ] 실물 버그 목록 + 각 버그의 "도메인 통합이 필요한 이유" 서술.
- [ ] Baseline 비교 수치(§6) — 특히 baseline이 못 찾는 버그.
- [ ] Ablation(각 적응의 기여).
- [ ] 안전 가드 발화 카운터(브릭 회피 증거).
- [ ] 대표 버그 케이스 스터디 2~3개.
- [ ] 교훈 1~3개(§7) 명시.
- [ ] Related work 델타 문장(§8) 각 항목.

---

## 부록 — 이번 세션에서 정리된 핵심 판단
- io_patterns는 **가중 회전 상시**(cap 아님). LLM 시퀀스 pattern-cap은 **CDW-무관 과잉 억압**이라 면제(harvest cap만 유지).
- **cull이 productivity로 균형**을 잡음(favored=고유 최소 커버리지). cap보다 옳음.
- **staleness(Entropic-inspired)** = 선택빈도를 productivity로 조절(포화 시드만 감쇠). 포화 전엔 no-op.
- halt 샘플링 확률성 → **단일 Seed covered_pcs union 누적**(재-calibration)으로 cull 오컬링 완화. 시퀀스는 replay union으로 이미 안정.
- new_cov는 **하한**(halt under-sampling). `[+][SC-depth]`는 edge-cov 증가 아님(프론티어 진입).
</content>
