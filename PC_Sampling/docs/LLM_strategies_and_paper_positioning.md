# LLM-Guided SSD Firmware Fuzzing — 전략 정리 & 논문 포지셔닝 (v9.2 기준)

> 대상: `pc_sampling_fuzzer_v9.2.py`. LLM 을 "두 번째 시드 공급원"으로 쓰는 coverage-guided NVMe
> 펌웨어 퍼저. 이 문서는 (1) v9.2 에 들어간 LLM 전략/기법 전부, (2) 근거 논문, (3) 논문화 시
> 독보적(도메인 특화) 기여를 정리한다.

---

## 0. 시스템 한눈에
- **타깃**: 실제 SSD 컨트롤러 펌웨어(Samsung PM9M1/P9, Cortex-R8/R5). nvme-cli passthru 로 명령 주입.
- **커버리지 측정**: J-Link/OpenOCD **halt 기반 PC 샘플링**(P9=DBGPCSR 미구현이라 halt 필수). Ghidra BB 매핑.
- **LLM 역할**: 코어 퍼징 루프(변이-발송-측정)는 무변경. 스펙 아는 LLM 이 **백그라운드 워커**로 신규
  명령군 시드·멀티-명령 시퀀스를 시드 풀에 주기 주입하고 corpus 를 평가(2-PC Samba drop-box 경유).
- **3 tasks**: `new_group_seeds`(단일 시드), `sequences`(상태의존 체인), `corpus_eval`(평가).

---

## 1. v9.2 LLM 전략/기법 전부

### A. Grounding & Feedback (프롬프트에 무엇을 주는가)
| # | 기법 | 내용 | 버전 |
|---|---|---|---|
| A1 | **디바이스 능력 grounding** | Identify OACS/ONCS 로 지원/미지원 명령 제시 | v9.0 |
| A2 | **SC-status 되먹임 (digest)** | 명령별 **실제 NVMe 완료상태**를 "미구현(0x01)=제안금지 / 구현=필드 교정"으로 **분리** 제시 (기존 저수확 단일목록의 오조준 제거) | v9.1 |
| A3 | **accept-CDW few-shot** | 디바이스가 실제 **accept(SC=0)한 CDW 값**을 유효 envelope 예시로 제시(positive grounding) | v9.1 |
| A4 | **SC-depth 되먹임** | 명령별 "펌웨어 처리 깊이(0~3)"와 **성공까지 남은 거리** 제시 → LLM 이 어느 명령을 얼마나 밀지 판단 | v9.2 |
| A5 | **닫힌 루프(자기 제안 되먹임)** | "네 제안이 이미 진전시킨 명령들 — 계속 밀어라"(`_llm_depth_cmds`) → iterative repair | v9.2 |
| A6 | **coverage-gap 타깃팅** | 미접촉 함수(정적분석) + never-sent/under-explored 명령 랭킹 | v9.0 |
| A7 | **구조적 data payload 지시** | 구현된 needs_data 명령에 **스펙 레이아웃**(`_DATA_LAYOUTS`: Copy range/Reservation key/DSM 등) 제시 → LLM 이 valid `data_hex` 생성 → **data 파싱 코드** 도달 | v9.2 |
| A8 | **스키마 전량 노출** | 스키마 요약 `[:20]` 캡 제거 → 구현된 전 명령 노출(명령 고착 해소) | v9.2 |

### B. Scheduling & Energy (탐색을 어떻게 유도하는가)
| # | 기법 | 내용 | 근거 |
|---|---|---|---|
| B1 | LLM 시드 에너지 부스트 | `seed_class='llm*'` 소폭 가중 → 실제 탐색되게 | AFLFast power schedule |
| B2 | 컬링 grace | LLM 시드는 exec_count<grace 동안 컬링 보호(변이 기회) | — |
| B3 | 시퀀스 에너지 부스트 | SequenceSeed 의 /len 페널티 상쇄 | — |
| B4 | **확정 미구현 에너지 바닥** | SC=0x01 지배 명령 시드는 에너지 floor(opcode 디코드에서 포화) | **Entropic / AFLFast COE** |
| B5 | **SC-depth 보상** | 시드가 명령의 최대 SC-depth 를 전진시키면 **PC 커버리지 0 이어도 is_interesting → corpus 진입** → 프론티어 탐색 유도 | **Entropic(정보이득)** 응용 |

### C. Validation & Safety (LLM 산출물을 어떻게 거르는가 — brickable 타깃)
| # | 기법 | 내용 |
|---|---|---|
| C1 | **3중 방어** | `validate_and_repair`(스키마/reserved) → `is_dangerous`(Format/Sanitize/lock/NS-delete) → `_send_nvme_command` 발송 가드(`RC_SKIP`) |
| C2 | JSON 재시도 | 응답이 JSON 아니면 교정 리프롬프트로 재요청 |
| C3 | dedup | (cmd+CDW+data) 시그니처로 중복 주입 차단 |
| C4 | **잠금/브릭 가드** | SecuritySend SECP **allowlist**(info 0x00만), Lockdown(0x24) 차단, Sanitize/Format(--no-erase), FWCommit brick 인지, NS-delete 차단 |
| C5 | **data 생성 제외** | FWDownload(실 fw_bin)·SecuritySend(크리덴셜) 는 LLM data 생성 제외 |

### D. 측정 보완 (도메인 핵심)
| # | 기법 | 내용 |
|---|---|---|
| D1 | **SC-depth 지표+보상** | halt 샘플러가 못 보는 fast-path 도달을, 디바이스가 **항상 반환하는 완료상태**로 결정적 측정(D 참조 = 아래 §3 핵심) |
| D2 | 런타임 미구현 판정 | SC=0x01 지배 → "이 펌웨어 미구현" 확정(OACS 광고값보다 정확) |
| D3 | state-cov 전역 이벤트 필터 | Sanitize In Progress 등 전역 상태 스윙을 동시-변경 필드 임계로 제외 |
| D4 | LLM 기여율 지표 | new_cov/전체 커버리지 %, depth_adv 를 `[StatCov]`/`[LLM/stats]` 출력 |

---

## 2. 관련 논문 (근거)

| 논문 | 무엇 | 이 시스템에서 쓴 곳 |
|---|---|---|
| **AFLFast** — Böhme, Pham, Roychoudhury, *Coverage-based Greybox Fuzzing as Markov Chain*, CCS'16 / TSE'19 | CGF 를 Markov chain 으로 모델링, 저밀도 경로에 에너지 몰기(power schedule). COE=고빈도 경로 컷오프 | B1(explore schedule), B4(COE 정신=미구현 컷오프) |
| **Entropic** — Böhme, Manès, Cha, *Boosting Fuzzer Efficiency: An Information Theoretic Perspective*, FSE'20 (libFuzzer 기본값) | 정보이득 많은 시드에 에너지, 정보 못 내는 시드엔 덜 | B4·B5(생산성 기반 에너지/보상), D1(SC-depth 를 "정보이득" 축으로) |
| **ChatAFL** — Meng, Kabir, Roychoudhury et al., *Large Language Model guided Protocol Fuzzing*, NDSS'24 | LLM 로 (a) grammar 추출→structure-aware 변이 (b) seed enrichment (c) saturation 시 새 메시지 생성 | A7(구조적 data=grammar), A6/sequences(enrichment), plateau 트리거(saturation) |
| **KernelGPT** — Yang, Zhao, Zhang et al., *Enhanced Kernel Fuzzing via LLMs*, ASPLOS'25 | LLM 이 syscall 명세를 합성 + **검증 피드백으로 반복 수리** | A2/A4/A5(SC-status 검증 oracle 로 iterative repair), C1(스키마 검증) |
| **Fuzz4All** — Xia, Deng, Zhang et al., *Universal Fuzzing with Large Language Models*, ICSE'24 | LLM 범용 퍼저 — autoprompting, generate/mutate 로테이션, few-shot | A3(few-shot), 3-tasks 로테이션 |
| **AFL** — Zalewski | favored/cull(엣지 최소 커버 집합) | B2/컬링, favored 지표 |

> 근거 축약: **에너지/스케줄 = AFLFast+Entropic**, **LLM 프롬프트/문법/수리 = ChatAFL+KernelGPT+Fuzz4All**.

---

## 3. 논문화 시 독보적(도메인 특화) 기여

기존 LLM-fuzzing 논문(ChatAFL/KernelGPT/Fuzz4All)은 **소프트웨어 타깃 + 계측 커버리지(edge/BB)** 를 전제한다. 이 시스템의 차별점은 **"실물 SSD 펌웨어 + 하드웨어 제약 커버리지 측정"** 이라는 도메인에서 나온다.

### ★ 핵심 novelty ① — Completion-status **SC-depth**: 커버리지 측정 blindness 보완 신호
- **문제**: Cortex-R5 는 **DBGPCSR/ETM 하드웨어 트레이스가 없어** halt 샘플링밖에 못 쓰고, halt 샘플링은 **빠른 펌웨어 경로(짧은 핸들러, opcode reject)를 구조적으로 under-sample** 한다. 즉 코드 커버리지 신호 자체가 눈이 먼다. (기존 논문은 계측/트레이스가 완전하다고 가정 → 이 문제 자체가 없음.)
- **해법(신규)**: 프로토콜이 **항상 반환하는 완료상태(NVMe SC)** 를 **"펌웨어가 명령을 어디까지 처리했나"의 서수(ordinal) depth** 로 사용. `opcode 디코드(0x01) < 필드검증(0x02) < 핸들러(0x80/feature) < 성공(0x00)`. **샘플링 운과 무관하게 100% 관측**되므로, halt 샘플러가 놓친 도달을 결정적으로 포착.
- **이중 용도**: (a) **측정** — LLM 기여를 코드 커버리지 밖에서 정량화(new_cov 하한 보완), (b) **보상** — depth 전진을 corpus admission 으로 연결해 **"의미적 커버리지"가 탐색을 구동**(코드 커버리지가 눈멀 때도).
- **왜 독보적**: coverage-guided fuzzing 은 보편적으로 **code coverage** 에 의존한다. **프로토콜 완료-상태 의미론을 depth 프록시로 삼아 하드웨어 제약 커버리지를 보완**하는 건 문헌에 없다. Entropic 의 "정보이득" 아이디어를 **디바이스 응답 기반 관측 가능 신호**로 실체화한 도메인 특화 기여.

### ★ 핵심 novelty ② — 디바이스-grounded **런타임 능력 모델** (SC=0x01)
- **문제**: 광고된 능력(OACS/ONCS 비트)이 **실제와 어긋난다**(예: MI 지원인데 OACS=0). 스펙/광고 기반 grounding 은 오조준을 낳는다.
- **해법(신규)**: 명령의 **실제 SC=0x01(Invalid Opcode) 응답**으로 "이 펌웨어의 진짜 구현 표면"을 **런타임 경험적으로** 확정하고, 이를 (a) 에너지 프루닝, (b) LLM 프롬프트 조준(죽은 opcode 회피/구현 명령 필드 교정)에 사용. 상태의존 구현이면 자동 해제.
- **왜 독보적**: LLM 을 **광고 스펙이 아니라 타깃의 실측 응답으로 grounding** 하고, 그 능력 모델을 **에너지·프롬프트 양쪽에 되먹이는** closed-loop. 펌웨어처럼 스펙-구현 괴리가 큰 도메인에 특화.

### ★ 핵심 novelty ③ — Brickable 타깃을 위한 **LLM-safe 발송 아키텍처**
- **문제**: 대부분의 퍼징 타깃은 소프트웨어(재시작 가능). 실물 SSD 펌웨어는 **잠금(SecuritySend/Lockdown)·소거(Sanitize/Format)·브릭(FWCommit)** 으로 **영구 손상 + 비싼 실물 손실**이 가능. LLM 이 위험 명령을 제안할 수 있다.
- **해법**: LLM 은 자유 제안하되 **다층 chokepoint 가드**(스키마→위험필터→발송 가드)가 최종 backstop. 특히 **SECP allowlist**(denylist 의 벤더/IEEE1667 잠금 벡터 누락 방지)로 잠금 원천 봉쇄. 실 자산(fw_bin) 명령은 LLM data 생성 제외.
- **왜 독보적**: "LLM 창의성 + 비가역 타깃 안전"의 실전 통합. 문헌의 LLM-fuzzing 은 안전이 거의 논점이 아님(재시작 가능하니). **실물 브릭 리스크 하의 LLM 퍼징 안전 아키텍처**는 시스템 기여.

### ★ 핵심 novelty ④ — 하드웨어-in-the-loop **복원력**
- halt-vs-컨트롤러 타이밍 레이스(호스트 freeze), sampler 의 flaky under-sampling 과 **공존하며** LLM 가이드를 돌리는 시스템: corpus 체크포인트+자동재부팅으로 freeze 를 "리부팅 1회 비용"으로 흡수. 실물 계측의 불완전성을 전제한 파이프라인.

### 부차적 기여
- **구조적 data payload 생성**(A7): CDW 변이·값-사전으로 못 뚫는 NVMe **data 파싱 코드**를 LLM 스펙 지식으로 타깃 — ChatAFL grammar 를 NVMe 데이터 구조에 특화.
- **닫힌 SC-status repair 루프**(A5): KernelGPT 의 "검증 피드백 수리"를 **시드 생성 + 완료상태 oracle** 로 이식.

---

## 4. 논문 포지셔닝 (한 문단 피치)

> *실물 SSD 컨트롤러 펌웨어는 (i) 하드웨어 트레이스 부재로 커버리지 측정이 부분맹(halt 샘플링이 빠른 경로를 놓침)이고, (ii) 광고 능력과 실제 구현이 어긋나며, (iii) 잠금/소거/브릭으로 비가역 손상이 가능해, 기존 LLM-guided fuzzing 을 그대로 적용하기 어렵다. 우리는 spec-aware LLM 을 두 번째 시드 공급원으로 두되, **프로토콜 완료-상태(NVMe SC)를 "처리 깊이(SC-depth)" 서수로 삼아 코드 커버리지의 측정 blindness 를 보완**(측정+보상)하고, **디바이스 실측 응답으로 런타임 능력 모델을 grounding** 하며, **다층 발송 가드로 브릭 안전을 보장**하는 파이프라인을 제시한다. new_cov 발생률이 baseline 대비 44배(8→122), LLM 시드 favored 비율 76% 로, 하드웨어 제약 환경에서 LLM 기여가 정량적으로 유효함을 보인다.*

**타깃 학회**: NDSS/USENIX Security/CCS(security fuzzing), 또는 ICSE/FSE/ASE(SE 계열 LLM-fuzzing), embedded/systems 각도면 EuroSys/ATC.

**차별화 요약 (기존 대비 한 줄)**:
- vs ChatAFL/Fuzz4All: 소프트웨어·완전계측 → **실물 펌웨어·부분맹 계측 + 완료상태 depth 보완**.
- vs KernelGPT: 스펙 합성 → **시드 생성 + 실측 SC oracle 로 능력 grounding·repair**.
- vs AFLFast/Entropic: 에너지 스케줄은 계승하되 **"정보이득"을 디바이스 완료상태로 관측 가능화**.

---

## 5. 재현/측정 (논문 실험 설계 힌트)
- **ablation**: (a) SC-depth off/on(측정+보상), (b) SC-status grounding off/on, (c) 스키마 캡 유무, (d) 구조적 data on/off → 각각 new_cov·favored·depth_adv·BB% 추이.
- **baseline**: v9.0(SC 되먹임 전) vs v9.2. 실측 예: new_cov 8@350k → 122@120k(≈44× rate), favored 9→31(76%).
- **지표**: new_cov(하한), SC-depth 전진, LLM 기여율(new_cov/covered), favored 비율, drop/dupe 율.
- **한계 명시**: new_cov 는 halt under-sampling·global-first 라 하한; SC-depth 로 보완하나 완전 커버리지 아님.
