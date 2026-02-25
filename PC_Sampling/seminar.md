# PC Sampling 기반 SSD 펌웨어 Fuzzer (v4.5) — 세미나 발표 가이드

---

## 발표 흐름 (추천 순서)

---

### 1. 왜 이 퍼저가 필요한가? (문제 제기)

**핵심 메시지**: "AFL++를 SSD 펌웨어에 그냥 쓸 수 없다"

| 구분 | 일반 퍼저 (AFL++) | 이 퍼저 |
|---|---|---|
| 커버리지 수집 | 컴파일 시 instrumentation | J-Link JTAG Halt-Sample-Resume |
| 입력 전달 | stdin / 파일 / 공유메모리 | NVMe passthru (nvme-cli subprocess) |
| 타겟 환경 | 동일 호스트 프로세스 | **별도 하드웨어** (SSD 컨트롤러) |

SSD 펌웨어는 **독립 MCU(Cortex-R8)**에서 실행되므로 소스 재컴파일도, 바이너리 instrumentation도 불가능하다. 유일하게 붙을 수 있는 통로가 **JTAG(J-Link)** 와 **PCIe(NVMe)** 두 채널이다.

---

### 2. 시스템 구성 (하드웨어 그림)

```
┌──────────────┐     JTAG/SWD      ┌──────────────────┐
│  Host PC     │◄──────────────────►│  J-Link V9       │
│  (Python)    │                    │  Debug Probe     │
│              │     NVMe/PCIe      │                  │
│  nvme-cli    │◄──────────────────►│  SSD Controller  │
│              │                    │  (Cortex-R8)     │
└──────────────┘                    └──────────────────┘
```

**포인트**: Host PC가 두 가지 역할을 동시에 한다.
- JTAG을 통해 CPU의 PC(Program Counter)를 샘플링 → **커버리지 수집**
- NVMe 명령을 통해 퍼징 입력을 전달 → **자극 주입**

---

### 3. PC Sampling이란 무엇인가?

**Halt → Read PC → Resume** 를 아주 빠르게 반복한다.

```
halt() → PC 읽기 → go()  ×N회
```

연속된 두 PC 값 `(prev_pc, cur_pc)` 를 **edge** 로 정의한다. 이것이 AFL++의 `(prev_loc >> 1) XOR cur_loc` bitmap과 대응된다.

**장점**: 펌웨어를 수정하지 않아도 된다.  
**단점**: 샘플링은 **비결정적**이다. 같은 코드가 실행돼도 어떤 PC가 잡힐지 보장이 없다.  
→ 이를 해결하려고 v4.5에서 **Calibration**을 도입.

---

### 4. 한 번의 Fuzzing Execution 흐름

청중이 가장 이해하기 어려운 부분. 단계별로 명확하게:

```
1. 시드 선택    → 에너지(Power Schedule) 기반 가중치 랜덤
2. Mutation    → AFL++ havoc + NVMe 특화 변형
3. 샘플링 시작  → 백그라운드 스레드 (J-Link)
4. NVMe 전송   → subprocess(nvme-cli passthru) [메인 스레드]
5. 완료 대기    → communicate()
6. 샘플링 종료  → stop_event.set()
7. 커버리지 평가 → current_edges ∩ global_edges == 새 발견?
8. 흥미롭다면   → corpus에 추가, 파일 저장
```

**스레드 동기화 포인트**: NVMe 명령 실행과 PC 샘플링이 **동시에** 일어난다.  
샘플링 스레드는 daemon thread로, 포화(saturation) 조건 달성 시 자동 조기 종료.

---

### 5. 포화(Saturation) 판정 — "언제 샘플링을 멈추나"

두 조건 중 하나라도 만족하면 샘플링 조기 종료:

| 조건 | 임계값 | 설명 |
|---|---|---|
| **글로벌 포화** | 20회 (기본) | 연속 N회 새 global edge 없음 |
| **idle 포화** | 10회 (기본) | 연속 N회 SSD의 idle loop PC 감지 |

idle PC는 퍼징 시작 전 진단 단계에서 자동 학습: 20번 샘플 중 30% 이상 등장하는 PC = idle loop.

---

### 6. Mutation 엔진 — AFL++ + NVMe 특화

**바이트 레벨 (havoc, 16종)**:
- bitflip, interesting values (±경계값), arith ±35, random, splice, delete/insert 등
- AFL++와 동일한 상수 (`ARITH_MAX=35`, `INTERESTING_8/16/32`)

**CDW 레벨 (NVMe 명령어 파라미터, 6종)**:
- Command Dword(CDW10~CDW15) 필드를 bitflip / arith / interesting / random으로 변형

**NVMe 특화 mutation (핵심 차별점)**:

| 변형 | 확률 | 의도 |
|---|---|---|
| opcode override | 10% | vendor-specific opcode, 잘못된 opcode 전송 |
| nsid override | 10% | NS=0, broadcast(0xFFFFFFFF), 없는 NS |
| Admin↔IO 교차 | 5% | 잘못된 큐로 전송 → 디스패치 혼란 |
| data_len 불일치 | 8% | DMA 엔진 혼란 유발 |

---

### 7. Power Schedule — "어떤 시드를 고를까"

AFLfast "explore" 방식:

```
에너지 = 2^floor(log2(전체실행수 / 이_시드_실행수))
```

- **새 시드** → 최대 에너지 16.0
- **많이 실행된 시드** → 에너지 낮아짐 → 선택 확률 감소
- → 새로 발견된 경로를 우선 탐색

---

### 8. v4.5 신기능 4가지 (하이라이트)

#### (1) Hit Count Bucketing

단순히 "이 edge를 봤냐"가 아니라 "몇 번 봤냐"를 추적. AFL++ 스타일 8단계 bucket:

```
1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+
```

루프를 1번 도는 코드 vs. 128번 도는 코드를 **다른 커버리지**로 인식 → 루프 경계 버그 탐색에 효과적.

#### (2) Calibration

새 시드를 corpus에 넣기 전 N회(기본 3회) 반복 실행해서 **모든 실행에서 등장한 edge만 stable_edges**로 분류. PC 샘플링의 통계적 노이즈 제거.

#### (3) Deterministic Stage

CDW10~CDW15에 대해 **체계적** mutation 우선 실행:
- Walking bitflip (32개)
- Arithmetic ±1~10
- Interesting 32/8 bit 값 대입

랜덤 havoc 전에 소진. AFL++의 deterministic stage와 같은 개념.

#### (4) MOpt Mutation Scheduling

**Pilot 단계** (5000회): 16개 mutation operator를 균등 사용하며 성공률 측정  
**Core 단계** (50000회): 성공률 기반 가중치로 잘 먹히는 operator 집중  
주기적으로 Pilot ↔ Core 전환.

---

### 9. Timeout Crash 처리 — "불량 현상 보존"

일반 퍼저는 crash 후 재시작. 이 퍼저는 **timeout 시 SSD를 그 상태 그대로 유지**:
- J-Link로 stuck PC를 20회 샘플링 → hang / loop / recovery 분류
- CPU를 resume 상태로 두고 퍼징 중단 (halt하지 않음)
- `dmesg` 마지막 80줄 캡처 (커널 NVMe 드라이버 동작 기록)
- crash 메타데이터(JSON) + dmesg 파일로 저장

---

### 10. 발표 시 추천 강조 포인트

1. **"instrumentation 없이 coverage-guided fuzzing"** — 하드웨어 퍼징의 핵심 도전과 해결책
2. **두 채널(JTAG + PCIe)의 동시 활용** — 스레드 모델 설명 시 구체적으로
3. **NVMe 특화 mutation** — 일반 바이트 뮤테이션만으로는 SSD 명령 처리 코드 심층 탐색 불가
4. **v4.5 calibration** — PC 샘플링의 태생적 비결정성 문제를 공식적으로 인식하고 대응

---

### 11. 예상 질문 & 답변

**Q. "왜 AFL++를 그냥 안 쓰냐?"**  
A. 타겟이 별도 하드웨어(SSD 컨트롤러)라 instrumentation 자체가 불가능하다. J-Link가 AFL++의 instrumentation을 대체한다.

**Q. "PC 샘플링은 정확하냐? edge를 놓치지 않냐?"**  
A. 놓친다. 의도적으로 통계적 근사치를 사용한다. 대신 v4.5 Calibration으로 불안정한 edge를 걸러내고, 안정적으로 관측되는 edge만 커버리지에 반영한다.

**Q. "포화 후에도 새 코드가 실행될 수 있지 않냐?"**  
A. 그렇다. 포화는 "지금 이 입력으로는 더 이상 새 경로가 없을 것 같다"는 휴리스틱이다. 다음 입력에서 다시 샘플링을 시작한다. throughput(초당 실행 횟수)과 커버리지 정확도 간의 trade-off다.

**Q. "Timeout crash 후 SSD가 복구 안 되면 어떻게 하냐?"**  
A. 그게 목적이다. 불량 현상을 보존하여 엔지니어가 직접 분석할 수 있도록 그 상태로 멈춘다. 퍼저가 자동 복구를 시도하면 재현 기회를 잃는다.
