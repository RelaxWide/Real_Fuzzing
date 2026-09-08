# v10.0 세션 인계 — BM9K1 코드 오버레이 + LLM 프롬프트 (2026-09-07~08)

> 이전 문맥 없이 이어받는 사람을 위한 문서. **왜 그렇게 했는지**와 **하지 말아야 할 것**에 무게를 둔다.
> 설계 원본은 `V10_BM9K1_PLAN.md`, 산출물 규격은 `BM9K1_ASSETS.md`.

## 0. 한 줄 요약

BM9K1(SiFive E76, RISC-V 4코어)의 **코드 오버레이 커버리지 측정**을 끝냈고,
그 결과를 LLM 프롬프트에 반영했다. 코드 작업은 완료, **남은 것은 실기 확인**이다.

---

## 1. 지금 상태

### 동작 중
- 비침습 PC 샘플링(cJTAG/SBA + PCSR 등가 레지스터), 코어별 커버리지
- 리포트 4종: `coverage_by_core.txt` / `function_coverage.csv` / `command_core_yield.csv` / `report.html`
- 코어별 `firmware_map_core<X>.png`
- 코어 샘플 예산 **적응 배분**(감쇠 수확률 기반)
- **코드 오버레이 bank 구분** — 같은 PC라도 오버레이가 다르면 다른 커버리지

### 막힌 것 (하드웨어)
- **POR 불가** — JTAG 커넥터를 꽂으면 ROM 부팅 모드로 빠진다. **물리 GND 단락이라
  소프트웨어로 해결 불가**(자세히는 §5). 현재 `--no-por` 로 운용.

### 실행
```bash
sudo python3 pc_sampling_fuzzer_v10.0.py --product BM9K1 --no-por
```
`--product` 는 필수(기본값 None → swd 로 잘못 감). `sudo` 는 `sjtag_addrs.json` 이 root-lock.

---

## 2. 코드 오버레이 — 핵심 개념

**문제**: 여러 코드 본체가 **같은 주소**를 공유한다.
- H코어: 35개(`.OVL_REGION_00~34`, section 19~53) 가 `0x56000` 공유. 총 **471KB 가 16KB 창**을 29.7배로 돌려 씀
- F코어: 4개가 `0xAE000` 공유

PC 샘플만으로는 그 주소가 35개 중 무엇인지 알 수 없다 → 전부 한 덩어리로 뭉갬.

**해결**: 펌웨어가 각 오버레이 앞머리(`base+4`)에 **헤더**를 심어뒀다.
```
0x4F564C00 | N     ← 'OVL' 매직(상위 3바이트) + 오버레이 순번(하위 1바이트)
```
버스트 **경계**에서 그 1워드를 SBA로 읽어 현재 bank 를 확정한다.

**동작 순서** (버스트마다)
```
① base+4 읽기 → bank 확정   ② 버스트 실행   ③ base+4 재확인
④ ①=③ 이면 관측에 bank 태깅 / 다르면 그 버스트 폐기(ovl-drop)
```
⚠ **핫루프(DRW 반복) 안에서는 절대 읽지 않는다.** 실측상 루프에 뭘 끼우면 실패율이 폭증한다.

### 키 구조
```
key = pack(core, bank, addr)
bank 0     = 비오버레이 본체
bank N+1   = 오버레이 순번 N   (OVL_BANK_OFFSET=1)
```
★ bank 0 을 오버레이 0번과 공유하면 **본체가 오버레이 커버리지를 삼킨다**(실측 확인).

---

## 3. 자산 파이프라인

Ghidra 추출은 **사내에서 관리**한다(저장소의 `tools/ghidra_export.py` 는 원본 참고용).
Python 추출기는 실측 비교에서 Ghidra 대비 **BB 6천·간선 2만 열세**라 폐기했다(`git log` 에 남음).

필요한 파일과 형식은 **`docs/BM9K1_ASSETS.md`** 에 정리돼 있다. 요약:
```
basic_blocks_core<X>[_ovl<N>].txt   0xSTART 0xEND        (END exclusive)
functions_core<X>[_ovl<N>].txt      0xENTRY <십진size> <name>
callgraph_core<X>.txt               0xCALLER 0xCALLEE
FW_<X>Core_overlay_map.json         빌드 레이아웃 맵 — **그대로 두면 된다**
symbols.json                        cores.<X>.counts
```

**레이아웃 맵만 있으면 된다.** 별도 판별표를 만들 필요 없다 — 헤더 규약으로 유도한다
(`riscv_cov.overlay_from_layout`). 규약이 깨지는 펌웨어가 나오면
`overlay_probe_core<X>.json`(워드→bank 표)을 손으로 두면 그쪽이 우선한다.

### 배치 후 확인
```bash
python3 tools/check_bm9k1_setup.py     # ②-b 절이 전부 ✅ 여야 한다
```

---

## 4. 실기에서 확인할 것 (미완)

시작 로그:
```
[Overlay] H: 프로브 0x56004 OK (현재 bank=12, 오버레이 35개, bank 표 35개)
```
- **이 줄이 나오면 오버레이 구분이 동작 중이다.**
- `SBA 읽기 실패` → SBA가 코드 메모리에 못 닿음. bank 0 으로 접혀 **종전과 동일하게** 동작(퍼징은 정상)
- `매직과 불일치` → 맵과 펌웨어가 다른 빌드

주기 `[Stats]`:
```
| ovl: H 18/35bank 126/1,050BB | ovl-drop: 340
```
- `ovl-drop` = 버스트 중 스왑으로 버린 샘플. 크면 그 코어 `burst_len` 을 줄인다
- `coverage_by_core.txt` 하단에 bank 별 커버율·미관측 목록

**한 bank 에만 몰리면 경고가 뜬다** — 프로브가 굳었거나 그 오버레이만 쓰는 중.

---

## 5. POR 문제 — 재시도 금지 목록

**원인 = 물리 GND 단락.** 이 시료는 특정 핀 2개를 GND로 단락하면 ROM 부팅 모드로
들어가는데, JTAG 커넥터를 꽂는 행위가 같은 일을 한다(20핀 중 4·6·8…이 전부 GND).

**이미 시도했고 안 되는 것들 — 다시 하지 말 것:**
| 시도 | 결과 |
|---|---|
| 젠더의 `GP15_ROM_BOOT` / `GP12_ROM_DEBUG` 토글(VCC/중립/GND) | **어떤 조합도 안 됨** — 접지되는 핀이 이 둘이 아니다 |
| POR 동안 pylink 세션을 닫아 핀 high-Z | 무효 |
| J-Link 역주입(back-powering) 가설 | 증상 설명에 불필요하게 복잡. 접음 |

관련 코드(`por_release_link`, `por_pre_cmd`, GPIO 도구)는 **전부 되돌렸다**(`3b385ef`).
되살리려면 `git revert 3b385ef`.

**해결 방향(하드웨어)**: 케이블 분리 상태로 각 핀-GND 도통 측정 → 하드웨어 문서의
ROM_BOOT/ROM_DEBUG 스트랩 핀 번호와 교집합 → 그 핀을 하우징에서 제거.
**cJTAG 은 TCKC/TMSC 2선 + GND + VTref 면 동작**하므로 대부분의 핀은 없어도 된다.
자르기 전 캡톤 테이프로 되돌릴 수 있게 검증할 것.

---

## 6. LLM 프롬프트 — 이번에 바뀐 것

**형식·길이·블록 구성은 그대로**고, `Coverage gaps` 한 블록의 **내용 품질**만 바뀌었다.
예산(`RAG_MAX_UNCOV_FUNCS=40`)이 고정이라 프롬프트가 길어지지 않았다.

| | 이전 | 현재 |
|---|---|---|
| 후보 풀 | 본체(bank 0)만 | 본체 + 오버레이 표 전부 |
| 정렬 | 크기순 | **콜그래프 홉 거리순** |
| 이름 필터 | `FUN_/sub_` + `(default\|thunk\|switch)` | `FUN_/sub_` 만 (제품 목록으로 관리) |
| frontier 도달 판정 | bank 0 만 | 모든 bank |

### 왜 홉 거리인가
실제 심볼이 `ARES::IHAL_Fcore::Sync`, `ZEUS::IO::SVBlockConfig::GetIndex` 처럼 생겨서
**이름 패턴 규칙이 통하지 않는다**(제품마다 다르고, 저런 접근자/HAL 은 CDW로 겨냥 불가).
반면 "지금 밟은 코드에서 몇 홉인가" 는 콜그래프로 계산되는 사실이다.

```
hops=1     nvme_format_handler        ← frontier
hops=2     fw_commit_apply
hops=None  ARES::IHAL_Fcore::Sync     ← 크기 3배인데도 뒤로
```
⚠ 콜그래프는 **직접 호출만** 담는다(함수 포인터 미포함) → `hops=None` 은 '절대 불가'가
아니라 '알려진 경로 없음'. 그래서 **제외가 아니라 후순위**다.

시작 로그의 `[LLM/cov] 미도달 N개 중 M개는 도달 경로 미상` 비율을 볼 것.
**90% 같으면** 콜그래프가 간접 호출을 너무 많이 놓치는 것 → `rag.max_hops` 조정 검토.

### 이름 필터 관리
```json
"rag": { "autoname_kw_off_products": ["BM9K1"] }
```
`(default|thunk|switch)` 는 `set_default_mode` 같은 **진짜 심볼도 지운다**. 심볼이
살아있는 제품만 목록에 넣는다(arch 가 아니라 제품의 성질 — ARM 제품도 해당될 수 있다).

---

## 7. 이 세션에서 밟은 지뢰 (같은 실수 반복 방지)

| 증상 | 원인 | 교훈 |
|---|---|---|
| `AttributeError: read_word` 로 캠페인 중단 | 편집 스크립트의 `str.replace` 앵커 불일치 → **조용한 no-op**. 반환값 미확인 | 문자열 치환 후 **실제 속성/실행**으로 확인 |
| `NameError: _riscv_cov` | 함수에 import 없음. 소스 문자열 테스트는 이걸 못 잡음 | 실행 경로를 **직접 실행**해 검증 |
| 표 35개 넣었는데 아무 변화 없음 | 판별표 파일명 불일치 / `bank_sizes` 키가 섹션인덱스 | 조용한 무시 금지 — 경고 + 이유 출력 |
| 커버리지 300% | bank 를 키에 넣었는데 분모는 본체만 | 분자/분모를 같은 기준으로 |
| CM/Q 에 오버레이가 있다고 나옴 | Ghidra 가 **0바이트 파일** 생성 | 빈 파일은 '있는 표'가 아니다 |
| 크래시가 텍스트 로그에 없음 | `run()` 의 `finally` 가 먼저 돌아 정상 종료처럼 보임 | 최상위 `[FATAL]` 로깅 |
| `__init__` 구간 경고가 로그에 없음 | `setup_logging` 이 `run()` 안에서 호출 | `_EarlyBuffer` 로 재생 |

---

## 8. 테스트에 대하여

**테스트 코드는 요청에 따라 전부 삭제했다**(`f532202`). 삭제 직전 396개가 통과 중이었고
git 히스토리에 남아 있다:
```bash
git checkout f532202^ -- PC_Sampling/test_riscv_cov.py    # 등
```
지금은 변경 검증을 **합성 데이터 실행**으로만 한다. 소스 문자열 검사로는 잡히지 않는
종류(NameError 등)가 있으므로, 코드를 고치면 **반드시 실행해 결과를 확인**할 것.

---

## 9. 다음에 할 만한 것

1. **실기 확인**(§4) — `[Overlay]` 줄, `ovl:` 진행, `ovl-drop`, 경로 미상 비율
2. **`[LLM/stats] LLM이 뚫은 새 커버리지(누적)`** 추이 — 프롬프트 개선의 유일한 실측 지표
3. corpus 한계 증가율 — 10k·30k 시점에 곡선이 눕는지
4. `primary_core`/`weights` — 적응 배분이 수렴하는지(`coverage_by_core.txt` 효율순)
5. 보류: 오버레이별 콜그래프(있으면 frontier 가 오버레이까지 확장), filemap 기반 모듈 롤업

---

## 10. 주요 커밋

```
4cabde7  모든 입력이 interesting 이던 문제 — 배경 커버리지 선반영
20244f5  함수 커버리지 리포트 3종 + 회계 경계
d61ec57  명령 × 코어 수확량 표
3b385ef  POR 훅 전부 되돌림 (물리 문제로 확정)
9cdd6fe  코어 샘플 예산 적응 배분      79c0595  저가중치 코어 영구 배제 수정
04a749c  플랜 §4/§6 누락 4건(핸들 락·버스트 지터·seed 로그·autoname)
52f1cbb  CoverageModel 오버레이 bank 지원   5955fef  런타임 bank 주입
38e7bb4  오버레이 회계 전 구간 bank 반영(커버리지 300% 수정)
a4ceb8a  레이아웃 맵만으로 판별 — 생성 단계 제거
0139f24  빌드 산출물 이름 그대로 수용
7e5e34a  docs/BM9K1_ASSETS.md
34f1ba6  0바이트 파일 대응        27e2556  NameError + [FATAL] 로깅
f532202  테스트 제거 + 툴 정리    ff0c9c9  overlay_probe·rag 정리
9171fb3  LLM 미도달 목록에 오버레이 포함
99cf7b0  미도달 순위를 콜그래프 거리로   0d6c996  autoname 필터 제품명 관리
```
