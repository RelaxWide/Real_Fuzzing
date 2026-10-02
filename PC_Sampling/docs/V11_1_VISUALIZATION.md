# v11.1 — LLM 효과 시각화 · 실행 기록 · CSFuzz p 수정

새 실행 파일 `pc_sampling_fuzzer_v11.1.py`(`FUZZER_VERSION = "11.1.0"`). v11(`pc_sampling_fuzzer_v11.py`)은
11.0.0 그대로 둔다. 실행: `sudo python3 pc_sampling_fuzzer_v11.1.py --config fuzzer_config.json --product …`

테스트는 퍼저를 모듈 이름이 아니라 **파일 경로**로 불러온다(`tests/fuzzer_target.py` 의 `FUZZER_FILE` 한 줄이
대상. 모듈 이름은 버전과 무관한 `fuzzer_active_test`). 버전업 때는 그 한 줄만 바꾼다. 장치 경로 AST 고정
시험은 v10.2·v10.3·v11·v11.1 을 모두 검사한다.

## 1. 실행 기록 — `run_record_<run_id>.json`

실행마다 `output_dir` 에 남는다. 100명령 스냅샷 시점에, 직전 저장 후 60초 이상 지났으면 다시 쓰고, 정상 종료 시 `final: true` 로 마지막 점을 찍는다.
중간에 죽어도 그때까지의 기록이 남는다. 이 파일 하나로 실행을 비교할 수 있다.

| 키 | 내용 |
|---|---|
| `conditions` | `llm`(--rag 여부), `llm_model`, `retrieval`(켜짐·꺼짐·`off_at_start`), `product`, `fw`(sysfs firmware_rev·model, RISC-V ELF 해시), `commands`, `io_workload`, `pm`, `state`, `exceptions`, `config_sha256`, `version` |
| `series[]` | 100명령 스냅샷 중 최소 60초 간격: `t`(초), `exec`, `bb_pct`, `func_pct`, `bb`, `sc`, `state`, `new_edge{llm,mutation}`(출처별 누적 새 BB), `cmds{llm,mutation}`(출처별 누적 실행 명령) |
| `final_coverage` | 최종 BB·함수 수·%, 출처별 새 BB·명령 수 |
| `llm_status` | 끝까지 LLM 이 켜져 있었는지(연속 실패로 꺼졌는지), LLM 요청 깔때기 |
| `covered` / `covered_kind` | 최종 커버리지 집합(BB 시작 주소 / RISC-V BB 키 / PC) — 그룹별 고유 BB 계산용 |

"출처"는 LLM 계보 여부다: LLM 이 만든 시드와 그 시드를 변이한 자식은 `llm`, 나머지는 `mutation`.

## 2. 비교 — `tools/compare_runs.py`

비교할 실행들의 `run_record_*.json` 을 한 폴더에 모아 두고(하위 폴더도 찾는다):

```
python3 tools/compare_runs.py <폴더> [--out DIR] [--group llm] [--metric bb_pct|func_pct|bb] [--x time|exec] [--strict]
```

| 산출물 | 내용 |
|---|---|
| `compare_coverage.png` | 그룹별 커버리지 성장(중앙값 굵은 선, 최소~최대 음영, 실행별 얇은 선). 기준 그룹(LLM OFF) 최종 중앙값 수평선과, 다른 그룹이 그 값에 도달한 시각 |
| `compare_speedup.png` | 커버리지 수준별 도달 시간 비율(OFF 시간 ÷ ON 시간). 1 보다 크면 그 수준까지 LLM 이 빠름 — 어느 구간에서 효과가 나는지 |
| `compare_llm_share.png` | LLM 실행마다 효율 배수(명령 1개당 새 BB, LLM ÷ mutation) 추이. 1x 위 = LLM 이 같은 명령으로 더 찾음 |
| `compare_summary.md` | 그룹별 실행 수·최종 중앙값·범위·기준 대비 차이·A12·기준 최종값 도달 시간·배속·고유 BB, 실행 목록 |

- **A12**(Vargha-Delaney): 비교 그룹의 한 실행이 기준 그룹의 한 실행보다 최종 커버리지가 높을 확률.
  0.5 = 차이 없음, 0.71 이상이면 통상 큰 차이. 퍼징 성능 비교에서 표준으로 쓰는 효과 크기다
- **비교 조건 검사**: 제품·명령 목록·FW(firmware_rev·ELF 해시)·커버리지 분모가 실행마다 다르면 경고,
  `--strict` 면 중단. 같은 run_id 파일이 여러 개면 더 오래 돈 것을 쓴다
- 퍼징은 실행마다 편차가 커서 **그룹당 3~5회**를 권한다(3회 미만이면 요약에 경고)
- 비교 실험: 같은 제품·FW·설정·시작 시드·실행 시간으로 `--rag` 실행과 `--no-rag` 실행을 번갈아 돌린다

## 3. 퍼저 그래프

| 그래프 | 변경 |
|---|---|
| `coverage_growth.png` | 상단: BB % 를 **시작 전 보정(회색) / mutation(파랑) / LLM 계보(주황)** 가 찾은 몫으로 겹치지 않게 쌓은 면적. 하단: **LLM 효율 배수** = 명령 1개당 새 BB, LLM ÷ mutation(로그 축, 1x 기준선). 굵은 선은 퍼징 시작부터 누적, 얇은 선은 최근 구간. 오른쪽 아래에 1k 명령당 새 BB 수. LLM 기록이 없는 실행은 예전 velocity 막대. 범례는 왼쪽 위, plateau 는 빗금 |
| `firmware_map.png` | 그대로 |
| `csfuzz_dynamics.png` | 그대로(아래 p 수정으로 의미가 생김) |
| `command_comparison.png`, `coverage_heatmap_1d.png`, `mutation_chart.png` | **기본 끔.** `visualization.extra_charts: true` 일 때만 |

한 실행 안의 몫은 **기여도**다. "LLM 이 있어서 빨라졌다"의 근거는 2 의 ON/OFF 비교다 — LLM 이
없었다면 mutation 이 같은 BB 를 결국 찾았을 수 있다.

## 4. CSFuzz p (corpus 선택 확률) 수정

p 는 C1(edge corpus)을 고를 확률, 1−p 가 C2(state 재생) 몫이다.

| | v11.0 | v11.1 |
|---|---|---|
| C1 보상 m1 | 명령당 새 edge(0/1) | 같음 |
| C2 보상 m2 | 재생 1회당 '같은 state 재현'(0/1) — 재현은 쉬워 거의 1 | **재생한 명령당 새 edge(0/1)** — m1 과 같은 단위 |
| 갱신 | (a·m1/NC1 − b·m2/NC2)·(NC1+NC2) — 비율을 corpus 크기로 나눠 효율이 같아도 작은 corpus(state, 최대 50)가 늘 이김 | **δ = 0.1 × (a·m1 − b·m2)/(a·m1 + b·m2)** — 효율이 높은 쪽으로 한 번에 최대 0.1 |
| 보류 | 없음 | 양쪽 각 50 명령 미만이거나 둘 다 0 이면 p 유지(표본은 이어서 센다) |

v11.0 에서 p 가 첫 갱신부터 하한 0.1 에 붙어 있던 것은 state 쪽이 약해서가 아니라, 성과 없이
state 재생이 **최대로** 선택되던 상태였다.

### 비교 판정과 기록 간격

최종 커버리지와 A12는 모든 실행의 가장 짧은 관측 시간(`--x time`) 또는 실행 횟수(`--x exec`)에서
계단식 관측값을 비교한다. 더 오래 돈 실행의 추가 성과는 비교 최종값에 포함하지 않는다.
도달 시간은 **미도달을 무한대로 둔 중앙값**이다 — 도달한 실행만 골라 계산하지 않으므로(생존자 편향 없음)
그룹의 **과반**이 도달한 수준만 배속을 표시한다. 기준 목표가 OFF 최종값 중앙값이라 OFF 실행 일부는 정의상
도달하지 못하는데, '전원 도달'을 요구하면 배속이 거의 항상 비었다(2026-10-01 수정).
고유 BB 는 실행 종료 시점의 집합이라, 모든 실행의 종료가 공통 예산과 같을 때만(기록 간격 60초·길이 1% 이내
차이는 같은 종료로 봄) 계산하고 아니면 생략한다. 요약에는 공통 예산을 정한 가장 짧은 실행을 표시한다 —
중간에 죽은 실행 하나가 비교 전체를 깎을 수 있으니 확인하고 필요하면 빼고 다시 비교한다. 기록 점이 없는
실행(첫 기록 전에 죽음)은 자동으로 빼고 요약에 적는다.

저장은 별도 타이머가 아니라 100명령 회계 스냅샷에서 수행한다. 따라서 느린 명령이나 복구 중에는
60초보다 길어질 수 있고, 첫 100명령 전에는 주기 기록이 없다. 종료 정리에서는 마지막 기록을 저장한다.

### LLM 몫·효율의 집계 기준

- **퍼징 시작 후만** 센다. 시작 전 초기 시드 보정이 찾은 BB 는 출처 비교에서 빼고 위 그래프의 회색 띠로
  따로 보인다(예전엔 mutation 몫에 들어가 있었는데 그 명령은 명령 수에 없어 mutation 이 과대평가됐다).
- 효율은 **corpus 에서 골라 실행한 명령(cmd·seq)**만 비교한다 — LLM 이 패턴만 고른 I/O 워크로드(iowl)·
  state 재생(replay)은 뺀다(부스트 계산과 같은 기준). 예전엔 워크로드 명령까지 LLM 예산으로 세어
  '명령 중 LLM 몫'이 실제보다 크게 보였다. 런타임 LLM 시드 보정 명령은 분모에 넣는다.
- 위 그래프 주황 면적(발견 몫)은 모든 경로를 포함한다(iowl 로 찾은 BB 도 LLM 몫).
- 실행 기록 `series[]` 에 `found{llm,mutation}`, `sel{llm:[새 BB, 명령], mutation:[…]}`, `totals.bb_at_start` 가 남는다.
