# v11.4 — 응답 시그니처 커버리지 (디버거 없는 피드백)

## 왜
`--no-jlink` 은 PC/BB 커버리지가 늘 0 이다. 그동안 피드백은 SC-depth(명령별 0~3단계) 하나였고, 명령당
4단계라 초반 수백 실행 뒤엔 사실상 피드백 없는 무작위 퍼징이 됐다. 처음 보는 (명령, status) 쌍(`_sc_seen`)은
로그·ledger 에만 남고 corpus 판정에 쓰이지 않았다.

**전제(사용자 결정 2026-10-20):** 장치가 돌려준 응답이 처음 보는 모양이면 펌웨어가 새 경로를 탔다고 본다.
이 전제를 J-Link 데이터로 검증하는 단계는 두지 않는다(검증용 도구 `tools/ledger_sc_corr.py` 는 남아 있다).

## 시그니처
`(명령, 완료 status)` + `dims` 에서 고른 축.

| 축 | 값 | 출처 |
|---|---|---|
| (기본) 명령 | track_key(실제 발송 명령) | 회계 |
| (기본) status | 장치 full status(성공 0, DNR 등 플래그 포함) | nvme-cli stderr |
| `latency` | 완료 시간 구간 — `latency_edges_ms` 경계(기본 4/16/64/256/1024ms → 6구간) | 프로세스 생성 뒤~완료. halt 샘플러는 프리즈 뺀 펌웨어 시간 |
| `dw0` | CQE DW0 모양: 없음 `-` / `0` / CDW11 그대로 `echo` / 유효 바이트 수 `b1`~`b4` | nvme-cli `NVMe command result:` |
| `prev` | 직전 명령과 그 SC-depth (기본 꺼짐 — 키가 많이 늘어난다) | 회계 |

errno(장치 미도달)·timeout 은 시그니처를 만들지 않는다. 축 값은 모두 상한이 있어 명령·status 당 최대
6 × 7 개다. 전체 상한 `max_keys`(기본 4096)를 넘으면 경고 1회 후 더 기록하지 않는다.

## 설정 — `fuzzer_config.json` `strategy.response_coverage`
```json
"response_coverage": {"enabled": "auto", "dims": ["latency", "dw0"],
                      "latency_edges_ms": [4, 16, 64, 256, 1024], "max_keys": 4096}
```
- `enabled: "auto"` — 샘플러가 PC 를 못 모을 때(`COLLECTS_COVERAGE=False` = NullSampler = `--no-jlink`)만 피드백.
  `true` 는 J-Link 연결 중에도 보조 피드백, `false` 는 끔.
- 수집·`[Stats]`·ledger(`sig_new`)·run_record(`resp_sig`) 기록은 enabled 와 무관.
- 잘못된 값은 시작 시 `[FATAL]` 로 멈춘다.

## 로그
- 새 시그니처로 corpus 진입: `[+][Resp-Cov] cmd=Read src=… sig=Read 0x0002 lat<16ms dw0=- total_sig=N corpus=… exec=…`
  (PC 를 못 모으면 `total_PC` 를 찍지 않는다.)
- `[Stats]`: PC 를 못 모으면 `pcs: 0` 대신 `resp_sig: N (sc: M)`. `[StatCov]` 생략.
- `[+] New coverage! … +0 PCs` 는 새 PC 가 있을 때만.

## 남은 것
- 차트·coverage report 의 PC/BB 패널은 아직 `--no-jlink` 에서도 그린다(0).
- `--no-jlink` A/B(SC-depth 만 vs 응답 시그니처): 같은 시간 동안 고유 시그니처 수·timeout/crash·error log·SMART 변화.
- 축 추가 후보: 반환 데이터(Identify/GetLogPage) 해시 모양, NVMeStateMonitor 변화 종류.
