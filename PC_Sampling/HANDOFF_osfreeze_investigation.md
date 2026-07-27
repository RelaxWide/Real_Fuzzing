# HANDOFF — OS Freeze 조사 (J-Link halt 관련), 2026-07 진행 중

퍼징 중 **호스트 OS 하드 프리즈** 조사. 실측으로 firmware-first/SMM → (A) AER 인터럽트 storm →
(C) non-posted read 무한 정지를 차례로 폐기. 현재 1순위는 **(F) flow-control credit 고갈로 인한
posted write 백프레셔 데드락**.

## 증상
- **J-Link halt 샘플러(P7, Cortex-R5)** 사용 시 퍼징 도중 **호스트 전체 프리즈 → 재부팅 필요.**
- 명령 **~30만~48만** 후 발생하나 이 숫자는 **노이즈**(과거 25만/37만/44만 등 제각각, 무상관).
- **즉각·전체·kernel-silent**: 다른 PC 실시간 `dmesg`/`journalctl -kf` 에 프리즈 순간까지 아무것도
  안 찍힘. 하지만 **재부팅 후 `journalctl -k -b -1` 의 마지막 줄**에 단서가 남음(아래).

## 확정된 것
- **J-Link halt 침습이 트리거.** `--no-jlink`(null 샘플러) **100만 명령 무프리즈** vs halt 켜면
  30~48만에서 프리즈. 침습 halt 유무가 유일 변수.
- **샘플러 코드 버그 아님.** `_read_all_pcs`(halt→read PC→go)는 SWD/J-Link(USB)로만 동작 — 호스트
  PCIe 미접근. 원인은 **R5(=SSD 컨트롤러 CPU)를 물리적으로 멈춘 물리적 부작용.**
- **AER 는 OS-native.** 부팅 로그 `ACPI ... _OSC: OS now controls [... AER ... DPC]` → 커널이 AER/DPC
  소유. → **firmware-first/SMM 아님**(GHES/APEI/ERST 로그 없음, pstore 비어 있음, BMC 없음).
- **AER corrected 에러는 원인이 아니라 부산물이었다(2026-07-27 확정).** 이전 "핵심 단서"였던
  ```
  pcieport 0000:00:01.1: AER: Corrected error message received from 0000:00:01.1
  pcieport 0000:00:01.1: PCIe Bus Error: severity=Corrected, type=Data Link Layer, (Receiver ID)
  ```
  (그 부팅에서 106개, 건강한 링크는 0) 는 **`pci=noaer` run 에서 0 으로 사라졌는데도 프리즈가
  그대로 재현**됐다. → halt 가 링크를 흔든 흔적일 뿐, 프리즈 메커니즘이 아니다.
- **프리즈는 커널 에러 처리 경로를 타지 않는다.** 에러 경로면 뭐라도 찍는다. `noaer` run 의
  `journalctl -k -b -1` **마지막 줄은 평범한 로그**(특이사항 없음) — 완전 무음.
  **무음 = 하드 행**(CPU 가 완료되지 않는 트랜잭션에 물려 통째로 정지)의 특징이지,
  인터럽트 storm/livelock(그래도 일부는 찍힘)의 특징이 아니다.

## 배제된 것
| 후보 | 근거 |
|---|---|
| halt 샘플러 고착/실패 | halt 실패율 0/665758 (0%) |
| vmalloc 고갈 / 메모리 누수 | VMon 안정(감소 없음) |
| kernel taint / 손상 | taint 없음 |
| page-alloc / memory corruption | 시그니처 불일치 + 커널 debug 옵션 없음(cmdline 확인) |
| 진단용 커널 debug 옵션(관측자 효과) | `debug_pagealloc/page_poison/kasan/slub_debug` 없음 |
| PM perturbation | `--pm` 미사용 |
| **firmware-first / SMM** | **폐기** — `_OSC` 가 OS-native AER 확인, GHES/APEI/ERST·pstore·BMC 전무 |
| **(A) AER 인터럽트 storm → livelock** | **폐기(2026-07-27)** — `pci=noaer` 적용(`/proc/cmdline` 확인) + corrected 카운트 **0** 인데도 프리즈 재현. 커널 AER 처리 경로 무관 |

## 실험 기록 — `pci=noaer` (2026-07-27)
| 항목 | 결과 |
|---|---|
| cmdline 적용 | ✅ `pci=noaer` 확인 |
| `journalctl -k -b -1 \| grep -ci "Corrected error"` | **0** (이전 106) |
| 마지막 줄 | **평범** — 특이 로그 없음 (완전 무음) |
| 프리즈 | **재현됨** |

→ **(A) 폐기.** 동시에 **부작용 주의: noaer 로 카나리아도 같이 껐다.** 링크는 여전히 불안정할 수
있는데 dmesg 로는 안 보인다. 단, **AER status 비트는 리포팅과 무관하게 하드웨어가 계속 셋**하므로
`setpci` 직접 읽기로 인터럽트 없이 가시성 복구 가능 → `pcie_link_probe.py`.

## 실험 기록 — Completion Timeout 점검 (2026-07-27)
`pcie_link_probe.py --show-cto` 실측: **root port·endpoint 둘 다 value=0(50us~50ms),
Disable=off**(= 타임아웃 **활성**).

→ **(C) 폐기.** 완료 안 되는 non-posted read 는 최대 50ms 안에 타임아웃되고 all-Fs 로 반환된다.
무한 정지가 아니므로 영구 프리즈를 설명 못 함.

**그러나 이 사실이 범위를 좁힌다:** Completion Timeout 은 **non-posted 트랜잭션만** 보호한다.
**posted write 는 completion 이 없어 타임아웃 개념 자체가 없다.** → 아래 (F).

## 현재 가설 (우선순위 순)

**★ (F) Flow-control credit 고갈 → posted write 백프레셔 데드락 — 1순위 (신규, 2026-07-27)**
R5 halt → 펌웨어가 인바운드 큐를 못 비움 → 컨트롤러가 **UpdateFC DLLP(크레딧 반환) 중단** →
root port posted 크레딧 고갈 → 호스트 posted write(**NVMe 도어벨 write 가 정확히 이것**)가 발행
불가 → CPU write buffer 포화 → CPU 정지 → 락 보유 상태라 전 코어 연쇄 → 완전 무음.
**표준 PCIe 에 크레딧 고갈용 타임아웃이 없다 — 설계상 무음이고 설계상 데드락.**

기존 관측 두 개가 이 가설과 정확히 맞는다(= 사후 설명이 아니라 예측 일치):
- **`go_settle` 무반응**: 1ms=25만·37만 / 5ms=44만 / 10ms=18만·9만. 누적 노출이 원인이면 duty
  cycle 에 반응해야 하는데 안 했다. 크레딧 데드락은 *halt 간격*이 아니라 *halt 가 나쁜 순간에
  착지했는지*의 문제라 간격에 무반응인 게 맞다.
- **재현 횟수의 큰 산포**: halt 마다 독립적 확률 p → **기하분포** → 9만~48만(5배 이상) 산포가
  자연스럽다. 지금까지 "노이즈"로 치부한 산포가 사실 메커니즘의 지문.

**(B) 링크 불안정 자체가 치명 — 여전히 유효**
corrected 가 누적되다 uncorrectable/link-down 으로 번짐. noaer 로 관측을 잃었을 뿐 배제 안 됨.
`pcie_link_probe.py --clear` 로 구간별 발생률을 되찾아 프리즈 직전 급증 여부를 본다.

**(D) DPC 발동 — 유효**
`_OSC` 상 **DPC 는 여전히 OS 소유**(noaer 는 AER 서비스만 끔). uncorrectable 시 link containment →
이후 MMIO 가 안 돌아오면 (C) 와 같은 정지로 수렴. `pcie_ports=compat` 로 포트 서비스 전면 차단해
배제한다.

## 다음 단계 (중지 지점)

0. **가시성 확보 — netconsole (최우선).** 이 조사의 최대 제약은 "kernel-silent"인데, 그건 journald
   가 디스크 flush 라 프리즈를 못 따라오기 때문이기도 하다. netconsole 은 UDP 로 즉시 나간다.
   ```bash
   # 퍼징 호스트
   sudo modprobe netconsole netconsole="@/,6666@<수신PC_IP>/<수신PC_MAC>"
   # 수신 PC
   nc -u -l 6666 | tee freeze.log
   ```
   watchdog 은 **panic 없이**(`nmi_watchdog=1`, `*_panic=0`) — lockup backtrace 가 netconsole 로
   나오면 (B)/(C)/(D) 를 추측이 아니라 스택으로 가른다.
   **⚠ `softlockup_panic`/`hardlockup_panic` 절대 금지** — 과거 이 옵션들이 퍼저의 *의도적* D-state
   를 호스트 panic 으로 승격시킨 전례(관측자 효과). 상세는 crash 조사 기록.
1. **★ halt *지속시간* 스윕 — 아직 한 번도 안 건드린 노브 (F 검증 + 잠재적 완화책)**
   지금까지 튜닝한 건 전부 `go_settle`(halt **간격**)이고 **halt 자체의 길이(~1.8ms)는 고정**이었다.
   (F) 가 맞다면 p 를 정하는 건 간격이 아니라 **halt 창 동안 컨트롤러 버퍼가 얼마나 차는가** =
   **halt 지속시간**이다. → `jlink_speed` 2000 → 8000/12000kHz 로 올리면 SWD 트랜잭션이 빨라져
   halt 창이 짧아진다(`halt_loop_stress.py` 가 `freeze_accum` 으로 실제 단축을 측정해준다).
   - MTBF 가 **크게 늘면 (F) 강력 지지 + 그 자체로 실용 완화책**(커버리지 해상도 손실 없음 —
     `go_settle` 낮추기와 달리 샘플 품질을 안 깎는다).
   - 무반응이면 지속시간 무관 → (B) 쪽으로.
2. **halt 단독 스트레스 (halt 단독 vs 호스트 I/O 상호작용 분리)** — `halt_loop_stress.py`.
   NVMe 트래픽 없이 halt 루프만. nvme 드라이버 unbind 하면 링크까지 idle.
   - 프리즈 **안 남** → halt 단독 무죄, **halt × 호스트 posted write** 필요 = (F) 지지
   - 프리즈 **남** → halt 자체가 링크를 죽임 = (B)
   - **⚠ 횟수 주의**: 기하분포라 1회분 노출(~70만 halt)에서의 음성은 증거력이 약하다(절반은 운).
     음성으로 결론내려면 **3배(~200만 halt, ≈3.8h)** — 스크립트 기본값이 200만인 이유.
3. **confound 닫기 — J-Link USB vs halt.** `--no-jlink` 는 halt 뿐 아니라 **J-Link USB 트래픽
   전체**를 뺐다. 엄밀히는 "halt 가 유일 변수"가 아니다. **P9/PM9M1 의 `sampler_type=pcsr`**
   (J-Link 연결 유지 + halt 없음) 구성에서 프리즈가 없었다면 USB 는 무죄, halt 확정.
   → 기존 run 기록으로 답할 수 있으면 실험 하나를 아낀다.
4. **`pcie_ports=compat`** — AER·DPC·PME·hotplug 전부 off → (D) 및 포트 서비스 잔여분 배제.
5. **링크 안정화 (B 완화)** — `pcie_aspm=off` + BIOS ASPM/L1 substates off. 그래도 나면 root port
   Link Control 2 로 **링크 속도 강제 하향**(Gen4→Gen3→Gen2) 후 retrain (신호무결성 마진).
   원인 규명 뒤에 써도 늦지 않는 완화책.

## 도구 (이 조사 전용, 퍼저와 독립)
- **`halt_loop_stress.py`** — NVMe 무트래픽 halt/go 루프. 퍼저의 `_read_all_pcs` 와 동일 경로/타이밍
  (P7 기본: Cortex-R5 SWD 2000kHz, go_settle 5ms, halt_poll 8ms). 출력 매 줄 flush →
  **ssh 로 원격 tee** 해야 프리즈를 넘겨 살아남는다(로컬 리다이렉트는 유실).
- **`pcie_link_probe.py`** — noaer 에서 잃은 카나리아 복구. `DevSta`(AER 무관 하드웨어 비트) /
  `LnkSta`(속도·폭 저하) / AER cor·unc status 를 setpci 로 직접 폴링. `--clear` 로 구간별 발생률,
  `--show-cto`/`--set-cto` 로 Completion Timeout 점검(→ (C) 폐기에 사용).

## 완화 옵션 (예방 못 하면)
- **노출 줄이기**(config): `go_settle_ms`↑ / `halt_poll_ms`↓ / "N명령마다 1회 샘플" 노브(코드 추가) →
  총 halt 수↓ → 링크 교란↓ → MTBF↑(예방 아님, 커버리지 해상도↓).
- **견디기(기존 방침)**: corpus 는 `output_dir/corpus/` 저장 + `--resume-coverage` + 외부 워치독
  재부팅 + systemd/cron 자동재시작 → 프리즈를 "수 분 다운"으로 흡수.

## 남은 확인 질문
- 이 프리즈가 **모든 PC 에서 나나, 특정 보드에서만 나나?** (링크 신호무결성/BIOS 의존이면 보드별 차이)
- ~~`pci=noaer` run 의 프리즈 여부 + corrected 카운트~~ → **답 나옴**(위 실험 기록: 프리즈 재현, 0개).
- ~~root port / endpoint 의 Completion Timeout Disable 이 켜져 있나?~~ → **답 나옴**: 둘 다
  value=0(50us~50ms), Disable=off → (C) 폐기.
- **halt *지속시간*(≠간격)을 줄이면 MTBF 가 늘어나나?** (`jlink_speed`↑) — (F) 의 핵심 검증이자
  유일하게 커버리지 해상도를 안 깎는 완화책 후보. **아직 한 번도 시도 안 함.**
- halt 단독(NVMe 무트래픽) **200만** 회에서 프리즈가 나나? (halt 단독 vs 호스트 I/O 상호작용)
- **`sampler_type=pcsr`**(J-Link 연결 유지 + halt 없음) 구성에서 프리즈 전례가 있었나?
  없었다면 J-Link USB confound 가 닫히고 halt 가 트리거로 확정된다.
