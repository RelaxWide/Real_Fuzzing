# HANDOFF — OS Freeze 조사 (halt 샘플러 관련), 2026-07 진행 중 중지

퍼징 중 **호스트 OS 하드 프리즈** 조사 기록. 재개용. (config 주석이 가리키던
`SESSION_HANDOFF_v9.0.md §4` 의 후속 — 이번엔 실측 데이터로 원인을 상당히 좁혔다.)

## 증상
- J-Link halt 샘플러(P9/P7, Cortex-R5) 사용 시 퍼징 도중 **호스트 전체 프리즈**.
- 명령 **~30만~48만** 수행 후 발생(단, 이 숫자는 **노이즈** — 과거 25만/37만/44만/18만/9만 등
  제각각, 상관 없음).
- **즉각·전체·kernel-silent**: 다른 PC에서 실시간 `dmesg`/`journalctl -kf` 로 지켜봐도 프리즈
  직전까지 **아무것도 안 찍힘**. taint 없음. 재부팅 후 이전-부팅 커널로그도 무.

## 배제된 것 (증거와 함께)
| 후보 | 배제 근거 |
|---|---|
| halt 샘플러 고착/실패 | halt 실패율 **0/665758 (0.0%)** — 완벽 동작 |
| vmalloc 고갈 / 메모리 누수 | **VMon 값 안 떨어짐** (10000-exec 주기 /proc/meminfo, 안정) |
| kernel taint / 손상 | **taint 로그 없음** (B/D/L/M 등 미발생) |
| page-alloc / memory corruption | 시그니처 불일치(logless·no-taint·VMon안정) + 아래 debug옵션도 없음 |
| 진단용 커널 debug 옵션(관측자 효과) | `cat /proc/cmdline` 및 dmesg 에 `debug_pagealloc/page_poison/kasan/slub_debug` **없음** |
| PM perturbation(PCIe D3/L1.2/CLKREQ#) | **`--pm` 미사용** (pm_inject_prob 기본 0.0) |
| AER / DPC / link-down / IOMMU fault | **원격 실시간 dmesg 완전 무** — 커널 에러 핸들링이 아예 안 뜸 |
| nvme: nsid mismatch | 정상 fuzzing 노이즈, 무관 |

## 확정된 것
- **J-Link halt 침습이 트리거.** `--no-jlink`(null 샘플러)로 **100만 명령까지 무프리즈**,
  halt 켜면 30~48만에서 프리즈. → 침습 halt 유무가 유일 변수.
- **샘플러 코드 버그 아님.** `_read_all_pcs`(halt→read PC reg→go)는 전부 **SWD/J-Link(USB)** 로만
  동작 — 호스트 PCIe 를 안 건드림. 즉 원인은 **R5(=SSD 컨트롤러 CPU)를 물리적으로 멈춘 물리적
  부작용**이지 소프트웨어 경로가 아님.

## 유력 가설 (kernel-silent 를 설명하는 것)
**Firmware-first PCIe 에러 핸들링(SMM/SMI).**
1. R5 를 halt → 컨트롤러가 **bus-master DMA/PCIe 트랜잭션 중간에 얼어붙음** → dangling/malformed
   TLP(호스트가 read 안 해도 컨트롤러가 마스터 중이던 게 끊김).
2. 다수 플랫폼은 이 PCIe 에러를 **OS 가 아니라 펌웨어(SMM)** 로 먼저 라우팅(firmware-first/WHEA).
3. SMI 는 **모든 코어를 동시에 SMM 으로** 끌어들임 → BIOS SMM 핸들러가 wedge 된 디바이스 처리
   중 hang → **전 코어 SMM 에 갇힘** → 즉각 전체 프리즈, **dmesg 불가**(SMM 은 OS 에 안 보이고
   soft-lockup 감지기까지 얼어붙음).
- 이 가설이 관측(즉각·전체·무음·taint없음·lockup로그없음)과 유일하게 정합.
- 대안(단일 CPU 가 non-posted read 에 stall)은 **eventually soft-lockup 로그**를 남겨야 하는데
  없으므로 약함 → all-core SMM 정지가 더 맞음.

## 재개 시 다음 단계 (중지 지점)
아래는 전부 **OS 아래(펌웨어/BIOS/PCIe-config)** 프로브 — dmesg 는 이미 소진.
1. **`pcie_ports=native`** 커널 cmdline 추가 후 J-Link run:
   - 무음 프리즈가 **AER 로그로 바뀌거나 멈추면** → firmware-first/SMM 확정.
2. **`turbostat --interval 5`** 로 J-Link run 중 **SMI 카운트** 관찰(no-jlink 와 비교). SMI 상승 =
   firmware-first 동작 증거.
3. **핵심 질문: 모든 PC 에서 나나, 특정 PC(메인보드)에서만 나나?**
   - 특정 PC 만 → firmware-first/SMM(BIOS 별 차이) 거의 확정 → 보드 교체 또는 BIOS 를 OS-native 로.
   - 모든 PC → 컨트롤러-halt 의 PCIe 위반 자체가 근본 → 예방 어려움 → 완화/견디기.
4. **BIOS**: PCIe error handling(firmware-first vs OS-first), Completion Timeout, ASPM 확인.
5. **`lspci -vvv -s <root_port>`**: AER/DPC 소유자(OS vs firmware), CTO 값.

## 완화 옵션 (예방 못 하면)
- **노출 줄이기**(코드 config): `go_settle_ms`↑(halt 빈도↓), `halt_poll_ms`↓(halt 지속↓). 필요 시
  "N명령마다 1회 샘플" 노브 코드 추가(작은 변경) → 총 halt 수↓ → MTBF↑(예방 아님, 커버리지 해상도↓).
- **link-down 가정 시**: `nvme_kernel_timeout_sec`(현재 30일) 축소 → 커널이 타임아웃→컨트롤러
  리셋으로 복구(트레이드오프: 느린 정상 명령 오살).
- **견디기(코드 기존 방침)**: corpus 는 `output_dir/corpus/` 저장, `--resume-coverage` 로 커버리지
  이어받기. + 외부 워치독 재부팅 + systemd/cron 자동재시작 → 프리즈를 "수 분 다운"으로 흡수.

## 참고 — 이번 조사와 무관하지만 확인된 것
- POR PCIe remove 대상은 v9.4/v9.5 에서 **`auto-root`(topology 최상단 root port 동적 탐지)** 로
  전환됨(하드코딩 `0000:00:01.1` 제거, 커밋 e20022c). 스위치 경유 토폴로지도 최상단 반환 검증.
  (`_pcie_topmost_bdf`, EP realpath 의 첫 BDF.)
