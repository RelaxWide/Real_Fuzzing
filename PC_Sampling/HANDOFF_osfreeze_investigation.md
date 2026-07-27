# HANDOFF — OS Freeze 조사 (J-Link halt 관련), 2026-07 진행 중

퍼징 중 **호스트 OS 하드 프리즈** 조사. 실측으로 원인을 **root port PCIe 링크 불안정 + OS-native
AER** 까지 좁힘. (firmware-first/SMM 가설은 폐기 — 아래 참조.)

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
- **★ 핵심 단서:** 프리즈한 부팅의 `journalctl -k -b -1` **마지막 줄**:
  ```
  pcieport 0000:00:01.1: AER: Corrected error message received from 0000:00:01.1
  pcieport 0000:00:01.1: PCIe Bus Error: severity=Corrected, type=Data Link Layer, (Receiver ID)
  ```
  - `0000:00:01.1` = **P7 의 최상단 root port**(POR remove 대상과 동일).
  - `severity=Corrected, Data Link Layer, Receiver ID` = **PCIe 링크 물리/데이터링크 계층 에러**
    (재전송으로 정정됨). **그 부팅에서 corrected 에러 106개**(`journalctl -k -b -1 | grep -c
    "Corrected error"` = 106). 건강한 링크는 **0** — 실제 링크 불안정.

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

## 현재 유력 가설 — OS-native AER + root port 링크 불안정
R5 halt(8ms) → SSD PCIe 링크가 ACK/NAK·flow-control 을 못 함 → **root port(00:01.1)가 corrected
DLL 에러를 냄** → 각 에러가 **AER 인터럽트** 유발 → 커널 AER 핸들러 폭주. 두 갈래:
- **(A) AER 인터럽트 storm → livelock**: 프리즈 직전 corrected 에러가 몰리면 전 코어가 AER IRQ 에
  갇혀 livelock. console/log flush 못 함 → kernel-silent. (마지막 corrected 줄이 빠져나온 최후.)
- **(B) 링크 악화 → uncorrectable/link-down 으로 escalation**: corrected 가 누적되다 치명 에러로
  번져 프리즈, 로그 못 남김.
- `pci=noaer` 실험이 (A) vs (B) 를 가른다(아래).

## 다음 단계 (중지 지점) — 결정적 실험
1. **`pci=noaer`** 커널 cmdline 추가(`/etc/default/grub` → `GRUB_CMDLINE_LINUX_DEFAULT` 에
   ` pci=noaer` → `sudo update-grub` → 재부팅, `cat /proc/cmdline` 확인) 후 **J-Link run**:
   - 프리즈 **멈춤** → **(A) AER 인터럽트 처리(storm/livelock)가 원인 확정.** 이후 전체 AER 대신
     **corrected 만 마스킹**(root port AER Correctable Error Mask, setpci)으로 정밀화.
   - 프리즈 **계속** → (B) 링크 불안정 자체가 치명 → 아래 2로.
2. **`pcie_aspm=off`** 추가 → ASPM 전력전환이 halt 중 링크 에러 유발하는 경우 제거(링크 안정화).
   추가로 **PCIe 링크 속도 강제 하향**(Gen 낮춤)도 신호무결성 마진 확보 후보.
3. 재현 시 **corrected 에러 카운트 추이** 관찰: `journalctl -k | grep -c "Corrected error"` 가
   프리즈 직전 급증하면 (A) storm 확정.

## 완화 옵션 (예방 못 하면)
- **노출 줄이기**(config): `go_settle_ms`↑ / `halt_poll_ms`↓ / "N명령마다 1회 샘플" 노브(코드 추가) →
  총 halt 수↓ → 링크 교란↓ → MTBF↑(예방 아님, 커버리지 해상도↓).
- **견디기(기존 방침)**: corpus 는 `output_dir/corpus/` 저장 + `--resume-coverage` + 외부 워치독
  재부팅 + systemd/cron 자동재시작 → 프리즈를 "수 분 다운"으로 흡수.

## 남은 확인 질문
- 이 프리즈가 **모든 PC 에서 나나, 특정 보드에서만 나나?** (링크 신호무결성/BIOS 의존이면 보드별 차이)
- `pci=noaer` run 의 프리즈 여부 + `grep -c "Corrected error"` 숫자.
