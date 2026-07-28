# HANDOFF — OS Freeze 조사 (J-Link halt 관련), 2026-07 진행 중

퍼징 중 **호스트 OS 하드 프리즈** 조사.

> ## ✅ 2026-07-28 결론 — 커널이 원인으로 확정
> | | 6.8.12 (mainline) | 5.15.0-139 |
> |---|---|---|
> | 결과 | **80만 명령 무프리즈** | **11,800 명령에 프리즈** |
> | `AERcor` / corrected | 0 | **0** (끝까지 에러 비트 없음) |
>
> 같은 날·같은 장비·같은 명령, **커널만** 교체. **68배 차이**이고 11,800 은 과거 최소치
> (9만)보다도 8배 빠르다. → **커널 확정.**
>
> **실용 결론: 6.8 로 퍼징한다.** 단기=mainline 6.8.12 그대로, 장기=20.04→22.04 업그레이드 후
> **서명된 HWE 6.8**(지원·Secure Boot 가능). 근본 원인(어느 커널 변경인지)은 선택 사항 — 아래
> "남은 것" 참조.
>
> ### ⚠ 선행지표 가설 철회
> corrected 에러 카운트를 프리즈의 **선행지표**로 쓰자고 했으나 **틀렸다.** 5.15 에서 `AERcor`
> 가 **끝까지 0 인 채로 얼었다.** 이전 부팅의 106개는 전조가 아니라 동반 현상이었다
> (`pci=noaer` 실험에서 이미 나왔던 결론을 6.8 의 "0" 을 보고 잘못 되살린 것).
>
> ### 그 실패가 오히려 범위를 좁힌다
> **에러 비트 하나 없이 얼었다.**
> - **(B) 링크 불안정 → 사실상 사망.** 링크가 죽어서 얼었다면 `RxErr`/`BadTLP` 중 뭐라도 서야
>   한다. Gen1 x1(신호 마진 최대)에서 신호 문제라는 것도 애초에 무리였다.
> - **(F) 크레딧 고갈 → 정확히 부합.** 크레딧 고갈은 **에러가 아니다** — CRC 실패도 수신 오류도
>   아니고 "보낼 크레딧이 없어 멈춤"이라 **에러 비트를 남길 이유가 구조적으로 없다.** 완전 무음
>   프리즈와도 맞는다.
> - 여기에 **정적 설정이 두 커널에서 동일**하다는 사실을 더하면: 설정은 같고 · 에러도 없고 ·
>   한쪽만 멈춘다 → **드라이버의 동적 거동 차이**. (F) 외에 남는 게 별로 없다.
>
> *(단서: 프로브는 5초 주기라 마지막 5초에만 몰린 에러는 놓친다. 전 구간 0 이었으므로 실제로
> 없었을 가능성이 높다.)*

> ## ★ 2026-07-27 전환 — 이건 머신 특정 문제다
> **다른 PC 에서 동일 구성으로 1000만 명령 무프리즈**(= 프리즈 임계치 30~48만의 **20배 이상**).
> 그 PC 는 **커널 버전이 더 높다.**
>
> → "halt 가 PCIe 를 멈춘다"는 게 일반 법칙이 아니라 **이 머신에서만 성립하는 조건**이다.
> → **조사 방향 전환: 메커니즘 규명(느림) → 두 머신의 차이 이분탐색(빠름).**
> → 이하의 (F)/(B)/(D) 가설과 실험 순서는 **이 사실을 모르고 세운 것**이라 우선순위가 낮아졌다.
> 특히 **(F) 는 커널 업그레이드로 고쳐지면 폐기**된다 — 크레딧 데드락은 하드웨어 패브릭 상태라
> 커널 버전으로 안 고쳐지기 때문. 즉 아래 1번이 수리이자 (F) 검증을 겸한다.

경과: firmware-first/SMM → (A) AER 인터럽트 storm → (C) non-posted read 무한 정지를 차례로 폐기.
머신 특정 사실이 밝혀지기 전 1순위였던 것은 (F) flow-control credit 고갈.

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

## 실험 기록 — 커널 6.8 (mainline v6.8.12) 진행 중 (2026-07-27)

| 항목 | 5.15.0-139 | 6.8.12 |
|---|---|---|
| 프리즈 | 9만~48만 명령 | **50만+ 무프리즈** (150만 목표로 진행 중) |
| `grep -c "Corrected error"` | **106** | **0** |
| root port `RootCmd` | — | **`CERptEn+`** (= corrected 보고 **활성**) |
| root port `CESta` | — | **전부 `-`** (하드웨어도 에러 미검출) |

→ **"0" 은 로깅 차이가 아니라 실재.** `CERptEn+` 로 보고가 켜져 있음을 확인했고 하드웨어
상태 비트도 깨끗하다. **링크가 실제로 다르게 동작한다.**

### ★ 부산물 — 선행지표 확보
corrected 에러 카운트가 **두 커널을 몇 분 만에 가른다.** 프리즈(수 시간, 기하분포)를 기다릴
필요 없이 링크 거동을 측정할 수 있다 → 앞서 "희귀 사건 대신 선행지표로 최적화하라"고 한
요구가 공짜로 충족됨. 6단계(5.15 복귀)에서 `pcie_link_probe.py --clear` 를 나란히 돌려
**어떤 corrected 비트**가 서는지 볼 것:
- **`RxErr`** → 수신기/물리 계층
- **`BadTLP`/`BadDLLP`** → CRC 실패 = **프로토콜 계층** → (F) 계열 확정

## 추가로 배제된 것 (2026-07-27)

| 후보 | 근거 |
|---|---|
| **ASPM / L1 substates** | **폐기** — 이 제품은 **link power management 자체를 미지원**(NVMe power state 만 지원). L0s/L1/L1SS 가 성립 불가 |
| **커널 간 링크 속도 차이** | **폐기** — `LnkCap`=`LnkSta`=**2.5GT/s x1**. `LnkCap` 은 읽기전용 하드웨어 레지스터라 커널이 못 바꾸고, 2.5GT/s x1 은 **PCIe 최저값**이라 내려갈 곳도 없다 |
| **완화책 "링크 속도 강제 하향"** | **불가** — 이미 최저 속도. 이 옵션은 목록에서 삭제 |
| **커널 간 PCIe *정적 설정* 차이 전반** | **폐기** — 5.15 vs 6.8 의 `lspci -vvv`(root port + endpoint) 덤프가 **동일**. `MaxPayload`/`MaxReadReq`/`DevCtl2`/`RootCmd`/`LnkCtl`/AER 설정 전부 같음 |
| **호스트 브리지 `_OSC` 협상 차이** | **폐기** — `supports`/`now controls` 줄 동일. diff 에 잡힌 두 줄은 **CPU/thermal `_OSC`**(`evaluated successfully for all CPUs` vs `\_SB_.PR00: _OSC native thermal LVT Acked`)로 커널별 로그 문구 차이일 뿐 PCIe 와 무관 |

> **★ 이 두 건이 갈래 하나를 통째로 닫는다.** 두 커널은 링크를 **똑같이 설정**하는데 결과가
> 다르다. → 원인은 정적 레지스터 값이 아니라 **드라이버의 동적 거동**(halt 로 멈춘 컨트롤러에
> 언제·얼마나 요청을 밀어넣는지, 타임아웃/리셋을 어떻게 처리하는지)이다. 5.15↔6.8 사이 nvme
> 드라이버 변경 폭이 크다. **이는 (F) 와 정확히 부합** — 크레딧 고갈은 정적 설정이 아니라
> "halt 중 호스트가 얼마나 밀어붙이나"의 문제이기 때문.
> (한계: 위 덤프는 **유휴 스냅샷**이다. 퍼징 중 동적으로 바뀌는 값이 있는지는 에러 누적 후
> 재캡처해 diff 하면 확인 가능.)

> **주목:** Gen1 x1 은 PCIe 에서 **신호 마진이 가장 큰** 구성이다(긴 트레이스·커넥터용 속도).
> 거기서 corrected DLL 에러가 106개 났다는 건 원인이 **물리적 신호무결성이 아니라 프로토콜/
> 버퍼 쪽**일 가능성을 시사한다 → **(B) 보다 (F) 에 무게.**

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

**(B) 링크 불안정 자체가 치명 — ~~유효~~ → 사실상 사망(2026-07-28)**
5.15 재현 run 에서 `AERcor` 가 **끝까지 0 인 채로 11,800 명령에 프리즈**. 링크가 죽어서 얼었다면
`RxErr`/`BadTLP` 중 뭐라도 서야 한다. 상단 결론 블록 참조.

**(D) DPC 발동 — 유효**
`_OSC` 상 **DPC 는 여전히 OS 소유**(noaer 는 AER 서비스만 끔). uncorrectable 시 link containment →
이후 MMIO 가 안 돌아오면 (C) 와 같은 정지로 수렴. `pcie_ports=compat` 로 포트 서비스 전면 차단해
배제한다.

## 다음 단계 (중지 지점) — 머신 차분 우선

> 아래 A/B/C 가 현재 우선순위. 그 뒤의 0~5 는 머신 특정 사실을 모르고 세운 순서라
> **A~C 가 끝난 뒤에도 원인이 안 잡힐 때만** 의미가 있다.

**A. 문제 PC 에 6.x 커널 설치 → 퍼저 150만 명령 → 5.15 로 되돌려 재확인 (1순위)**

실측 환경(2026-07-27):
| | 배포판 | 커널 |
|---|---|---|
| **문제 PC** | Ubuntu **20.04.6** (focal) | **5.15.0-139-generic** |
| 정상 PC | Ubuntu 22.04 (jammy) | 6.x (= jammy HWE **6.8**) |

> **★ 함정: 20.04 는 5.15 가 천장이다.** focal 의 HWE 커널이 바로 5.15 라 `apt` 로 6.x 를
> 받을 방법이 없다. "정상 PC 커널을 apt 로 깔면 된다"는 이 조합에서 **성립하지 않는다.**
> (참고: 22.04 의 **GA 커널도 5.15** 다. 정상 PC 가 6.x 인 건 거기서 HWE 를 쓰기 때문.)

- **권장: mainline 커널 .deb 만 설치** — userspace 를 그대로 두고 **커널만** 바꾼다.
  배포판 업그레이드(20.04→22.04)는 venv/pylink/nvme-cli/J-Link 가 얹힌 리그의 userspace 를
  통째로 바꿔 **변수가 다시 뒤섞이므로**, "커널이 원인"이라는 결론을 낼 수 없다.
  ```bash
  mokutil --sb-state    # mainline 은 unsigned — Secure Boot 켜져 있으면 부팅 안 됨
  # https://kernel.ubuntu.com/~kernel-ppa/mainline/v6.8.12/amd64/ 에서 4개:
  #   linux-headers-*_all.deb / linux-headers-*-generic_*_amd64.deb
  #   linux-image-unsigned-*-generic_*_amd64.deb / linux-modules-*-generic_*_amd64.deb
  cd /tmp && sudo dpkg -i linux-*.deb && sudo update-grub    # 5.15 는 GRUB 에 그대로 남는다
  ```
  out-of-tree DKMS 의존 없음(pylink=libusb 유저스페이스, nvme=in-tree)이라 모듈 리스크 낮음.
- **150만 = 관측 최대(48만)의 3배.** 기하분포라 '살아남았다' 주장에는 3배 노출이 필요.
- **반드시 5.15 로 되돌려 재현시킬 것.** 6.8 통과만으로는 부족하다 — 같은 날 같은 장비에서
  5.15 가 다시 얼어야 커널이 원인으로 확정된다. (`kernel_sweep.py --plan 6.8...,5.15...`)
- **동시에 `pci=noaer` 제거** — 원인 아님이 확인됐고 켜두면 링크 카나리아만 가린다.
- 고쳐지면 → 원인은 커널 쪽(포트 서비스/nvme 타임아웃 경로 등)이거나 칩셋 차이. **(F) 폐기.**

**B. 커널이 안 고치면 — 차분 덤프 (양쪽 5분씩)**
다른 PC 는 커널만 다른 게 아니라 **보드·칩셋·BIOS·슬롯이 전부 다르다.** 커널이 제일 싸게
바꿀 수 있는 변수라 먼저 칠 뿐, 음성이면 나머지를 본다.
```bash
uname -r; cat /proc/cmdline
sudo dmidecode -s baseboard-product-name; sudo dmidecode -s bios-version
sudo lspci -vvv -s <root port BDF> | grep -E "LnkCap|LnkSta|DevCtl2|ASPM|DPC"
sudo lspci -vvv -s <SSD BDF>       | grep -E "LnkCap|LnkSta|DevCtl2|ASPM"
journalctl -k -b | grep -iE "_OSC|aer|dpc"
```
**특히 `LnkSta` 의 속도/폭이 두 머신에서 같은가.** 문제 PC 만 낮은 폭으로 링크업했거나
라이저/슬롯이 다르면 그게 곧 답이다.

**C. 링크 프로브 양쪽 비교 (공짜 감별 — (B) 계열을 한 번에 살리거나 죽인다)**
```bash
sudo python3 pcie_link_probe.py --root <root> --ep <ssd> --interval 5 --clear
```
- **정상 PC 도 링크 에러가 나는데 안 죽는다** → 에러는 무죄, **처리 방식**(커널/칩셋)의 문제
- **정상 PC 는 0, 문제 PC 만 난다** → 문제 PC 의 링크가 실제로 나쁨(신호무결성/슬롯/라이저)

**실용 선택지:** 정상 PC 를 퍼징에 쓸 수 있으면 **리그를 옮기는 것도 정답**이다. 이 머신을
꼭 써야 하는 게 아니면 원인 규명은 선택사항.

---

### (이하는 머신 특정 사실 이전에 세운 순서 — A~C 이후에만 의미)

0. **가시성 확보 — netconsole.** 이 조사의 최대 제약은 "kernel-silent"인데, 그건 journald
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
1. **halt *지속시간* 스윕 (F 검증 + 잠재적 완화책). ⚠ 비용 주의 — 아래 분산 문제.**
   **MTBF 비교는 단일 run 으로 불가능하다.** 재현 횟수가 9만~48만(5배)로 흩어지는 기하분포라
   `speed=12000` 한 번이 `speed=2000` 한 번보다 오래 버텨도 **아무것도 증명 못 한다**(노이즈 안).
   3배 개선을 노이즈와 구분하려면 **arm 당 4~5회 재현** → arm 당 5~10시간, arm 2~3개면 20~30시간.
   → **대안: 희귀 사건(프리즈) 대신 선행지표로 최적화.** 퍼저 + `pcie_link_probe --clear` 로
   halt 가 만드는 링크 이벤트가 **측정되는지** 먼저 보고(분 단위), 측정되면 그 지표로 speed 를
   비교한 뒤 마지막에만 프리즈로 확증한다. 20~30시간 → ~1시간.
   링크 이벤트가 0 으로 안 잡히면 → 링크 계층에 안 보인다는 뜻이고 netconsole 백트레이스 외 길 없음.
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
3. **confound 닫기 — J-Link USB vs halt. ⚠ 수율 낮음, 기본적으로 건너뛸 것.**
   `--no-jlink` 는 halt 뿐 아니라 **J-Link USB 트래픽 전체**를 뺐으므로 엄밀히는 "halt 가 유일
   변수"가 아니다. 다만 **닫는 비용이 ~7.8시간인데 산출은 예상된 음성 1비트**다(J-Link USB 가
   호스트를 무음 하드프리즈시킬 사전확률은 낮다). **퍼저가 30~48만 명령에 재현하므로 다른
   실험은 전부 퍼저로 하는 게 빠르다.** 스크립트가 퍼저보다 나은 건 **기본 halt 모드 +
   nvme unbind**(= 퍼저가 구조적으로 못 만드는 "NVMe 트래픽 없는 halt") 하나뿐.
   → **`halt_loop_stress.py --no-halt`** (SWD/USB 트래픽 동일 + 코어 정지 없음).
   - 프리즈 **남** → 원인은 halt 가 아니라 J-Link/SWD/USB 경로
   - 프리즈 **안 남** → confound 닫힘, **halt 가 트리거로 확정**
   **주의(제품별 sampler 사실관계):** `pcsr` = **PM9M1·BM9H1**, `jlink_halt` = **P7·P9**.
   즉 "다른 제품으로 halt 를 빼는" 우회는 **제품·컨트롤러·펌웨어가 같이 바뀌어** 깨끗한 대조가
   안 되고, P7/P9 는 둘 다 halt 라 제품 교체로 halt 를 뺄 수도 없다(R5 가 PCSR 미구현이라
   halt 를 쓰는 것으로 보임). 그래서 **같은 장치에서 halt 만 빼는 `--no-halt` 대조군**이 필요하다.
4. **`pcie_ports=compat`** — AER·DPC·PME·hotplug 전부 off → (D) 및 포트 서비스 잔여분 배제.
5. ~~**링크 안정화 (B 완화)** — `pcie_aspm=off` + 링크 속도 강제 하향~~ → **둘 다 불가(2026-07-27)**:
   제품이 link power management 미지원이라 ASPM 이 없고, 링크는 이미 **2.5GT/s x1**(PCIe 최저)
   이라 낮출 여지가 없다. 위 "추가로 배제된 것" 참조.

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

## 남은 것 (선택 — 실용 목표는 이미 달성)

**근본 원인 = 5.15↔6.8 사이 어느 커널 변경인가.** 원래 bisect 는 비현실적이었으나
**11,800 명령 재현이면 커널당 몇 분**이라 실용 범위에 들어온다. `kernel_sweep.py` 가 반복을
자동화한다(mainline .deb 을 여러 버전 깔고 `--plan v1,v2,...`).

> **⚠ 선행 확인:** **11,800 이 반복 재현되는지 1회는 봐야 한다.** 한 샘플이라 운일 수 있고,
> 실제 평균이 27만이면 각 커널의 "통과" 판정에 몇 시간씩 들어 bisect 가 다시 비싸진다.
> 5.15 에서 한 번만 더 돌려보면 안다.

목표가 SSD 펌웨어 퍼징이지 커널 고고학이 아니므로, **필요해지기 전까지는 하지 않아도 된다**
(업스트림 리포트가 필요하거나 5.15 를 반드시 써야 하는 사정이 생길 때).

## 남은 확인 질문
- ~~이 프리즈가 모든 PC 에서 나나, 특정 보드에서만 나나?~~ → **답 나옴(2026-07-27, 결정적)**:
  **다른 PC 에서 1000만 명령 무프리즈, 커널 버전 상위.** 머신 특정 문제 확정. 상단 참조.
- **정상 PC 의 커널로 바꾸면 문제 PC 도 살아나나?** (= 커널 vs 하드웨어 갈림길, 1순위 실험)
- 두 머신의 `LnkSta`(링크 속도/폭)·보드·BIOS·슬롯이 어떻게 다른가?
- ~~`pci=noaer` run 의 프리즈 여부 + corrected 카운트~~ → **답 나옴**(위 실험 기록: 프리즈 재현, 0개).
- ~~root port / endpoint 의 Completion Timeout Disable 이 켜져 있나?~~ → **답 나옴**: 둘 다
  value=0(50us~50ms), Disable=off → (C) 폐기.
- **halt *지속시간*(≠간격)을 줄이면 MTBF 가 늘어나나?** (`jlink_speed`↑) — (F) 의 핵심 검증이자
  유일하게 커버리지 해상도를 안 깎는 완화책 후보. **아직 한 번도 시도 안 함.**
- halt 단독(NVMe 무트래픽) **200만** 회에서 프리즈가 나나? (halt 단독 vs 호스트 I/O 상호작용)
- `--no-halt` 대조군에서 프리즈가 나나? (J-Link USB confound 닫기)
- **P9 도 프리즈하나?** P7·P9 **둘 다 `jlink_halt`** 다. 둘 다 프리즈하면 halt 가 컨트롤러
  PCIe 를 멈추는 **제품 무관·일반 메커니즘** = (F) 강화. P7 만이면 제품/펌웨어 특정 문제.
  (`pcsr` 인 PM9M1·BM9H1 은 halt 를 안 하므로 애초에 비교군이 못 된다 — 제품이 같이 바뀜.)
