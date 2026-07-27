# RUNBOOK — 커널 6.8 테스트 (OS freeze 가 커널 문제인지 확정)

문제 PC: Ubuntu 20.04.6 focal / **5.15.0-139-generic** — 프리즈 30만~48만 명령
정상 PC: Ubuntu 22.04 jammy / **6.8** (jammy HWE) — 1000만 명령 무프리즈

**목표:** 같은 머신에서 **커널만** 6.8 로 바꿔 프리즈가 사라지는지, 그리고 5.15 로 되돌리면
다시 나는지 확인. 배경·가설은 `HANDOFF_osfreeze_investigation.md`.

> **왜 배포판 업그레이드(20.04→22.04)가 아니라 mainline 커널인가:**
> 업그레이드는 venv/pylink/nvme-cli/J-Link 가 얹힌 리그의 userspace 를 통째로 바꾼다.
> 그러면 변수가 다시 뒤섞여 **"커널이 원인"이라는 결론을 낼 수 없다.** mainline .deb 는
> 커널만 바꾸므로 단일 변수 실험이 되고, 되돌리기도 GRUB 에서 5.15 선택이면 끝이다.

---

## 0단계 — 사전 확인 (문제 PC, 5분)

```bash
# ① Secure Boot — mainline 커널은 서명이 없어서 켜져 있으면 부팅 자체가 안 된다
sudo apt install -y mokutil 2>/dev/null; mokutil --sb-state

# ② /boot 여유 공간 — 20.04 는 /boot 가 512MB 인 경우가 많고 커널 하나가 ~100MB 다
df -h /boot

# ③ 현재 상태 기록 (되돌릴 때 대조용)
uname -r; cat /proc/cmdline; nvme list
```

**판정:**
- `SecureBoot enabled` → **BIOS 에서 Secure Boot 를 꺼야 한다.** 못 끄면 여기서 멈추고 알릴 것
  (서명된 커널을 쓰는 다른 경로를 짜야 함).
- `SecureBoot disabled` 또는 `This system doesn't support Secure Boot` → 진행.
- `/boot` 여유가 **300MB 미만**이면 먼저 정리:
  ```bash
  sudo apt autoremove --purge     # 오래된 커널 제거
  df -h /boot                     # 다시 확인
  ```

---

## 1단계 — GRUB 설정 (부팅 시 커널 선택 + noaer 제거)

```bash
sudo cp /etc/default/grub /etc/default/grub.bak     # 백업
sudo nano /etc/default/grub
```

**세 곳을 고친다:**

| 항목 | 이렇게 | 왜 |
|---|---|---|
| `GRUB_CMDLINE_LINUX_DEFAULT` | ` pci=noaer` **삭제** | 원인 아님이 확인됐고, 켜두면 링크 에러 관측만 가린다 |
| `GRUB_TIMEOUT_STYLE` | `menu` | 20.04 는 기본이 `hidden` 이라 **메뉴가 안 뜬다** → 커널 선택 불가 |
| `GRUB_TIMEOUT` | `10` | 선택할 시간 |
| `GRUB_DEFAULT` | `saved` | `grub-reboot`(1회성 다음 부팅 지정) 과 `kernel_sweep.py` 가 이걸 요구 |

`GRUB_DEFAULT=saved` 로 했으면 아래도 추가(없으면):
```
GRUB_SAVEDEFAULT=false
```

```bash
sudo update-grub
grep -E "^GRUB_(DEFAULT|TIMEOUT|CMDLINE)" /etc/default/grub    # 확인
```

---

## 2단계 — mainline 6.8 커널 내려받기

```bash
V=v6.8.12
BASE=https://kernel.ubuntu.com/~kernel-ppa/mainline/${V}/amd64
mkdir -p ~/mainline && cd ~/mainline

for f in $(curl -s ${BASE}/ | grep -oE 'linux-[a-z0-9._+-]+\.deb' | sort -u | grep -v lowlatency); do
    wget -c "${BASE}/${f}"
done

ls -1 *.deb
```

**받아져야 할 4개** (이름의 날짜 suffix 는 다를 수 있음):
```
linux-headers-6.8.12-060812_...._all.deb
linux-headers-6.8.12-060812-generic_...._amd64.deb
linux-image-unsigned-6.8.12-060812-generic_...._amd64.deb
linux-modules-6.8.12-060812-generic_...._amd64.deb
```

4개가 아니면 브라우저로 `${BASE}/` 를 직접 열어 위 4종을 받을 것 (`lowlatency` 는 제외).

---

## 3단계 — 설치

```bash
sudo dpkg -i ~/mainline/linux-*.deb
sudo apt -f install          # 의존성 오류가 났을 때만 필요
sudo update-grub
```

**확인 — 5.15 가 지워지지 않고 남아 있어야 한다:**
```bash
ls /boot/vmlinuz-*
# vmlinuz-5.15.0-139-generic  ← 이게 반드시 있어야 되돌릴 수 있다
# vmlinuz-6.8.12-060812-generic
```

---

## 4단계 — 6.8 로 부팅 + 환경 정상성 확인 ★ 빼먹지 말 것

```bash
sudo reboot
```
GRUB 메뉴에서 **Advanced options → 6.8.12** 선택.

부팅 후:
```bash
uname -r                       # 6.8.12-060812-generic 이어야 함
cat /proc/cmdline              # pci=noaer 가 없어야 함
nvme list                      # SSD 가 보여야 함
lspci | grep -i non-volatile   # SSD 가 보여야 함
lsusb | grep -i segger         # J-Link 가 보여야 함
```

**이 중 하나라도 안 되면 테스트는 무효다.** 6.8 에서 장치가 안 잡히는데 "프리즈 안 났다"는
아무 의미가 없다. 안 되면 멈추고 알릴 것.

퍼저가 J-Link 를 잡는지 짧게 확인:
```bash
cd /home/ssd/gdbfuzz
sudo .venv/bin/python3 PC_Sampling/jlink_reg_diag.py --device Cortex-R5 --interface swd --speed 2000
```

---

## 5단계 — 6.8 에서 퍼저 150만 명령

```bash
cd /home/ssd/gdbfuzz
sudo .venv/bin/python3 PC_Sampling/pc_sampling_fuzzer_v9.5.py --product P7 --resume-coverage 2>&1 | tee ~/run_6.8.log
```

- **150만** = 관측 최대(48만)의 3배. 기하분포라 "살아남았다"고 말하려면 3배 노출이 필요하다.
- 진행은 로그의 `exec=` 로 본다. 기존 재현이 30만~48만이므로 **50만을 넘기는 순간부터 유의미**하고,
  150만이면 확정적이다.
- 얼면 → **그 자체가 결과다**(6단계 건너뛰고 7단계 분기 B 로).

**자동 기록을 원하면** 손으로 세는 대신:
```bash
sudo python3 PC_Sampling/kernel_sweep.py --list      # GRUB_DEFAULT=saved 확인
sudo python3 PC_Sampling/kernel_sweep.py --plan 6.8.12-060812-generic,5.15.0-139-generic
sudo python3 PC_Sampling/kernel_sweep.py --run       # 부팅할 때마다
```
프리즈해도 "몇 명령에서 죽었는지"가 자동으로 남는다(30초마다 fsync).

---

## 6단계 — 5.15 로 되돌려 재현 확인 ★ 이게 있어야 확정된다

5.15 로 부팅해서 같은 퍼저를 돌린다.

```bash
sudo reboot     # GRUB 에서 5.15.0-139-generic 선택
uname -r        # 5.15.0-139-generic 확인
cd /home/ssd/gdbfuzz
sudo .venv/bin/python3 PC_Sampling/pc_sampling_fuzzer_v9.5.py --product P7 --resume-coverage 2>&1 | tee ~/run_5.15.log
```

**48만 이전에 얼면 → 커널이 원인으로 확정.**

왜 필요한가: "6.8 에서 통과"만으로는 그 사이 **다른 것**(케이블 재접속, 온도, 장치 상태)이
바뀌었을 가능성을 못 배제한다. 같은 날 같은 장비에서 5.15 가 다시 얼어야 커널이 유일한
차이임이 증명된다.

---

## 7단계 — 결과별 분기

| 6.8 | 5.15 (되돌림) | 결론 / 다음 |
|---|---|---|
| **PASS** 150만 | **FREEZE** <48만 | **커널 원인 확정.** 6.8 로 퍼징 계속. (F) 폐기 — 크레딧 데드락은 커널로 안 고쳐지므로. 장기적으로 22.04 업그레이드해서 서명된 6.8 HWE 로 갈 것 |
| **PASS** 150만 | **PASS** 150만 | 커널 무관 — 그 사이 **다른 게** 바뀌었다. 무엇이 바뀌었는지 추적(케이블/슬롯/온도/장치 상태). 재현 자체가 불안정해진 것이므로 신중히 |
| **FREEZE** | — | **커널 아님.** → `HANDOFF` 의 **B단계(차분 덤프)** 로. 보드·칩셋·BIOS·슬롯 차이를 본다. 특히 두 PC 의 `LnkSta`(링크 속도/폭) 비교 |

---

## 알아둘 것

- **프리즈하면 호스트는 스스로 못 살아난다.** 전원 강제 재투입이 필요하다.
- **corpus 는 `--resume-coverage` 로 이어진다** — 프리즈해도 커버리지가 0 부터 다시 시작하지
  않는다. 다만 마지막 몇 분은 유실될 수 있다.
- **5.15 를 지우지 말 것.** 되돌릴 수 없으면 6단계를 못 하고, 그러면 결론도 못 낸다.
- mainline 커널은 **unsupported** 다. 원인 확정용 실험 도구로 쓰고, 장기 운용은 22.04 +
  서명된 HWE 6.8 로 가는 게 맞다.
- `pci=noaer` 는 이 테스트에서 뺀다(원인 아님 확인됨). 다시 넣을 이유가 생기면 HANDOFF 참조.
