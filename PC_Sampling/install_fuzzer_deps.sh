#!/usr/bin/env bash
# PC Sampling Fuzzer v7.8 dependency installer
# Target: Ubuntu 24.04 (kernel 6.x, e.g. 6.8.0-generic)
#
# fuzzer 는 `sudo python3 pc_sampling_fuzzer_v7.8.py ...` 로 실행되므로
# 모든 Python 패키지는 root 가 볼 수 있도록 *전역* 으로 설치한다.
# (pip --user 는 호출 계정의 ~/.local 에만 깔려 sudo/root 에서 안 보임)
set -euo pipefail

log()  { printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '\n[WARN] %s\n' "$*" >&2; }

export DEBIAN_FRONTEND=noninteractive

log "PC Sampling Fuzzer v7.8 dependency installer (Ubuntu 24.04 / kernel 6.x)"

log "APT update"
sudo apt-get update

# 시스템 도구 + Python 전역 패키지
#   openocd        : PCSR 비침습 PC 샘플링 (coverage)
#   nvme-cli       : NVMe passthru
#   pciutils       : setpci / lspci (PM perturbation, PCIe rescan)
#   bolt           : Thunderbolt(USB4) 장치 authorize/관리 (boltctl)
#   matplotlib/numpy : graph 산출물 (coverage_growth / firmware_map / csfuzz_dynamics / heatmap)
#   python3-serial : pmu_4_1.py 가 pyserial 을 쓸 경우 대비 (PMU GPIO 제어)
# 주의: 이 fuzzer 는 graphviz/dot/sfdp 를 쓰지 않는다 (v7.6+ 에서 per-command CFG 제거됨, matplotlib 전용).
log "Installing required system packages"
sudo apt-get install -y \
  python3 python3-pip \
  openocd nvme-cli pciutils bolt \
  python3-matplotlib python3-numpy python3-serial

# pmu_4_1.py 가 libgpiod 를 쓸 수도 있어 있으면 추가 (없으면 경고만)
log "Installing optional GPIO package if available"
if apt-cache show python3-gpiod >/dev/null 2>&1; then
  sudo apt-get install -y python3-gpiod
else
  warn "python3-gpiod not found in this repo; install manually if pmu_4_1.py requires it"
fi

# intelhex : --unsupported-skip 의 vendor parser fallback (보통 DebugPackage 번들로 해결되나 안전망)
log "Installing intelhex system-wide"
if apt-cache show python3-intelhex >/dev/null 2>&1; then
  sudo apt-get install -y python3-intelhex
else
  sudo pip3 install --break-system-packages intelhex
fi

# pylink-square : v8.1 P9(Cortex-R5) J-Link halt 샘플러(JLinkHaltSampler) 의존성.
# PM9M1/BM9H1(PCSR/OpenOCD)만 돌리면 불필요하나, --product P9 사용 시 필요.
log "Installing pylink-square system-wide (P9 J-Link sampler)"
sudo pip3 install --break-system-packages pylink-square || \
  warn "pylink-square install 실패 — --product P9 사용 시 'pip3 install pylink-square' 수동 설치"

# OpenOCD / J-Link USB 권한
log "Installing OpenOCD udev rules"
if [ -f /usr/share/openocd/contrib/60-openocd.rules ]; then
  sudo install -m 0644 /usr/share/openocd/contrib/60-openocd.rules /etc/udev/rules.d/60-openocd.rules
  sudo udevadm control --reload-rules
  sudo udevadm trigger
else
  warn "60-openocd.rules not found; skipping udev rule copy"
fi

log "Enabling bolt service (Thunderbolt)"
sudo systemctl enable --now bolt 2>/dev/null || warn "bolt service could not be enabled automatically"

# 핵심: fuzzer 와 동일한 root 컨텍스트에서 import 가 실제로 되는지 확인
log "Verifying Python imports under sudo/root context"
sudo python3 - <<'PY'
mods = ["matplotlib", "numpy", "serial", "intelhex"]
missing = []
for m in mods:
    try:
        __import__(m)
    except Exception as e:
        missing.append(f"{m}: {e}")
if missing:
    raise SystemExit("Missing Python modules under sudo:\n" + "\n".join(missing))
print("Python imports under sudo: OK")
PY

# 필수 바이너리 (graphviz dot/sfdp 는 제외 — v7.8 에서 미사용)
log "Verifying required binaries"
for cmd in python3 nvme lspci setpci openocd; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing binary: $cmd" >&2; exit 1; }
done
command -v boltctl >/dev/null 2>&1 || warn "boltctl not found (Thunderbolt 미사용이면 무시)"

# JLinkExe 는 SEGGER 독점 .deb — apt 에 없음. 존재 여부만 확인.
if command -v JLinkExe >/dev/null 2>&1; then
  echo "JLinkExe: OK"
else
  warn "JLinkExe not found. Install SEGGER J-Link Software Pack if you need J-Link dump / --unsupported-skip."
fi

log "openocd version"
openocd --version 2>&1 | head -1 || true

cat <<'EOF'

==================================================
Install complete.

남은 수동 단계:
  1) Fuzzer 폴더 일체 복사:
       pc_sampling_fuzzer_v7.8.py / state_fields.py / nvme_seeds.py
       ufas / *.cfg / DebugPackage/ / pmu_4_1.py (또는 실제 PMU 스크립트)

  2) J-Link dump / --unsupported-skip 쓸 경우 (--no-jlink 면 생략):
       SEGGER J-Link Software Pack(.deb) 설치
       https://www.segger.com/downloads/jlink/  (JLink_Linux_*.deb)

  3) Thunderbolt 장치 인증 확인:
       boltctl list                 # device 가 authorized 인지
       (필요시) boltctl authorize <uuid>
       sudo nvme list ; lspci | grep -i nvme

  4) Smoke test:
       sudo python3 pc_sampling_fuzzer_v7.8.py --help

  ※ pmu_4_1.py 가 pyserial 외 다른 라이브러리를 쓰면 첫 실행 traceback 을 보고
    해당 패키지만 추가 설치하면 됨.
==================================================

EOF
