#!/usr/bin/env bash
# PC Sampling Fuzzer dependency installer
# Target: Ubuntu 24.04 / 26.04 (kernel 6.8 이상. 26.04 GA = 7.0)
#
# fuzzer 는 `sudo python3 pc_sampling_fuzzer_v9.5.py ...` 로 실행되므로
# 모든 Python 패키지는 root 가 볼 수 있도록 *전역* 으로 설치한다.
# (pip --user 는 호출 계정의 ~/.local 에만 깔려 sudo/root 에서 안 보임)
#
# 주의(커널): 5.15 에서는 J-Link halt 샘플링 중 호스트 하드 프리즈가 재현된다(6.8 대비 68배).
#             상세는 HANDOFF_osfreeze_investigation.md. 6.8 이상을 쓸 것.
set -euo pipefail

log()  { printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '\n[WARN] %s\n' "$*" >&2; }

export DEBIAN_FRONTEND=noninteractive

log "PC Sampling Fuzzer dependency installer (Ubuntu 24.04/26.04, kernel 6.8+)"

log "APT update"
sudo apt-get update

# 시스템 도구 + Python 전역 패키지
#   openocd        : PCSR 비침습 PC 샘플링 (coverage)
#   nvme-cli       : NVMe passthru
#   pciutils       : setpci / lspci (PM perturbation, PCIe rescan)
#   bolt           : Thunderbolt(USB4) 장치 authorize/관리 (boltctl)
#   matplotlib/numpy : graph 산출물 (coverage_growth / firmware_map / csfuzz_dynamics / heatmap)
#   python3-serial : pmu_4_1.py 가 pyserial 을 쓸 경우 대비 (PMU GPIO 제어)
#   cifs-utils     : (클라이언트) 우분투가 원격 SMB 공유를 마운트할 때
#   nfs-common     : (클라이언트) NFS 공유 마운트
#   samba          : (서버) 윈도우 PC 에서 \\우분투IP\<계정> 으로 홈 디렉터리 접근할 때.
#                    ※ 리스닝 서비스가 뜬다. 설정은 아래 "남은 수동 단계" 참조
#                       ([homes] 주석 해제 + smbpasswd -a <계정> 이 필요)
#   net-tools      : ifconfig/route 등 구식 도구 (요즘 우분투 기본 미설치, ip 로 대체 가능하나 습관상 필요)
#   openssh-client : (나가는 쪽) 이 머신에서 원격으로 ssh/scp 할 때
#   openssh-server : (들어오는 쪽) PuTTY 등으로 이 머신에 접속할 때.
#                    ※ desktop ISO 는 SSH 서버를 기본 설치하지 않는다 — 없으면 PuTTY 가 붙지 않음
#   vim            : 기본 에디터
# 주의: 이 fuzzer 는 graphviz/dot/sfdp 를 쓰지 않는다 (v7.6+ 에서 per-command CFG 제거됨, matplotlib 전용).
log "Installing required system packages"
sudo apt-get install -y \
  python3 python3-pip \
  openocd nvme-cli pciutils bolt \
  python3-matplotlib python3-numpy python3-serial \
  cifs-utils nfs-common samba net-tools openssh-client openssh-server vim

# SSH 서버는 설치만으로 끝내지 않는다 — 리그는 원격 접속이 기본 전제라 활성화까지 해둔다.
log "Enabling SSH server (PuTTY 등 원격 접속용)"
sudo systemctl enable --now ssh 2>/dev/null || warn "ssh 서비스 활성화 실패 — 'systemctl status ssh' 확인"
sudo ufw allow ssh   2>/dev/null || true
sudo ufw allow samba 2>/dev/null || true

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

# paramiko : 현재 리포의 활성 코드는 import 하지 않는다(third-party 의존성은 matplotlib/numpy/pylink 뿐).
#            원격 리그 제어·로그 수집용 별도 스크립트에서 쓰므로 편의상 함께 설치한다.
#            없어도 fuzzer 는 동작하므로 실패해도 경고만 하고 진행.
log "Installing paramiko system-wide (원격 제어 스크립트용, fuzzer 필수 아님)"
if apt-cache show python3-paramiko >/dev/null 2>&1; then
  sudo apt-get install -y python3-paramiko
else
  sudo pip3 install --break-system-packages paramiko || \
    warn "paramiko install 실패 — 원격 스크립트 쓸 때 'pip3 install paramiko' 수동 설치"
fi

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
# 필수: 없으면 fuzzer 가 동작하지 않는다 → 실패 처리
required = ["matplotlib", "numpy", "serial", "intelhex"]
# 선택: 특정 제품/스크립트에서만 필요 → 경고만
optional = ["pylink", "paramiko"]

missing = []
for m in required:
    try:
        __import__(m)
    except Exception as e:
        missing.append(f"{m}: {e}")
if missing:
    raise SystemExit("Missing Python modules under sudo:\n" + "\n".join(missing))
print("Python imports under sudo (required): OK")

for m in optional:
    try:
        __import__(m)
        print(f"  optional {m}: OK")
    except Exception as e:
        print(f"  [WARN] optional {m} 미설치 ({e}) — "
              f"{'--product P7/P9 (J-Link halt 샘플러) 사용 시 필요' if m == 'pylink' else '원격 제어 스크립트 사용 시 필요'}")
PY

# 필수 바이너리 (graphviz dot/sfdp 는 제외 — v7.8 에서 미사용)
log "Verifying required binaries"
for cmd in python3 nvme lspci setpci openocd; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Missing binary: $cmd" >&2; exit 1; }
done
command -v boltctl   >/dev/null 2>&1 || warn "boltctl not found (Thunderbolt 미사용이면 무시)"
command -v mount.cifs >/dev/null 2>&1 || warn "mount.cifs not found (SMB 네트워크 드라이브 미사용이면 무시)"

# 원격 접속(PuTTY 등) 가능 여부는 리그 운용에 직결되므로 리스닝까지 확인한다.
log "SSH 서버 리스닝 확인"
if ss -tln 2>/dev/null | grep -q ':22 '; then
  echo "sshd listening on :22 — OK"
  ip -4 -o addr show scope global 2>/dev/null | awk '{print "  접속 주소: " $4}'
else
  warn "sshd 가 :22 에서 리스닝하지 않음 — 'sudo systemctl status ssh' 확인. PuTTY 접속 불가 상태."
fi

# nvme-cli 버전 — fuzzer 가 nvme CLI 출력을 다수 파싱하므로 메이저 버전 변화는 회귀 위험.
# 1.x(20.04) → 2.x(24.04+) 에서 출력 포맷이 바뀐 이력이 있다.
log "nvme-cli version (출력 파싱 호환성 확인용)"
nvme version 2>&1 | head -1 || true

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
  1) Fuzzer 폴더 일체 복사(또는 git clone):
       pc_sampling_fuzzer_v9.5.py / nvme_seeds.py / fuzzer_config.json
       coverage_growth_plot.py / *.cfg / DebugPackage/ / rag/ / pmu 스크립트

  2) J-Link 사용 시 (--no-jlink 면 생략) — apt 에 없으므로 반드시 수동:
       SEGGER J-Link Software Pack(.deb) 설치
       https://www.segger.com/downloads/jlink/  (JLink_Linux_*.deb)

  3) Thunderbolt 장치 인증 확인:
       boltctl list                 # device 가 authorized 인지
       (필요시) boltctl authorize <uuid>
       sudo nvme list ; lspci | grep -i nvme

  4-A) 우분투가 **클라이언트** (원격 SMB 공유를 마운트) — 필요할 때만:
       sudo mkdir -p /mnt/share
       sudo mount -t cifs //서버/공유 /mnt/share -o username=계정,uid=$(id -u),vers=3.0
       # 영구 마운트는 /etc/fstab 에:
       #   credentials=/etc/samba/creds,uid=1000,gid=1000,vers=3.0,_netdev,nofail,x-systemd.automount
       # ※ nofail 필수 — 없으면 망/서버 장애 시 부팅이 멈춘다.
       # ※ x-systemd.automount 권장 — 부팅을 지연시키지 않고 첫 접근 때 붙는다.

  4-B) 우분투가 **서버** (윈도우에서 \\우분투IP\<계정> 으로 홈 접근) — samba 는 위에서 설치됨:
       sudo vim /etc/samba/smb.conf
         → [homes] 섹션 주석 해제 + browseable = yes / read only = no
       sudo smbpasswd -a <계정>      # ★ 리눅스 비밀번호와 별개. 이걸 빼먹으면 인증 거부됨
       testparm && sudo systemctl restart smbd && sudo systemctl enable smbd
       sudo ufw allow samba 2>/dev/null || true
       # 비밀번호가 짧아 거부되면: sudo pdbedit -P "min password length" -C 1

  5) Smoke test:
       sudo python3 pc_sampling_fuzzer_v9.5.py --help
       sudo python3 jlink_reg_diag.py --device Cortex-R5 --interface swd --speed 2000

  ※ pmu_4_1.py 가 pyserial 외 다른 라이브러리를 쓰면 첫 실행 traceback 을 보고
    해당 패키지만 추가 설치하면 됨.
==================================================

EOF
