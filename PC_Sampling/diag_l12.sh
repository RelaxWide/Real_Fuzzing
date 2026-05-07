#!/bin/bash
# L1.2 진입·복귀 단계별 진단 스크립트
# 목적: PS0/PS1 각각에서 L1.2 진입 시 /dev/nvme0과 PCIe sysfs가 어떻게 변하는지 추적
#
# 사용법:
#   sudo bash diag_l12.sh          # PS0+L1.2 테스트
#   sudo bash diag_l12.sh ps1      # PS1+L1.2 테스트 (true L1.2 — 클록 off)
#   sudo bash diag_l12.sh ps1 exit # PS1+L1.2 진입 후 복귀 테스트
#   sudo bash diag_l12.sh all      # PS0/PS1 모두 순차 테스트

BDF="0000:02:00.0"
RP_BDF="0000:00:01.1"
L1SS_OFF=0x240
NVME_DEV="/dev/nvme0"
PMU_PY="$(dirname "$0")/pmu_4_1.py"

MODE="${1:-ps0}"
DO_EXIT="${2:-exit}"

set -euo pipefail

# ── 유틸 함수 ──────────────────────────────────────────────────────────────────
ts() { date '+%H:%M:%S.%3N'; }

log() { echo "[$(ts)] $*"; }

read_reg() {
    local bdf=$1 off=$2 width=${3:-l}
    sudo setpci -s "$bdf" "${off}.${width}" 2>/dev/null || echo "FAIL"
}

write_reg() {
    local bdf=$1 off=$2 val=$3 mask=$4 width=${5:-l}
    sudo setpci -s "$bdf" "${off}.${width}=${val}:${mask}" 2>/dev/null
}

nvme_ctrl_state() {
    # NVMe 컨트롤러 커널 내부 상태: live / resetting / connecting / deleting / dead
    cat /sys/class/nvme/nvme0/state 2>/dev/null || echo "unknown"
}

check_state() {
    local label=$1
    echo ""
    echo "── $label ──────────────────────────────────────"
    echo "  LNKCTL    EP : $(read_reg $BDF    $LNKCTL_OFF w)"
    echo "  LNKCTL    RP : $(read_reg $RP_BDF $RP_LNKCTL_OFF w)"
    echo "  L1SS CTL1 EP : $(read_reg $BDF    $L1SS_CTL1_OFF)"
    echo "  L1SS CTL1 RP : $(read_reg $RP_BDF $L1SS_CTL1_OFF)"
    echo "  PMCSR     EP : $(read_reg $BDF    $PMCSR_OFF w)"
    local pci_sysfs="/sys/bus/pci/devices/$BDF"
    if [ -e "$pci_sysfs" ]; then
        echo "  PCI sysfs    : EXISTS"
        local drv
        drv=$(readlink "$pci_sysfs/driver" 2>/dev/null | xargs basename 2>/dev/null || echo "none")
        echo "  PCI driver   : $drv"
    else
        echo "  PCI sysfs    : MISSING ← surprise removal"
    fi
    if [ -e "$NVME_DEV" ]; then
        echo "  $NVME_DEV    : EXISTS"
    else
        echo "  $NVME_DEV    : MISSING"
    fi
    echo "  NVMe state   : $(nvme_ctrl_state)"
}

pmu_clkreq_deassert() {
    log "[PMU] CLKREQ# Deassert → pin15 (SetGpioHigh)"
    python3 "$PMU_PY" 15 1 1 3300 && log "[PMU] pin15 rc=0" || log "[PMU] pin15 rc=$?"
}

pmu_clkreq_assert() {
    log "[PMU] CLKREQ# Assert → pin16 (SetGpioLow)"
    python3 "$PMU_PY" 16 1 1 3300 && log "[PMU] pin16 rc=0" || log "[PMU] pin16 rc=$?"
}

poll_config() {
    local label=$1 timeout_s=${2:-5}
    local deadline=$(( $(date +%s) + timeout_s ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local v
        v=$(read_reg $BDF $LNKCTL_OFF w)
        if [ "$v" != "FAIL" ] && [ "$v" != "ffff" ] && [ "$v" != "FFFF" ]; then
            log "[$label] config space 복귀: LNKCTL=0x$v"
            return 0
        fi
        log "[$label] config space=0x$v (클록 없음) — 대기"
        sleep 0.2
    done
    log "[$label] config space 복귀 실패 (${timeout_s}s timeout)"
    return 1
}

poll_nvme() {
    local timeout_s=${1:-30}
    local deadline=$(( $(date +%s) + timeout_s ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if [ ! -e "$NVME_DEV" ]; then
            log "[nvme-poll] $NVME_DEV 없음  state=$(nvme_ctrl_state)"
            if [ ! -e "/sys/bus/pci/devices/$BDF" ]; then
                log "[nvme-poll] $BDF sysfs도 없음 — surprise removal 상태"
            fi
            sleep 1
            continue
        fi
        local st rc=0
        st=$(nvme_ctrl_state)
        sudo nvme id-ctrl "$NVME_DEV" >/dev/null 2>&1 || rc=$?
        log "[nvme-poll] id-ctrl rc=$rc  state=$st"
        # id-ctrl 성공 AND state=live 둘 다 확인
        if [ "$rc" -eq 0 ] && [ "$st" = "live" ]; then
            log "[nvme-poll] 완전 복귀 확인 (id-ctrl OK + state=live)"
            return 0
        fi
        [ "$st" = "dead" ] && { log "[nvme-poll] state=dead — 드라이버 포기 상태"; return 1; }
        sleep 1
    done
    log "[nvme-poll] ${timeout_s}s 안에 $NVME_DEV 미복귀  최종 state=$(nvme_ctrl_state)"
    return 1
}

# ── Cap offset 탐지 ─────────────────────────────────────────────────────────────
log "=== L1.2 단계별 진단 시작 ==="

PM_CAP=$(sudo lspci -vvv -s "$BDF" 2>/dev/null \
    | grep -i "Power Management" | grep -oP '\[\K[0-9a-fA-F]+' | head -1)
[ -z "$PM_CAP" ] && { log "PM cap 탐지 실패"; exit 1; }
PMCSR_OFF=$(printf "0x%x" $((16#$PM_CAP + 4)))

PCIE_CAP=$(sudo lspci -vvv -s "$BDF" 2>/dev/null \
    | grep -iP "PCI Express.*Endpoint|Express.*Endpoint" \
    | grep -oP '\[\K[0-9a-fA-F]+' | head -1)
[ -z "$PCIE_CAP" ] && { log "PCIe cap 탐지 실패"; exit 1; }
LNKCTL_OFF=$(printf "0x%x" $((16#$PCIE_CAP + 0x10)))

RP_PCIE_CAP=$(sudo lspci -vvv -s "$RP_BDF" 2>/dev/null \
    | grep -iP "PCI Express" | grep -oP '\[\K[0-9a-fA-F]+' | head -1)
RP_LNKCTL_OFF=$(printf "0x%x" $((16#${RP_PCIE_CAP:-80} + 0x10)))

L1SS_CTL1_OFF=$(printf "0x%x" $((L1SS_OFF + 0x08)))

log "PMCSR=$PMCSR_OFF  LNKCTL=$LNKCTL_OFF  RP_LNKCTL=$RP_LNKCTL_OFF  L1SS_CTL1=$L1SS_CTL1_OFF"

# ── 공통 L1.2 진입 함수 ─────────────────────────────────────────────────────────
do_l12_entry() {
    local nvme_ps=$1   # 0 or 1

    log ""
    log "━━━ L1.2 진입 (NVMe PS${nvme_ps}) ━━━"

    # NVMe PS 설정
    log "[1] NVMe PS${nvme_ps} 설정"
    sudo nvme set-feature "$NVME_DEV" -f 2 -v "$nvme_ps" 2>&1 | head -1 || true
    sleep 0.1

    # L1SS CTL1 enable (bit3:ASPM L1.1, bit2:ASPM L1.2, bit1:PM L1.1, bit0:PM L1.2)
    log "[2] L1SS CTL1 enable (RP→EP 순)"
    write_reg "$RP_BDF" "$L1SS_CTL1_OFF" 0x0000000f 0x0000000f
    write_reg "$BDF"    "$L1SS_CTL1_OFF" 0x0000000f 0x0000000f

    # ASPM L1 enable (LNKCTL bits[1:0]=0x02)
    log "[3] LNKCTL ASPM L1 enable (RP→EP 순)"
    write_reg "$RP_BDF" "$LNKCTL_OFF" 0x0002 0x0003 w
    write_reg "$BDF"    "$LNKCTL_OFF" 0x0002 0x0003 w

    # 레지스터 검증 (CLKREQ# deassert 이전)
    log "[4] 레지스터 검증 (deassert 이전)"
    echo "    LNKCTL EP : $(read_reg $BDF    $LNKCTL_OFF w)"
    echo "    L1SS CTL1 : $(read_reg $BDF    $L1SS_CTL1_OFF)"

    # CLKREQ# deassert → 실제 L1.2 진입 트리거
    log "[5] CLKREQ# deassert"
    pmu_clkreq_deassert
    sleep 0.3  # L1 idle timer + clock off 대기

    # 진입 후 상태
    log "[6] 진입 후 상태"
    local v
    v=$(read_reg $BDF $LNKCTL_OFF w)
    log "    LNKCTL = 0x$v  (0xffff → clock off, 진입 성공)"
    if [ -e "$NVME_DEV" ]; then
        log "    $NVME_DEV : 존재 (PS0이면 정상 — device-side CLKREQ# 유지)"
    else
        log "    $NVME_DEV : 없음 (커널 드라이버 reset 시작)"
    fi
    if [ ! -e "/sys/bus/pci/devices/$BDF" ]; then
        log "    $BDF sysfs : MISSING"
    else
        local drv
        drv=$(readlink "/sys/bus/pci/devices/$BDF/driver" 2>/dev/null | xargs basename 2>/dev/null || echo "none")
        log "    $BDF sysfs : 존재, driver=$drv"
    fi
}

# ── 공통 L1.2 복귀 함수 ─────────────────────────────────────────────────────────
do_l12_exit() {
    log ""
    log "━━━ L1.2 복귀 (pin16 assert → 폴링) ━━━"

    # CLKREQ# assert → 클록 복원
    log "[A] CLKREQ# assert"
    pmu_clkreq_assert

    # config space 응답 폴링
    log "[B] config space 복귀 폴링 (5s)"
    if ! poll_config "config-poll" 5; then
        log "    !!! config space 복귀 실패 — 링크 문제 가능성"
    fi

    # sysfs + driver 상태 즉시 확인
    log "[C] PCIe sysfs 상태"
    if [ -e "/sys/bus/pci/devices/$BDF" ]; then
        local drv
        drv=$(readlink "/sys/bus/pci/devices/$BDF/driver" 2>/dev/null | xargs basename 2>/dev/null || echo "none")
        log "    $BDF sysfs=EXISTS  driver=$drv"
    else
        log "    $BDF sysfs=MISSING ← surprise removal 확정"
    fi

    # LNKCTL disable
    log "[D] LNKCTL ASPM disable (L0 복귀)"
    write_reg "$BDF"    "$LNKCTL_OFF" 0x0000 0x0003 w 2>/dev/null || true
    write_reg "$RP_BDF" "$LNKCTL_OFF" 0x0000 0x0003 w 2>/dev/null || true
    # L1SS disable
    write_reg "$BDF"    "$L1SS_CTL1_OFF" 0x00000000 0x0000000f 2>/dev/null || true
    write_reg "$RP_BDF" "$L1SS_CTL1_OFF" 0x00000000 0x0000000f 2>/dev/null || true

    # NVMe 재등록 대기
    log "[E] $NVME_DEV 재등록 대기 (최대 30s)"
    local t0
    t0=$(date +%s)
    poll_nvme 30 && \
        log "    복귀 성공 ($(( $(date +%s) - t0 ))s)" || \
        log "    복귀 실패 (30s timeout)"

    check_state "최종 상태"
}

# ── 테스트 실행 ─────────────────────────────────────────────────────────────────
run_test() {
    local ps=$1

    check_state "진입 전 초기 상태 (PS${ps})"
    do_l12_entry "$ps"
    sleep 0.5
    check_state "L1.2 진입 직후 (PS${ps})"

    do_l12_exit

    # NVMe PS0 복귀
    log ""
    log "[F] NVMe PS0 복귀 시도"
    sudo nvme set-feature "$NVME_DEV" -f 2 -v 0 2>&1 | head -1 || \
        log "    PS0 set-feature 실패 (드라이버 reset 중일 수 있음)"

    check_state "복귀 완료 (PS${ps})"
}

# state=live 될 때까지 대기 (다음 사이클 진입 전 안전 확인)
wait_nvme_live() {
    local timeout_s=${1:-60}
    local deadline=$(( $(date +%s) + timeout_s ))
    log "[stabilize] NVMe state=live 대기 (최대 ${timeout_s}s)..."
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local st
        st=$(nvme_ctrl_state)
        log "[stabilize] state=$st"
        [ "$st" = "live" ] && { log "[stabilize] OK"; return 0; }
        [ "$st" = "dead" ] && { log "[stabilize] state=dead — 복구 불가"; return 1; }
        sleep 2
    done
    log "[stabilize] timeout — 최종 state=$(nvme_ctrl_state)"
    return 1
}

case "$MODE" in
    ps0) run_test 0 ;;
    ps1) run_test 1 ;;
    # ps0 두 번: 복귀 후 state=live 확인 후 재진입 — 두 번째 실패 여부 재현
    twice)
        log "=== PS0 첫 번째 ==="
        run_test 0
        log ""
        wait_nvme_live 60
        log ""
        log "=== PS0 두 번째 (state=live 확인 후 재진입) ==="
        run_test 0
        ;;
    all)
        log "=== PS0 테스트 ==="
        run_test 0
        wait_nvme_live 60
        log ""
        log "=== PS1 테스트 ==="
        run_test 1
        ;;
    *)
        echo "Usage: $0 [ps0|ps1|all|twice]"
        exit 1
        ;;
esac

log ""
log "=== 진단 완료 ==="
