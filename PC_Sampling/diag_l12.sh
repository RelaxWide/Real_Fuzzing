#!/usr/bin/env bash
# L1.2 entry/exit diagnostic script.
# The important invariant for repeated tests is:
#   "NVMe state=live" is not enough; RP/EP ASPM, L1SS, PMCSR, CLKREQ#,
#   config space, and an NVMe command must all be back at baseline.

set -euo pipefail

BDF="${BDF:-0000:02:00.0}"
RP_BDF="${RP_BDF:-0000:00:01.1}"
L1SS_OFF="${L1SS_OFF:-0x240}"
PMU_PY="${PMU_PY:-$(dirname "$0")/pmu_4_1.py}"

MODE="${1:-ps0}"

BASELINE_STABLE_CHECKS="${BASELINE_STABLE_CHECKS:-5}"
BASELINE_STABLE_INTERVAL="${BASELINE_STABLE_INTERVAL:-1}"
BASELINE_SETTLE_S="${BASELINE_SETTLE_S:-5}"
NVME_DEBUG="${NVME_DEBUG:-0}"
RESTORE_NVME_PS0="${RESTORE_NVME_PS0:-0}"
FORCE_PS0_ENTRY_SET="${FORCE_PS0_ENTRY_SET:-0}"

ts() { date '+%H:%M:%S.%3N'; }
log() { echo "[$(ts)] $*"; }

# /sys/class/nvme/nvmeN 심링크의 실제 경로에서 BDF를 추출해 매칭.
# /dev/nvme0 는 char device(c), namespace /dev/nvme0n1 은 block(b)이므로
# [ -b ] 검사는 controller를 찾지 못하는 버그가 있음 — 이 함수는 sysfs 심링크만 사용.
find_nvme_dev() {
    local ctrl_dir ctrl path bdf
    for ctrl_dir in /sys/class/nvme/nvme[0-9]*; do
        [ -d "$ctrl_dir" ] || continue
        ctrl=$(basename "$ctrl_dir")
        # 컨트롤러만 선택 (nvme0, nvme1 … — nvme0n1 같은 namespace 제외)
        [[ "$ctrl" =~ ^nvme[0-9]+$ ]] || continue
        # 심링크 실제 경로에서 마지막 BDF 추출 (EP BDF = 경로 중 마지막 XX:XX.X)
        path=$(readlink -f "$ctrl_dir" 2>/dev/null || true)
        bdf=$(printf '%s\n' "$path" \
            | grep -oP '[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f](?=/)' \
            | tail -1) || true
        [ "$NVME_DEBUG" = "1" ] && log "[nvme-find] ctrl=$ctrl path=$path bdf=${bdf:-none} target=$BDF" >&2
        [ "$bdf" = "$BDF" ] && echo "/dev/$ctrl" && return 0
    done
    return 1
}

refresh_nvme_dev() {
    local cur_dev
    cur_dev=$(find_nvme_dev 2>/dev/null || echo "")
    [ -n "$cur_dev" ] || return 1
    if [ "$cur_dev" != "$NVME_DEV" ]; then
        log "★ 컨트롤러 번호 변경: $NVME_DEV → $cur_dev"
        NVME_DEV="$cur_dev"
    fi
}

nvme_ctrl_state() {
    local cur_dev ctrl_name
    cur_dev=$(find_nvme_dev 2>/dev/null) || { echo "unknown"; return; }
    ctrl_name=$(basename "$cur_dev")
    cat "/sys/class/nvme/${ctrl_name}/state" 2>/dev/null || echo "unknown"
}

NVME_DEV=$(find_nvme_dev 2>/dev/null || echo "/dev/nvme0")
log "초기 NVMe 디바이스: $NVME_DEV"

read_reg() {
    local bdf=$1 off=$2 width=${3:-l}
    sudo setpci -s "$bdf" "${off}.${width}" 2>/dev/null || echo "FAIL"
}

write_reg() {
    local bdf=$1 off=$2 val=$3 mask=$4 width=${5:-l}
    sudo setpci -s "$bdf" "${off}.${width}=${val}:${mask}" 2>/dev/null
}

is_hex() {
    [[ "$1" =~ ^[0-9a-fA-F]+$ ]]
}

reg_has_value() {
    local v=$1 width=${2:-w}
    [ "$v" != "FAIL" ] || return 1
    is_hex "$v" || return 1
    if [ "$width" = "l" ]; then
        [ "$v" != "ffffffff" ] && [ "$v" != "FFFFFFFF" ]
    else
        [ "$v" != "ffff" ] && [ "$v" != "FFFF" ]
    fi
}

pmu_clkreq_deassert() {
    log "[PMU] CLKREQ# deassert"
    python3 "$PMU_PY" 15 1 1 3300 && log "[PMU] deassert rc=0" || log "[PMU] deassert rc=$?"
}

pmu_clkreq_assert() {
    log "[PMU] CLKREQ# assert"
    python3 "$PMU_PY" 16 1 1 3300 && log "[PMU] assert rc=0" || log "[PMU] assert rc=$?"
}

poll_config() {
    local label=$1 timeout_s=${2:-10}
    local deadline=$(( $(date +%s) + timeout_s ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local v
        v=$(read_reg "$BDF" "$LNKCTL_OFF" w)
        if [ "$v" != "FAIL" ] && [ "$v" != "ffff" ] && [ "$v" != "FFFF" ]; then
            log "[$label] EP config space restored: LNKCTL=0x$v"
            return 0
        fi
        log "[$label] EP config space=0x$v; waiting"
        sleep 0.2
    done
    log "[$label] EP config space restore timeout (${timeout_s}s)"
    return 1
}

poll_nvme() {
    local timeout_s=${1:-90}
    local deadline=$(( $(date +%s) + timeout_s ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local cur_dev st rc=0

        # BDF 기준 재탐색을 항상 우선한다. /dev/nvme0가 남아 있어도
        # 다른 컨트롤러일 수 있으므로 char device 존재만 믿지 않는다.
        cur_dev=$(find_nvme_dev 2>/dev/null || echo "")

        if [ -z "$cur_dev" ]; then
            local sysfs_exists="no"
            [ -e "/sys/bus/pci/devices/$BDF" ] && sysfs_exists="yes"
            log "[nvme-poll] BDF=$BDF 에 nvme 없음  sysfs=$sysfs_exists  (probe 진행 중 or 실패)"
            sleep 1
            continue
        fi

        if [ "$cur_dev" != "$NVME_DEV" ]; then
            log "[nvme-poll] ★ 컨트롤러 번호 변경: $NVME_DEV → $cur_dev"
            NVME_DEV="$cur_dev"
        fi

        st=$(cat "/sys/class/nvme/$(basename "$cur_dev")/state" 2>/dev/null || echo "unknown")
        sudo nvme id-ctrl "$cur_dev" >/dev/null 2>&1 || rc=$?
        log "[nvme-poll] dev=$cur_dev  id-ctrl rc=$rc  state=$st"

        if [ "$rc" -eq 0 ] && [ "$st" = "live" ]; then
            log "[nvme-poll] NVMe command path restored"
            return 0
        fi
        [ "$st" = "dead" ] && { log "[nvme-poll] state=dead"; return 1; }
        sleep 1
    done
    log "[nvme-poll] timeout; final dev=$(find_nvme_dev 2>/dev/null || echo none)  state=$(nvme_ctrl_state)"
    return 1
}

verify_baseline_regs_once() {
    local ep_lnk rp_lnk ep_l1ss rp_l1ss pmcsr

    ep_lnk=$(read_reg "$BDF" "$LNKCTL_OFF" w)
    rp_lnk=$(read_reg "$RP_BDF" "$RP_LNKCTL_OFF" w)
    ep_l1ss=$(read_reg "$BDF" "$EP_L1SS_CTL1_OFF")
    rp_l1ss=$(read_reg "$RP_BDF" "$RP_L1SS_CTL1_OFF")
    pmcsr=$(read_reg "$BDF" "$PMCSR_OFF" w)

    log "    regs: EP_LNKCTL=0x$ep_lnk RP_LNKCTL=0x$rp_lnk EP_L1SS=0x$ep_l1ss RP_L1SS=0x$rp_l1ss PMCSR=0x$pmcsr"

    reg_has_value "$ep_lnk" w || return 1
    reg_has_value "$rp_lnk" w || return 1
    reg_has_value "$ep_l1ss" l || return 1
    reg_has_value "$rp_l1ss" l || return 1
    reg_has_value "$pmcsr" w || return 1

    [ $((16#$ep_lnk & 0x3)) -eq 0 ] || return 1
    [ $((16#$rp_lnk & 0x3)) -eq 0 ] || return 1
    [ $((16#$ep_l1ss & 0xf)) -eq 0 ] || return 1
    [ $((16#$rp_l1ss & 0xf)) -eq 0 ] || return 1
    [ $((16#$pmcsr & 0x3)) -eq 0 ] || return 1
}

verify_nvme_cmd_once() {
    local cur_dev st rc=0
    cur_dev=$(find_nvme_dev 2>/dev/null || echo "")
    if [ -z "$cur_dev" ] || [ ! -c "$cur_dev" ]; then
        log "    nvme: BDF=$BDF 에 nvme 없음  state=$(nvme_ctrl_state)"
        return 1
    fi
    if [ "$cur_dev" != "$NVME_DEV" ]; then
        log "    nvme: ★ 컨트롤러 번호 변경 $NVME_DEV → $cur_dev"
        NVME_DEV="$cur_dev"
    fi
    st=$(cat "/sys/class/nvme/$(basename "$cur_dev")/state" 2>/dev/null || echo "unknown")
    sudo nvme id-ctrl "$cur_dev" >/dev/null 2>&1 || rc=$?
    log "    nvme: dev=$cur_dev  id-ctrl rc=$rc  state=$st"
    [ "$rc" -eq 0 ] && [ "$st" = "live" ]
}

verify_baseline_stable() {
    local label=${1:-baseline-stable}
    local checks=${2:-$BASELINE_STABLE_CHECKS}
    local interval=${3:-$BASELINE_STABLE_INTERVAL}
    local i

    log "[$label] baseline stability check (${checks} consecutive samples, ${interval}s interval)"
    for ((i = 1; i <= checks; i++)); do
        log "[$label] sample $i/$checks"
        verify_baseline_regs_once || {
            log "[$label] failed: baseline registers are not stable"
            return 1
        }
        verify_nvme_cmd_once || {
            log "[$label] failed: NVMe command path is not stable"
            return 1
        }
        sleep "$interval"
    done

    log "[$label] stable"
}

cap_offsets() {
    local pm_cap pcie_cap rp_pcie_cap ep_l1ss_cap rp_l1ss_cap

    pm_cap=$(sudo lspci -vvv -s "$BDF" 2>/dev/null |
        grep -i "Power Management" | grep -oP '\[\K[0-9a-fA-F]+' | head -1 || true)
    [ -z "$pm_cap" ] && { log "PM capability not found"; exit 1; }
    PMCSR_OFF=$(printf "0x%x" $((16#$pm_cap + 4)))

    pcie_cap=$(sudo lspci -vvv -s "$BDF" 2>/dev/null |
        grep -iP "PCI Express.*Endpoint|Express.*Endpoint" |
        grep -oP '\[\K[0-9a-fA-F]+' | head -1 || true)
    [ -z "$pcie_cap" ] && { log "EP PCIe capability not found"; exit 1; }
    LNKCTL_OFF=$(printf "0x%x" $((16#$pcie_cap + 0x10)))

    rp_pcie_cap=$(sudo lspci -vvv -s "$RP_BDF" 2>/dev/null |
        grep -iP "PCI Express" | grep -oP '\[\K[0-9a-fA-F]+' | head -1 || true)
    [ -z "$rp_pcie_cap" ] && { log "RP PCIe capability not found"; exit 1; }
    RP_LNKCTL_OFF=$(printf "0x%x" $((16#$rp_pcie_cap + 0x10)))

    ep_l1ss_cap=$(sudo lspci -vvv -s "$BDF" 2>/dev/null |
        grep -i "L1 PM Substates" | grep -oP '\[\K[0-9a-fA-F]+' | head -1 || true)
    rp_l1ss_cap=$(sudo lspci -vvv -s "$RP_BDF" 2>/dev/null |
        grep -i "L1 PM Substates" | grep -oP '\[\K[0-9a-fA-F]+' | head -1 || true)

    EP_L1SS_CTL1_OFF=$(printf "0x%x" $((16#${ep_l1ss_cap:-${L1SS_OFF#0x}} + 0x08)))
    RP_L1SS_CTL1_OFF=$(printf "0x%x" $((16#${rp_l1ss_cap:-${L1SS_OFF#0x}} + 0x08)))

    log "PMCSR=$PMCSR_OFF EP_LNKCTL=$LNKCTL_OFF RP_LNKCTL=$RP_LNKCTL_OFF EP_L1SS_CTL1=$EP_L1SS_CTL1_OFF RP_L1SS_CTL1=$RP_L1SS_CTL1_OFF"
}

check_state() {
    local label=$1
    echo
    echo "-- $label ----------------------------------------"
    echo "  EP LNKCTL : $(read_reg "$BDF" "$LNKCTL_OFF" w)"
    echo "  RP LNKCTL : $(read_reg "$RP_BDF" "$RP_LNKCTL_OFF" w)"
    echo "  EP L1SS   : $(read_reg "$BDF" "$EP_L1SS_CTL1_OFF")"
    echo "  RP L1SS   : $(read_reg "$RP_BDF" "$RP_L1SS_CTL1_OFF")"
    echo "  EP PMCSR  : $(read_reg "$BDF" "$PMCSR_OFF" w)"
    if [ -e "/sys/bus/pci/devices/$BDF" ]; then
        echo "  PCI sysfs : EXISTS"
    else
        echo "  PCI sysfs : MISSING"
    fi
    if [ -e "$NVME_DEV" ]; then
        echo "  $NVME_DEV : EXISTS"
    else
        echo "  $NVME_DEV : MISSING"
    fi
    echo "  NVMe state: $(nvme_ctrl_state)"
}

require_l12_armed() {
    local ep_lnk rp_lnk ep_l1ss rp_l1ss

    ep_lnk=$(read_reg "$BDF" "$LNKCTL_OFF" w)
    rp_lnk=$(read_reg "$RP_BDF" "$RP_LNKCTL_OFF" w)
    ep_l1ss=$(read_reg "$BDF" "$EP_L1SS_CTL1_OFF")
    rp_l1ss=$(read_reg "$RP_BDF" "$RP_L1SS_CTL1_OFF")

    log "    EP LNKCTL=0x$ep_lnk RP LNKCTL=0x$rp_lnk"
    log "    EP L1SS=0x$ep_l1ss RP L1SS=0x$rp_l1ss"

    reg_has_value "$ep_lnk" w || {
        log "    L1.2 arm failed: EP LNKCTL config read failed"
        return 1
    }
    reg_has_value "$rp_lnk" w || {
        log "    L1.2 arm failed: RP LNKCTL config read failed"
        return 1
    }
    reg_has_value "$ep_l1ss" l || {
        log "    L1.2 arm failed: EP L1SS config read failed"
        return 1
    }
    reg_has_value "$rp_l1ss" l || {
        log "    L1.2 arm failed: RP L1SS config read failed"
        return 1
    }

    if [ $((16#$ep_lnk & 0x3)) -ne 2 ] || [ $((16#$rp_lnk & 0x3)) -ne 2 ]; then
        log "    L1.2 arm failed: ASPM L1 is not enabled on both EP/RP"
        log "    expected: EP/RP LNKCTL bits[1:0] == 0x2"
        return 1
    fi

    if [ $((16#$ep_l1ss & 0xf)) -eq 0 ] || [ $((16#$rp_l1ss & 0xf)) -eq 0 ]; then
        log "    L1.2 arm failed: L1SS is not enabled on both EP/RP"
        log "    current state is L1-only or asymmetric; skip CLKREQ# deassert"
        log "    offsets: EP_L1SS_CTL1=$EP_L1SS_CTL1_OFF RP_L1SS_CTL1=$RP_L1SS_CTL1_OFF"
        return 1
    fi

    log "    L1.2 armed: EP/RP ASPM L1 and L1SS enable bits are set"
}

do_l12_entry() {
    local nvme_ps=$1

    log ""
    log "=== L1.2 entry: PS${nvme_ps}+L1.2+D0 ==="

    log "[1] NVMe PS${nvme_ps}"
    refresh_nvme_dev || log "    NVMe controller not found by BDF; using $NVME_DEV"
    if [ "$nvme_ps" -eq 0 ] && [ "$FORCE_PS0_ENTRY_SET" != "1" ]; then
        log "    PS0 entry set-feature skip (already target PS0; FORCE_PS0_ENTRY_SET=1 to force)"
    else
        sudo nvme set-feature "$NVME_DEV" -f 2 -v "$nvme_ps" 2>&1 | head -1 || true
    fi
    sleep 0.1

    log "[2] L1SS enable bits clear"
    write_reg "$RP_BDF" "$RP_L1SS_CTL1_OFF" 0x00000000 0x0000000f || true
    write_reg "$BDF" "$EP_L1SS_CTL1_OFF" 0x00000000 0x0000000f || true

    log "[3] L1SS enable (RP then EP)"
    write_reg "$RP_BDF" "$RP_L1SS_CTL1_OFF" 0x0000000f 0x0000000f
    write_reg "$BDF" "$EP_L1SS_CTL1_OFF" 0x0000000f 0x0000000f

    log "[4] ASPM L1 enable (RP then EP)"
    write_reg "$RP_BDF" "$RP_LNKCTL_OFF" 0x0002 0x0003 w
    write_reg "$BDF" "$LNKCTL_OFF" 0x0002 0x0003 w

    log "[5] verify before CLKREQ# deassert"
    require_l12_armed || return 1

    log "[6] CLKREQ# deassert"
    pmu_clkreq_deassert
    sleep 0.3

    log "[7] after entry: EP LNKCTL=$(read_reg "$BDF" "$LNKCTL_OFF" w)"
}

stabilize_baseline() {
    log ""
    log "=== Baseline restore: PS0+L0+D0 ==="

    log "[A] RP L1SS + ASPM disable before refclk restore"
    write_reg "$RP_BDF" "$RP_L1SS_CTL1_OFF" 0x00000000 0x0000000f || true
    write_reg "$RP_BDF" "$RP_LNKCTL_OFF" 0x0000 0x0003 w || true
    log "    RP LNKCTL=$(read_reg "$RP_BDF" "$RP_LNKCTL_OFF" w)"

    log "[B] CLKREQ# assert"
    pmu_clkreq_assert
    sleep 0.1

    log "[C] EP config space poll"
    poll_config "baseline-config" 10 || return 1

    log "[D] EP L1SS + ASPM disable"
    write_reg "$BDF" "$LNKCTL_OFF" 0x0000 0x0003 w || true
    write_reg "$BDF" "$EP_L1SS_CTL1_OFF" 0x00000000 0x0000000f || true

    log "[E] PMCSR D0"
    write_reg "$BDF" "$PMCSR_OFF" 0x0000 0x0003 w || true
    sleep 0.1

    log "[F] NVMe command path poll"
    poll_nvme 60 || return 1

    if [ "$RESTORE_NVME_PS0" = "1" ]; then
        log "[G] optional NVMe PS0 restore"
        refresh_nvme_dev || log "    NVMe controller not found by BDF before optional PS0 restore; using $NVME_DEV"
        sudo nvme set-feature "$NVME_DEV" -f 2 -v 0 2>&1 | head -1 || true
        poll_nvme 30 || return 1
    else
        log "[G] optional NVMe PS0 restore skipped (RESTORE_NVME_PS0=1 to enable)"
    fi

    log "[H] baseline readback"
    if ! verify_baseline_regs_once; then
        log "baseline restore failed: registers are not PS0+L0+D0 baseline"
        return 1
    fi

    verify_baseline_stable "baseline-post-restore" || return 1

    log "[I] final settle before next operation (${BASELINE_SETTLE_S}s)"
    sleep "$BASELINE_SETTLE_S"
    log "baseline restore OK"
}

do_l12_exit() {
    stabilize_baseline
    check_state "exit complete"
}

run_test() {
    local ps=$1
    check_state "before entry (PS${ps})"
    do_l12_entry "$ps"
    sleep 0.5
    check_state "after L1.2 entry (PS${ps})"
    do_l12_exit
}

cap_offsets

case "$MODE" in
    ps0)
        run_test 0
        ;;
    ps1)
        run_test 1
        ;;
    twice)
        log "=== PS0 first pass ==="
        run_test 0
        verify_baseline_stable "twice-pre-second" || {
            log "baseline stability check failed; skip second entry"
            exit 1
        }
        log "[twice] extra settle before second entry (${BASELINE_SETTLE_S}s)"
        sleep "$BASELINE_SETTLE_S"
        log ""
        log "=== PS0 second pass after verified baseline ==="
        run_test 0
        ;;
    all)
        log "=== PS0 test ==="
        run_test 0
        stabilize_baseline || exit 1
        log ""
        log "=== PS1 test ==="
        run_test 1
        ;;
    *)
        echo "Usage: $0 [ps0|ps1|all|twice]"
        exit 1
        ;;
esac

log ""
log "=== diagnostic complete ==="
