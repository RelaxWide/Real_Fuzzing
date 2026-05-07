#!/bin/bash
# PMCSR D3hot ↔ D0 + L1.2 진입/복귀 직접 진단 스크립트

BDF="0000:02:00.0"
RP_BDF="0000:00:01.1"     # 루트 포트
L1SS_OFF=0x240            # lspci에서 확인한 L1SS cap offset

set -e

echo "=== PCIe PM 진단: $BDF ==="
echo ""

# PM cap offset 탐지
PM_CAP=$(sudo lspci -vvv -s "$BDF" 2>/dev/null | grep -i "Power Management" | grep -oP '\[\K[0-9a-fA-F]+' | head -1)
[ -z "$PM_CAP" ] && { echo "PM cap 탐지 실패"; exit 1; }
PMCSR_OFF=$(printf "0x%x" $((16#$PM_CAP + 4)))

# PCIe Express cap offset 탐지
PCIE_CAP=$(sudo lspci -vvv -s "$BDF" 2>/dev/null | grep -iP "PCI Express.*Endpoint|Express.*Endpoint" | grep -oP '\[\K[0-9a-fA-F]+' | head -1)
[ -z "$PCIE_CAP" ] && { echo "PCIe Express cap 탐지 실패"; exit 1; }
LNKCTL_OFF=$(printf "0x%x" $((16#$PCIE_CAP + 0x10)))

RP_PCIE_CAP=$(sudo lspci -vvv -s "$RP_BDF" 2>/dev/null | grep -iP "PCI Express.*Root|Express.*Root" | grep -oP '\[\K[0-9a-fA-F]+' | head -1)
[ -z "$RP_PCIE_CAP" ] && RP_PCIE_CAP=$(sudo lspci -vvv -s "$RP_BDF" 2>/dev/null | grep "PCI Express" | grep -oP '\[\K[0-9a-fA-F]+' | head -1)
RP_LNKCTL_OFF=$(printf "0x%x" $((16#${RP_PCIE_CAP:-80} + 0x10)))
RP_L1SS_OFF=$((L1SS_OFF))   # 보통 EP/RP 동일 offset

L1SS_CTL1_OFF=$(printf "0x%x" $((L1SS_OFF + 0x08)))

echo "  PMCSR   = ${PMCSR_OFF}"
echo "  LNKCTL  = ${LNKCTL_OFF}  (RP: ${RP_LNKCTL_OFF})"
echo "  L1SS+08 = ${L1SS_CTL1_OFF}"
echo ""

# ── 테스트 1: D3hot ↔ D0 (L-state 변경 없이) ─────────────────────────
echo "━━━ 테스트 1: D3hot ↔ D0 (ASPM 현재 상태 유지) ━━━"
VAL=$(sudo setpci -s "$BDF" "${PMCSR_OFF}.w")
echo "  현재 PMCSR = 0x${VAL}  (D$((16#${VAL} & 3)))"

echo "  D3hot 진입..."
sudo setpci -s "$BDF" "${PMCSR_OFF}.w=0003:0003"
sleep 0.05
VAL=$(sudo setpci -s "$BDF" "${PMCSR_OFF}.w")
echo "  PMCSR after D3hot = 0x${VAL}  (D$((16#${VAL} & 3)))"

echo "  D0 복귀 (100ms 후)..."
sleep 0.1
for i in 1 2 3; do
    sudo setpci -s "$BDF" "${PMCSR_OFF}.w=0000:0003"
    sleep 0.1
    VAL=$(sudo setpci -s "$BDF" "${PMCSR_OFF}.w")
    DS=$((16#${VAL} & 3))
    echo "    attempt $i: PMCSR=0x${VAL} D${DS}"
    [ "$DS" -eq 0 ] && { echo "  → D0 성공 (attempt $i)"; break; }
    [ "$i" -eq 3 ] && echo "  → D0 실패"
done
echo ""

# ── 테스트 2: L1.2 활성화 → D3hot → 복귀 (퍼저 실제 시퀀스) ──────────
echo "━━━ 테스트 2: L1.2+D3hot 진입 → L0+D0 복귀 (퍼저 시퀀스) ━━━"

echo "  [a] LNKCTL ASPM L0s disable, ClkPM disable..."
sudo setpci -s "$BDF"    "${LNKCTL_OFF}.w=0000:0003"
sudo setpci -s "$RP_BDF" "${RP_LNKCTL_OFF}.w=0000:0003"

echo "  [b] L1SS L1.2 활성화 (bits[3:0]=0xA: ASPM+PMPM L1.2)..."
sudo setpci -s "$BDF"    "${L1SS_CTL1_OFF}.l=0000000a:0000000f"
sudo setpci -s "$RP_BDF" "${L1SS_CTL1_OFF}.l=0000000a:0000000f" 2>/dev/null || true

echo "  [c] LNKCTL ASPM L1 enable..."
sudo setpci -s "$BDF"    "${LNKCTL_OFF}.w=0002:0003"
sudo setpci -s "$RP_BDF" "${RP_LNKCTL_OFF}.w=0002:0003"

echo "  [d] D3hot 진입..."
sudo setpci -s "$BDF" "${PMCSR_OFF}.w=0003:0003"
sleep 0.2
VAL=$(sudo setpci -s "$BDF" "${PMCSR_OFF}.w" 2>&1) || VAL="READ_FAIL"
echo "    PMCSR after D3hot = ${VAL}"

echo ""
echo "  ── 복귀 시퀀스 시작 ──"

echo "  [e] LNKCTL L0 (ASPM disable → clock 요청)..."
sudo setpci -s "$BDF"    "${LNKCTL_OFF}.w=0000:0003" 2>&1 || echo "    EP LNKCTL write 실패"
sudo setpci -s "$RP_BDF" "${RP_LNKCTL_OFF}.w=0000:0003" 2>&1 || echo "    RP LNKCTL write 실패"

echo "  [f] L1SS disable..."
sudo setpci -s "$BDF"    "${L1SS_CTL1_OFF}.l=00000000:0000000f" 2>&1 || echo "    EP L1SS write 실패"
sudo setpci -s "$RP_BDF" "${L1SS_CTL1_OFF}.l=00000000:0000000f" 2>&1 || echo "    RP L1SS write 실패"

echo "  [g] 100ms 대기 후 D0 진입 시도..."
sleep 0.1
for i in 1 2 3; do
    WRITE_OUT=$(sudo setpci -s "$BDF" "${PMCSR_OFF}.w=0000:0003" 2>&1); WRITE_RC=$?
    sleep 0.1
    VAL=$(sudo setpci -s "$BDF" "${PMCSR_OFF}.w" 2>&1); READ_RC=$?
    DS=$((16#${VAL:-ff} & 3))
    echo "    attempt $i: write_rc=$WRITE_RC  PMCSR=0x${VAL}  D${DS}  read_rc=$READ_RC"
    [ "$DS" -eq 0 ] && { echo "  → D0 성공 (attempt $i)"; break; }
    [ "$i" -eq 3 ] && echo "  → D0 실패"
done

echo ""
echo "  [h] 최종 상태 확인..."
VAL_PMCSR=$(sudo setpci -s "$BDF" "${PMCSR_OFF}.w" 2>&1)
VAL_LNKCTL=$(sudo setpci -s "$BDF" "${LNKCTL_OFF}.w" 2>&1)
VAL_L1SS=$(sudo setpci -s "$BDF" "${L1SS_CTL1_OFF}.l" 2>&1)
echo "    PMCSR   = 0x${VAL_PMCSR}  (D$((16#${VAL_PMCSR:-f} & 3)))"
echo "    LNKCTL  = 0x${VAL_LNKCTL}  (ASPM bits=$((16#${VAL_LNKCTL:-0} & 3)))"
echo "    L1SS    = 0x${VAL_L1SS}"
echo ""
echo "=== 진단 완료 ==="
