#!/bin/bash
# PMCSR D3hot ↔ D0 직접 진단 스크립트
# 퍼저가 내부에서 하는 setpci 시퀀스를 수동으로 재현

BDF="0000:02:00.0"
set -e

echo "=== PCIe PM 진단: $BDF ==="
echo ""

# 1. PM capability offset 탐지
echo "[1] PM Capability offset 탐지..."
PM_CAP=$(sudo lspci -vvv -s "$BDF" 2>/dev/null | grep -i "Power Management" | grep -oP '\[\K[0-9a-fA-F]+' | head -1)
if [ -z "$PM_CAP" ]; then
    echo "  ERROR: PM capability 탐지 실패"
    exit 1
fi
PM_CAP_DEC=$((16#$PM_CAP))
PMCSR_OFF=$((PM_CAP_DEC + 4))
PMCSR_HEX=$(printf "0x%x" $PMCSR_OFF)
echo "  PM cap offset = 0x${PM_CAP}  →  PMCSR offset = ${PMCSR_HEX}"
echo ""

# 2. 현재 PMCSR 읽기
echo "[2] 현재 PMCSR 값..."
VAL=$(sudo setpci -s "$BDF" "${PMCSR_HEX}.w" 2>&1)
echo "  PMCSR = 0x${VAL}  (bits[1:0]=$((16#${VAL:-0} & 3)) → D$((16#${VAL:-0} & 3)))"
echo ""

# 3. D3hot 진입
echo "[3] D3hot 진입 시도..."
sudo setpci -s "$BDF" "${PMCSR_HEX}.w=0003:0003"
RC=$?
echo "  setpci write rc=$RC"
sleep 0.05
VAL=$(sudo setpci -s "$BDF" "${PMCSR_HEX}.w" 2>&1)
echo "  PMCSR readback = 0x${VAL}  (D$((16#${VAL:-0} & 3)))"
echo ""

# 4. 100ms 대기 후 D0 복귀
echo "[4] 100ms 대기 후 D0 진입 시도..."
sleep 0.1
for attempt in 1 2 3; do
    echo "  attempt $attempt: setpci write..."
    sudo setpci -s "$BDF" "${PMCSR_HEX}.w=0000:0003"
    RC=$?
    echo "    write rc=$RC"
    sleep 0.1
    VAL=$(sudo setpci -s "$BDF" "${PMCSR_HEX}.w" 2>&1)
    DSTATE=$((16#${VAL:-ff} & 3))
    echo "    PMCSR readback = 0x${VAL}  (D${DSTATE})"
    if [ "$DSTATE" -eq 0 ]; then
        echo "  → D0 진입 성공 (attempt $attempt)"
        break
    fi
    if [ "$attempt" -eq 3 ]; then
        echo "  → D0 진입 실패 (3회 모두 실패)"
    fi
done
echo ""

# 5. LNKCTL 현재 상태
echo "[5] LNKCTL 현재 상태..."
CAP_OFF=$(sudo lspci -vvv -s "$BDF" 2>/dev/null | grep -i "Express.*Endpoint\|PCI Express" | grep -oP '\[\K[0-9a-fA-F]+' | head -1)
if [ -n "$CAP_OFF" ]; then
    LNKCTL_OFF=$(printf "0x%x" $((16#$CAP_OFF + 0x10)))
    LNK=$(sudo setpci -s "$BDF" "${LNKCTL_OFF}.w" 2>&1)
    echo "  LNKCTL = 0x${LNK}  (ASPM bits[1:0]=$((16#${LNK:-0} & 3)))"
else
    echo "  PCIe Express cap 탐지 실패"
fi
echo ""

echo "=== 진단 완료 ==="
