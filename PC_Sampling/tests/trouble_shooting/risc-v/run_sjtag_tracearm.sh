#!/usr/bin/env bash
# Phase 0 arm wrapper — 고정 커맨드(sudoers NOPASSWD 용).
#   TE enable(StallEna=0=무침습) + 버퍼 클리어 + Wptr 베이스라인 기록.
#   이후 대상 동작(명령 1개 등)을 실행하고 run_sjtag_tracedelta.sh 로 측정.
#
# 사용:  sudo ./run_sjtag_tracearm.sh [CORE]     # CORE 기본 0 (TE=te_base+0x1000*CORE)
#
# ★ 전제: 같은 전원사이클에서 이미 SJTAG 인증됨(AUTH_PASS latch). 안 됐으면 먼저
#   sudo ./run_debug.sh 로 인증. base/tool 은 sjtag_addrs.json 의 "runtime" 에서 읽음.
#
# sudoers 예(비루트 퍼저가 무암호 호출):
#   fuzzer ALL=(root) NOPASSWD: /home/ssd/gdbfuzz/PC_Sampling/risc-v/run_sjtag_tracearm.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

CORE="${1:-0}"
[[ "$CORE" =~ ^[0-7]$ ]] || { echo "CORE 는 0..7 정수여야 함 (받음: $CORE)" >&2; exit 2; }

exec python3 "$DIR/sjtag_unlock.py" --power both --trace-arm --trace-core "$CORE"
