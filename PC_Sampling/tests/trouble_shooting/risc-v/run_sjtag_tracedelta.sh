#!/usr/bin/env bash
# Phase 0 delta wrapper — 고정 커맨드(sudoers NOPASSWD 용).
#   run_sjtag_tracearm.sh 이후 생성된 트레이스 바이트 수 / overflow 여부 리턴.
#   판정: delta ≪ 32KB → per-op 정확 캡처 가능(→Phase A) / overflow → 필터·트리거 필요.
#
# 사용:  sudo ./run_sjtag_tracedelta.sh
#
# ★ 전제: 직전에 run_sjtag_tracearm.sh 로 arm 됨(.trace_state.json 존재). 같은 전원사이클.
#
# sudoers 예:
#   fuzzer ALL=(root) NOPASSWD: /home/ssd/gdbfuzz/PC_Sampling/risc-v/run_sjtag_tracedelta.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

exec python3 "$DIR/sjtag_unlock.py" --power both --trace-delta
