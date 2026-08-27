#!/usr/bin/env bash
# SF-E76 secure JTAG unlock → J-Link 디버그: 원스텝 오케스트레이터.
#
# 하는 일 (한 방에 connect 까지):
#   [1] SJTAG PKC 인증(AUTH_PASS)  — sjtag_unlock.py --execute
#   [2] JLinkScript 생성(json 값)  — sjtag_unlock.py --gen-jlinkscript
#   [3] J-Link connect              — JLinkExe -autoconnect 1 (실행 즉시 타깃 접속)
#       또는 JLINK=JLinkGDBServer 로 GDB 서버 기동(클라이언트 대기)
#
# 사용:
#   sudo WINEPREFIX=/root/.wine32 SIGNER=/path/signer.exe ./run_debug.sh 0x<BASE>
#   → 인증 후 JLinkExe 가 바로 connect 되어 J-Link> 프롬프트(연결됨)로 떨어진다.
#
# 환경변수(선택):
#   SIGNER       서명 .exe 경로               (필수 — 인증 시)
#   TOOL_PREFIX  서명도구 런처                (기본: wine)
#   WORD_ORDER   t32-negative | stdout        (기본: t32-negative)
#   JLINK        JLinkExe | JLinkGDBServer    (기본: JLinkExe = 즉시 connect)
#   JLINK_SCRIPT J-Link Commander 스크립트    (있으면 connect 후 그 명령들 자동 실행)
#   NO_AUTH=1    인증 건너뛰기(이미 인증됨 — 전원 안 내렸을 때)
#
# ★ 인증은 전원사이클마다 필요. 전원 내렸으면 NO_AUTH 없이(=인증 포함) 실행.
set -euo pipefail

BASE="${1:-}"
[ -n "$BASE" ] || { echo "사용: sudo ./run_debug.sh 0x<BASE>"; exit 2; }

DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_PREFIX="${TOOL_PREFIX:-wine}"
WORD_ORDER="${WORD_ORDER:-t32-negative}"
JLINK="${JLINK:-JLinkExe}"
SCRIPT="$DIR/sf_e76.JLinkScript"

if [ "${NO_AUTH:-0}" != "1" ]; then
  : "${SIGNER:?인증하려면 SIGNER=서명.exe 경로 필요 (또는 NO_AUTH=1)}"
  echo "== [1/3] SJTAG 인증 =="
  python3 "$DIR/sjtag_unlock.py" --base "$BASE" \
      --tool "$SIGNER" --tool-prefix "$TOOL_PREFIX" \
      --power both --execute --word-order "$WORD_ORDER"
else
  echo "== [1/3] 인증 건너뜀 (NO_AUTH=1) =="
fi

echo "== [2/3] JLinkScript 생성 =="
python3 "$DIR/sjtag_unlock.py" --gen-jlinkscript "$SCRIPT"

echo "== [3/3] J-Link connect: $JLINK =="
COMMON=(-device E76 -if cJTAG -speed 10000 -JLinkScriptFile "$SCRIPT")
case "$JLINK" in
  *GDBServer*|*gdbserver*|*GDBServerCL*)
    exec "$JLINK" "${COMMON[@]}" ;;              # GDB 서버(클라이언트 대기, 시작 시 타깃 connect)
  *)
    if [ -n "${JLINK_SCRIPT:-}" ]; then          # commander 스크립트로 connect+명령 자동
      exec "$JLINK" "${COMMON[@]}" -autoconnect 1 -CommanderScript "$JLINK_SCRIPT"
    else
      exec "$JLINK" "${COMMON[@]}" -autoconnect 1   # 즉시 connect 후 대화형 프롬프트
    fi
    ;;
esac
