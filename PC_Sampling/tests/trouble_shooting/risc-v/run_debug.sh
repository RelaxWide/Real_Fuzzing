#!/usr/bin/env bash
# SF-E76 secure JTAG unlock → J-Link 디버그: 원스텝 오케스트레이터.
#
# 하는 일 (한 방에 connect 까지):
#   [1] SJTAG PKC 인증(AUTH_PASS)  — sjtag_unlock.py --execute
#   [2] JLinkScript 생성(json 값)  — sjtag_unlock.py --gen-jlinkscript
#   [3] J-Link connect              — JLinkExe -autoconnect 1 (실행 즉시 타깃 접속)
#
# 사용 (base/tool/word-order 는 sjtag_addrs.json 의 "runtime" 에서 읽음):
#   sudo ./run_debug.sh
#   sudo ./run_debug.sh 0x<BASE>          # base 만 override 하고 싶을 때
#
# ★ 사전 준비: sjtag_addrs.json 의 "runtime" 에 sjtag_base, sign_tool 채워둔다(1회).
#   wine 환경(WINEPREFIX 등)은 아래 기본값 사용 — 다르면 환경변수로 override.
#
# 환경변수(선택):
#   WINEPREFIX   wine prefix                 (기본: /root/.wine32)
#   JLINK        JLinkExe | JLinkGDBServer   (기본: JLinkExe = 즉시 connect)
#   JLINK_SCRIPT connect 후 자동 실행할 Commander 스크립트(halt/regs 등)
#   NO_AUTH=1    인증 건너뛰기(이미 인증됨 — 전원 안 내렸을 때)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/sf_e76.JLinkScript"
JLINK="${JLINK:-JLinkExe}"

# wine 환경 기본값(없을 때만) — 인증에 wine 서명도구 쓸 때. sudo(root) 기준 prefix.
export WINEPREFIX="${WINEPREFIX:-/root/.wine32}"
export WINEDEBUG="${WINEDEBUG:--all}"
export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-mscoree,mshtml=}"

# base 는 json runtime 에서 읽지만, 인자로 주면 그걸로 override.
BASE_ARG=()
[ -n "${1:-}" ] && BASE_ARG=(--base "$1")

if [ "${NO_AUTH:-0}" != "1" ]; then
  echo "== [1/3] SJTAG 인증 (base/tool/word-order 는 json runtime) =="
  # --execute 는 AUTH_PASS 확보해도 DM 판정으로 비-0(10/11)을 낼 수 있어 rc 로 판단.
  set +e
  python3 "$DIR/sjtag_unlock.py" "${BASE_ARG[@]}" --power both --execute
  rc=$?
  set -e
  case "$rc" in
    0|10|11) echo "  → 인증 OK (rc=$rc, AUTH_PASS 확보) — connect 로 진행" ;;
    *)       echo "  ✗ 인증 실패 (rc=$rc) — connect 중단"; exit "$rc" ;;
  esac
else
  echo "== [1/3] 인증 건너뜀 (NO_AUTH=1) =="
fi

echo "== [2/3] JLinkScript 생성 =="
python3 "$DIR/sjtag_unlock.py" --gen-jlinkscript "$SCRIPT"

echo "== [3/3] J-Link connect: $JLINK =="
# -JTAGConf -1,-1 = JTAG 체인 위치 자동감지(대화형 프롬프트 스킵).
COMMON=(-device E76 -if cJTAG -speed 10000 -JTAGConf -1,-1 -JLinkScriptFile "$SCRIPT")
case "$JLINK" in
  *GDBServer*|*gdbserver*|*GDBServerCL*)
    exec "$JLINK" "${COMMON[@]}" ;;                # GDB 서버(클라이언트 대기, 시작 시 connect)
  *)
    if [ -n "${JLINK_SCRIPT:-}" ]; then
      exec "$JLINK" "${COMMON[@]}" -autoconnect 1 -CommanderScript "$JLINK_SCRIPT"
    else
      exec "$JLINK" "${COMMON[@]}" -autoconnect 1   # 즉시 connect 후 대화형 프롬프트
    fi
    ;;
esac
