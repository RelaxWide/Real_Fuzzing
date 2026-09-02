#!/usr/bin/env bash
# Ghidra headless 로 RISC-V ELF 를 분석할 수 있는 환경인지 점검한다.
#
# 사용:  ./check_ghidra.sh [ELF경로]
#        ELF 를 주면 실제 import 까지 시도한다(가장 확실한 판정).
#
# 왜 필요한가: BB/함수/콜그래프 표는 Ghidra 로 만든다(실기 objdump 는 RISC-V 를 못 푼다:
#   "can't disassemble for architecture UNKNOWN"). 그 Ghidra 가 이 환경에서 되는지,
#   그리고 RISC-V 모듈이 있는지를 먼저 확인해야 5단계 설계가 확정된다.
# ★ 출력에 주소·심볼은 찍지 않는다(개수/가부만).
set -uo pipefail

ok=0; ng=0
say()  { printf '  %-34s %s\n' "$1" "$2"; }
good() { say "$1" "✅ $2"; ok=$((ok+1)); }
bad()  { say "$1" "❌ $2"; ng=$((ng+1)); }

echo "=== Ghidra headless 환경 점검 ==="

# 1) Ghidra 설치 위치 — GHIDRA_HOME → PATH → 흔한 위치 → 리포 동봉본 순
GH=""
for c in "${GHIDRA_HOME:-}/support/analyzeHeadless" \
         "$(command -v analyzeHeadless 2>/dev/null)" \
         /opt/ghidra*/support/analyzeHeadless \
         "$HOME"/ghidra*/support/analyzeHeadless \
         /usr/share/ghidra/support/analyzeHeadless \
         "$(dirname "$0")"/../../backup/gdbfuzz_upstream/dependencies/ghidra/support/analyzeHeadless; do
  [ -n "$c" ] && [ -x "$c" ] && { GH="$c"; break; }
done
if [ -z "$GH" ]; then
  bad "analyzeHeadless" "못 찾음 — GHIDRA_HOME 을 설정하거나 Ghidra 설치 필요"
  echo; echo "  힌트: find / -name analyzeHeadless -not -path '*/proc/*' 2>/dev/null | head"
  exit 1
fi
good "analyzeHeadless" "$GH"
ROOT="$(cd "$(dirname "$GH")/.." && pwd)"

# 2) 버전
VER=$(grep -oP '(?<=application.version=).*' "$ROOT/Ghidra/application.properties" 2>/dev/null)
[ -n "$VER" ] && good "Ghidra 버전" "$VER" || bad "Ghidra 버전" "application.properties 없음"

# 3) Java
if command -v java >/dev/null 2>&1; then
  good "Java" "$(java -version 2>&1 | head -1 | tr -d '"')"
else
  bad "Java" "없음 — Ghidra 실행 불가"
fi

# 4) RISC-V 프로세서 모듈 + RV32GC 언어
if [ -d "$ROOT/Ghidra/Processors/RISCV" ]; then
  good "RISCV 프로세서 모듈" "있음"
  LD="$ROOT/Ghidra/Processors/RISCV/data/languages"
  if grep -qs 'RV32GC' "$LD"/*.ldefs; then
    good "RV32GC 언어" "있음 (A+C 포함 — RV32IMAC 코어에 적합)"
  elif grep -qs 'RV32IMC' "$LD"/*.ldefs; then
    say "RV32GC 언어" "⚠ 없음. RV32IMC 만 있음 → A(lr/sc/amo) 미해석으로 BB 가 끊길 수 있음"
    ok=$((ok+1))
  else
    bad "RV32 언어" "RV32 계열 정의를 못 찾음"
  fi
else
  bad "RISCV 프로세서 모듈" "없음 — 이 Ghidra 로는 RISC-V 분석 불가(최신 버전 필요)"
fi

# 5) 실제 import (ELF 를 준 경우) — 가장 확실한 판정
ELF="${1:-}"
if [ -n "$ELF" ]; then
  if [ ! -f "$ELF" ]; then bad "ELF" "파일 없음: $ELF"; else
    echo; echo "  --- 실제 import 시도 (수 분 걸릴 수 있음) ---"
    TMP=$(mktemp -d); LOG="$TMP/head.log"
    "$GH" "$TMP" chk -import "$ELF" -processor RISCV:LE:32:RV32GC \
          -scriptlog "$TMP/script.log" -deleteProject >"$LOG" 2>&1
    rc=$?
    if [ $rc -eq 0 ] && grep -qiE "REPORT: (Analysis|Import) succeeded|Analysis succeeded" "$LOG"; then
      good "ELF import/분석" "성공"
      # 함수 개수만 보고(심볼·주소는 출력하지 않음)
      n=$(grep -coiE "^INFO .*Function" "$LOG" 2>/dev/null || echo 0)
      say "" "(로그 라인 참고용: $n)"
    else
      bad "ELF import/분석" "실패 (rc=$rc)"
      echo "  --- 로그 마지막 15줄 ---"; tail -15 "$LOG" | sed 's/^/    /'
    fi
    rm -rf "$TMP"
  fi
else
  echo; echo "  ℹ ELF 경로를 인자로 주면 실제 분석까지 검증합니다:  $0 /path/to/core0.elf"
fi

echo; echo "=== 결과: 통과 $ok / 실패 $ng ==="
[ $ng -eq 0 ] && echo "  → headless 로 진행 가능. 5단계(ghidra_export 확장)를 headless 기준으로 설계합니다." \
              || echo "  → 위 ❌ 를 해결해야 합니다. 알려주시면 대안을 잡겠습니다."
exit $ng
