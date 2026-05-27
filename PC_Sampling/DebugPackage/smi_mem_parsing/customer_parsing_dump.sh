#!/bin/bash
# Linux 용 customer_parsing_dump.bat 동등 wrapper.
# 원본 .bat 의 동작:
#   cd /d %~dp0
#   ..\python\python.exe customer_parsing_dump.py "%~f1"
#
# 차이점 (Linux):
#   - ..\python\python.exe  → 시스템 python3 사용
#   - PYTHONPATH 에 DebugPackage/ 추가 (parser 의 'from module.share import ...'
#     가 DebugPackage/module/ 을 찾을 수 있도록)
#
# Usage: ./customer_parsing_dump.sh <dump_file_path>

set -e

# 1) Script 위치로 cd (.bat 의 'cd /d %~dp0' 동치)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# 2) PYTHONPATH: parser 가 'from module.share import ...' 형태로 import 하는데
#    module/ 패키지가 SCRIPT_DIR 의 상위 DebugPackage/ 에 있음 → 명시 추가.
DEBUG_PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
export PYTHONPATH="${DEBUG_PKG_DIR}:${PYTHONPATH:-}"

# 3) 인자 검증
if [ -z "${1:-}" ]; then
    echo "[customer_parsing_dump.sh] usage: $0 <dump_file_path>" >&2
    exit 2
fi
if [ ! -f "$1" ]; then
    echo "[customer_parsing_dump.sh] dump file not found: $1" >&2
    exit 3
fi

# 4) Python interpreter 자동 선택:
#    a) bundled (DebugPackage/python/bin/python3) 가 있으면 우선
#    b) 시스템 python3 fallback
PY_BIN="python3"
if [ -x "${DEBUG_PKG_DIR}/python/bin/python3" ]; then
    PY_BIN="${DEBUG_PKG_DIR}/python/bin/python3"
elif [ -x "${DEBUG_PKG_DIR}/python/bin/python" ]; then
    PY_BIN="${DEBUG_PKG_DIR}/python/bin/python"
fi

# 5) 실행 — argv[1] = dump 파일 절대 경로
exec "${PY_BIN}" customer_parsing_dump.py "$1"
