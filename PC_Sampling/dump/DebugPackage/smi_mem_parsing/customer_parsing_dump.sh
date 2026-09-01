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

# 2) PYTHONPATH 구성:
#    - DebugPackage/                            ← parser 의 'from module.share import ...'
#    - DebugPackage/python/Lib/site-packages    ← bundled Windows Python 의 pure-Python
#         third-party 패키지 (intelhex 등) 재사용. Linux 의 시스템 python3 도 .py 만
#         있으면 import 가능 (C 확장 .pyd 는 못 씀 — 그 경우 pip3 로 별도 설치 필요).
DEBUG_PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUNDLED_SITE_PACKAGES="${DEBUG_PKG_DIR}/python/Lib/site-packages"
if [ -d "${BUNDLED_SITE_PACKAGES}" ]; then
    export PYTHONPATH="${DEBUG_PKG_DIR}:${BUNDLED_SITE_PACKAGES}:${PYTHONPATH:-}"
else
    export PYTHONPATH="${DEBUG_PKG_DIR}:${PYTHONPATH:-}"
fi

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
