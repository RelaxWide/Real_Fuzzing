#!/bin/sh
# 실행 환경이 최신인지 3초 만에 확인한다.
# "인자를 인식 못 한다" 는 지금까지 전부 구버전 체크아웃이 원인이었다(3회).
cd "$(dirname "$0")" || exit 1
echo "── 커밋"
git log --oneline -1 2>/dev/null || echo "  (git 저장소가 아니다 — 파일만 복사한 환경?)"
echo "── 미반영 로컬 수정 (있으면 git pull 이 거부된다)"
git status --short . 2>/dev/null | head || true
echo "── 파일 버전"
python3 sfe76_link.py --help >/dev/null 2>&1
python3 -c "import sfe76_link as s; print('  sfe76_link  ', s.VERSION, ' API_LEVEL=', s.API_LEVEL)" 2>&1
python3 probe_ap_raw.py --version 2>&1 | sed 's/^/  /'
echo "── 기대값: API_LEVEL >= 3, probe_ap_raw >= 2026-08-11.5"
