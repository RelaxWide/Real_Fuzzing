#!/bin/sh
# 실행 환경이 최신인지 3초 만에 확인한다.
# "인자를 인식 못 한다" 는 지금까지 전부 구버전 체크아웃이 원인이었다(4회).
cd "$(dirname "$0")" || exit 1

echo "── 커밋"
git log --oneline -1 2>/dev/null || echo "  (git 저장소가 아니다 — 파일만 복사한 환경?)"

echo "── 미반영 로컬 수정 (있으면 git pull 이 거부된다)"
st=$(git status --short . 2>/dev/null | grep -v '^??')
if [ -n "$st" ]; then
  echo "$st"
  echo "  ★ 이게 원인이다.  git checkout -- <파일>  후  git pull"
else
  echo "  없음"
fi

echo "── 파일 버전 (전 도구)"
python3 -c "import sfe76_link as s; print('  %-22s %s  API_LEVEL=%d' % ('sfe76_link', s.VERSION, s.API_LEVEL))" 2>&1
for f in try_jlinkscript.py probe_ap_raw.py probe_cjtag_mode.py probe_rom_dm.py \
         probe_alias_power.py find_dm.py; do
  [ -f "$f" ] || continue
  v=$(python3 "$f" --version 2>/dev/null | head -1)
  [ -z "$v" ] && v="(--version 없음 = 구버전)"
  printf "  %-22s %s\n" "${f%.py}" "$v"
done

echo "── 기대값 (2026-08-11 기준)"
echo "  sfe76_link       API_LEVEL >= 5"
echo "  try_jlinkscript  >= 2026-08-11.24   (--dmver 가 여기서 들어왔다)"
echo "  probe_ap_raw     >= 2026-08-11.6"
