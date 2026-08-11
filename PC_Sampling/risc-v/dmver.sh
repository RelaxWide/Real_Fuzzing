#!/bin/sh
# --dmver 인자가 없는 환경에서도 같은 측정을 한다.
#   base 후보를 하나씩 --dumplog 으로 돌리고 로그에서 DM version 만 뽑는다.
#   유효: 2(0.13) / 3(1.0).   14 = 0xEAFFFFFE 를 읽음 = 그 주소 아님.
#
# 사용:  sudo ./dmver.sh                    (기본 후보)
#        sudo ./dmver.sh 0x81490000 0x814A0000   (후보 직접 지정)
cd "$(dirname "$0")" || exit 1

BASES="$*"
[ -z "$BASES" ] && BASES="0x81480000 0x81481000 0x81482000 0x81484000 0x81488000
0x81490000 0x814A0000 0x81400000 0x81500000 0x80000000 0x0"

printf '%-12s %-10s %s\n' "base" "DMversion" "spec"
for b in $BASES; do
  out=$(python3 try_jlinkscript.py --dumplog --log-base "$b" \
        --logfile "/tmp/jl_$b.log" 2>&1)
  ver=$(printf '%s' "$out" | grep -o 'DM version [0-9]*' | head -1 | awk '{print $3}')
  spec=$(printf '%s' "$out" | grep -o 'Debug Spec\. Version:[^,]*' | head -1 \
         | sed 's/.*: *//')
  [ -z "$ver" ] && ver="-"
  [ -z "$spec" ] && spec="-"
  mark=""
  case "$ver" in 2|3) mark="   <<<< 유효 DM. 여기다" ;; esac
  printf '%-12s %-10s %s%s\n' "$b" "$ver" "$spec" "$mark"
done

echo
echo "ver 2 또는 3 이 나온 base 가 정답이다. 전부 14 면 후보를 넓힌다:"
echo "  sudo ./dmver.sh 0x81490000 0x814B0000 0x81600000 ..."
echo "AP 를 바꿔 보려면 try_jlinkscript.py --dumplog --log-ap 1 --log-base <addr>"
