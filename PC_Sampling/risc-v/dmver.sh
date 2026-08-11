#!/bin/sh
# DM version 오라클로 **AP × CoreBase** 를 훑는다.
#
#   J-Link 이 dmstatus 를 읽고 version 을 로그에 찍는다.
#   유효: 2(0.13) / 3(1.0).
#   14 = 0xEAFFFFFE(버스 기본값)를 읽었다는 뜻 = 그 조합은 아니다.
#
# ★ 이전 판은 AP 를 index 0(APBAP1)으로 고정했다. APB-AP 는 네 개고
#   AHB/AXI 도 있다. 주소를 더 찍기 전에 **AP 부터 바꿔봐야 한다.**
#
# 사용:
#   sudo ./dmver.sh                       기본 (AP 0,1,4,5 × base 2종)
#   sudo ./dmver.sh --aps 0,1,2,3,4,5
#   sudo ./dmver.sh --bases 0x81480000,0x81490000
cd "$(dirname "$0")" || exit 1

APS="0,1,4,5"
BASES="0x81480000,0x81481000"
while [ $# -gt 0 ]; do
  case "$1" in
    --aps)   APS="$2";   shift 2 ;;
    --bases) BASES="$2"; shift 2 ;;
    *) echo "알 수 없는 인자: $1"; exit 1 ;;
  esac
done

echo "AP  base         DMver  spec          (14 = 그 조합 아님)"
echo "--------------------------------------------------------"
hit=0
for ap in $(echo "$APS" | tr ',' ' '); do
  # AP 타입에 맞는 셀렉터를 고른다: 0,1,4,5=APB / 3=AHB / 2=AXI(셀렉터 없음)
  sel=APB
  [ "$ap" = "3" ] && sel=AHB
  [ "$ap" = "2" ] && continue          # AXI 용 셀렉터는 J-Link 에 없다
  for b in $(echo "$BASES" | tr ',' ' '); do
    out=$(python3 try_jlinkscript.py --dumplog --log-ap "$ap" --log-sel "$sel" \
          --log-base "$b" --logfile "/tmp/jl_${ap}_$b.log" 2>&1)
    ver=$(printf '%s' "$out" | grep -o 'DM version [0-9]*' | head -1 | awk '{print $3}')
    spec=$(printf '%s' "$out" | grep -o 'Debug Spec\. Version:[^,]*' | head -1 \
           | sed 's/.*: *//')
    [ -z "$ver" ] && ver="-"
    [ -z "$spec" ] && spec="-"
    mark=""
    case "$ver" in 2|3) mark="  <<<< 유효 DM. 여기다"; hit=1 ;; esac
    printf '%-3s %-12s %-6s %-13s%s\n' "$ap($sel)" "$b" "$ver" "$spec" "$mark"
  done
done

echo
if [ "$hit" = "1" ]; then
  echo "★ ver 2/3 인 줄의 AP 와 base 가 답이다. 정본 스크립트를 그 값으로 굳힌다."
else
  echo "전부 14/-  → 다음 순서로 넓힌다:"
  echo "  1) AHB-AP:   sudo ./dmver.sh --aps 3"
  echo "  2) base 확대: sudo ./dmver.sh --aps 0,1,4,5 --bases 0x81490000,0x81400000,0x0"
  echo "  3) 그래도 없으면 DM 위치는 실측으로 못 찾는다 → ASK.md"
fi
