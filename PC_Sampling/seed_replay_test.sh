#!/usr/bin/env bash
# seed_replay_test.sh
# corpus / seed 디렉토리의 파일들을 실제 NVMe passthru로 재실행하여
# 모두 rc=0(pass)를 반환하는지 확인한다.
#
# 사용법:
#   sudo ./seed_replay_test.sh [옵션]
#
# 옵션:
#   -d DEVICE      NVMe 장치 (기본: /dev/nvme0)
#   -c CORPUS_DIR  corpus 디렉토리 (기본: ./output/corpus)
#   -n NAMESPACE   NVMe 네임스페이스 ID (기본: 1)
#   -t TIMEOUT     명령 타임아웃 초 (기본: 10)
#   -v             상세 출력 (명령어 전체 표시)
#   -h             도움말

set -uo pipefail

# ── 기본값 ──────────────────────────────────────────────────────────
DEVICE="/dev/nvme0"
CORPUS_DIR="./output/corpus"
NAMESPACE=1
TIMEOUT=10
VERBOSE=0

# ── 색상 ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
CYN='\033[0;36m'
NC='\033[0m'

usage() {
    grep '^#' "$0" | sed 's/^# \?//' | head -20
    exit 0
}

while getopts "d:c:n:t:vh" opt; do
    case $opt in
        d) DEVICE="$OPTARG"     ;;
        c) CORPUS_DIR="$OPTARG" ;;
        n) NAMESPACE="$OPTARG"  ;;
        t) TIMEOUT="$OPTARG"    ;;
        v) VERBOSE=1            ;;
        h) usage                ;;
        *) echo "알 수 없는 옵션: -$OPTARG" >&2; exit 1 ;;
    esac
done

# ── 사전 검사 ───────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR${NC}: NVMe passthru는 root 권한이 필요합니다 (sudo 사용)"
    exit 1
fi

if ! command -v nvme &>/dev/null; then
    echo -e "${RED}ERROR${NC}: nvme-cli가 설치되지 않았습니다"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}ERROR${NC}: python3가 필요합니다"
    exit 1
fi

if [[ ! -d "$CORPUS_DIR" ]]; then
    echo -e "${RED}ERROR${NC}: 디렉토리가 없습니다: $CORPUS_DIR"
    exit 1
fi

# ── Python 헬퍼: JSON 파싱 + nvme 명령 구성 ─────────────────────────
# 각 파일마다 python3를 호출해 JSON을 읽고 nvme 커맨드를 stdout으로 출력한다.
build_cmd() {
    local data_file="$1"
    local json_file="$2"

    python3 - "$data_file" "$json_file" "$DEVICE" "$NAMESPACE" "$TIMEOUT" <<'PYEOF'
import sys, json, os

data_file, json_file, device, namespace, timeout_s = sys.argv[1:]
namespace  = int(namespace)
timeout_ms = int(float(timeout_s) * 1000)

MAX_DATA_BUF = 65536

# --- Write-direction 명령 집합 (fuzzer와 동일 기준) ---
WRITE_CMDS = {
    "Write", "WriteLong", "WriteZeroes", "Compare",
    "SetFeatures", "NsAttach", "NsManagement",
    "FirmwareDownload", "SecuritySend",
}
# Admin 고정 read 크기
ADMIN_FIXED_RESPONSE = {
    "Identify": 4096,
    "GetFeatures": 4096,
    "TelemetryHostInitiated": 4096,
}

try:
    with open(json_file) as f:
        meta = json.load(f)
except Exception as e:
    print(f"ERROR:JSON parse failed: {e}", file=sys.stderr)
    sys.exit(1)

cmd_name   = meta.get("command", "")
cmd_type   = meta.get("type", "admin")          # "admin" | "io"
force_admin = meta.get("force_admin")           # True | False | None

opcode_str  = meta.get("opcode_override") or meta.get("opcode", "0x0")
nsid_str    = meta.get("nsid_override")   or hex(namespace)
opcode      = int(opcode_str, 16)
nsid        = int(nsid_str,   16)

cdw2  = meta.get("cdw2",  0)
cdw3  = meta.get("cdw3",  0)
cdw10 = meta.get("cdw10", 0)
cdw11 = meta.get("cdw11", 0)
cdw12 = meta.get("cdw12", 0)
cdw13 = meta.get("cdw13", 0)
cdw14 = meta.get("cdw14", 0)
cdw15 = meta.get("cdw15", 0)

# passthru 타입 결정 (fuzzer의 _send_nvme_cmd와 동일 로직)
if force_admin is True:
    passthru = "admin-passthru"
elif force_admin is False:
    passthru = "io-passthru"
elif cmd_type == "admin":
    passthru = "admin-passthru"
else:
    passthru = "io-passthru"

# 타겟 장치
if passthru == "io-passthru":
    target = f"{device}n{namespace}"
else:
    target = device

# data_len 결정 (fuzzer의 _send_nvme_cmd와 동일 로직)
file_size = os.path.getsize(data_file)
is_write  = (cmd_name in WRITE_CMDS)
write_direction = False
data_len = 0

data_len_override = meta.get("data_len_override")
if data_len_override is not None:
    data_len = min(max(0, int(data_len_override)), MAX_DATA_BUF)
    if is_write and file_size > 0:
        write_direction = True
elif is_write and file_size > 0:
    data_len = min(file_size, MAX_DATA_BUF)
    write_direction = True
elif cmd_type == "io" and cmd_name not in ("Flush", "DatasetManagement"):
    # IO Read: NLB from CDW12[15:0]
    nlb = cdw12 & 0xFFFF
    data_len = min(max(512, (nlb + 1) * 512), MAX_DATA_BUF)
elif cmd_name == "GetLogPage":
    numdl = (cdw10 >> 16) & 0x7FF
    data_len = min(max(4, (numdl + 1) * 4), MAX_DATA_BUF)
elif cmd_name in ADMIN_FIXED_RESPONSE:
    data_len = ADMIN_FIXED_RESPONSE[cmd_name]

# 명령 구성
parts = [
    "nvme", passthru, target,
    f"--opcode={opcode:#x}",
    f"--namespace-id={nsid}",
    f"--cdw2={cdw2:#x}",   f"--cdw3={cdw3:#x}",
    f"--cdw10={cdw10:#x}", f"--cdw11={cdw11:#x}",
    f"--cdw12={cdw12:#x}", f"--cdw13={cdw13:#x}",
    f"--cdw14={cdw14:#x}", f"--cdw15={cdw15:#x}",
    f"--timeout={timeout_ms}",
]

if data_len > 0:
    parts.append(f"--data-len={data_len}")
    if write_direction:
        parts += [f"--input-file={data_file}", "-w"]
    else:
        parts.append("-r")

print(" ".join(parts))
PYEOF
}

# ── 메인 루프 ───────────────────────────────────────────────────────
echo "════════════════════════════════════════════════"
echo "  Seed Replay Test"
echo "════════════════════════════════════════════════"
printf "  Device     : %s\n" "$DEVICE"
printf "  Corpus dir : %s\n" "$CORPUS_DIR"
printf "  Namespace  : %s\n" "$NAMESPACE"
printf "  Timeout    : %ss\n" "$TIMEOUT"
echo "════════════════════════════════════════════════"
echo ""

PASS=0; FAIL=0; SKIP=0; TOTAL=0

while IFS= read -r -d '' data_file; do
    # .json 파일은 메타데이터이므로 스킵
    [[ "$data_file" == *.json ]] && continue
    [[ ! -f "$data_file" ]]      && continue

    ((TOTAL++)) || true
    filename=$(basename "$data_file")
    json_file="${data_file}.json"

    # JSON 없으면 스킵
    if [[ ! -f "$json_file" ]]; then
        printf "${YEL}[SKIP]${NC} %-52s — .json 없음\n" "$filename"
        ((SKIP++)) || true
        continue
    fi

    # nvme 명령 구성
    nvme_cmd=$(build_cmd "$data_file" "$json_file" 2>/tmp/seed_replay_err)
    if [[ $? -ne 0 || -z "$nvme_cmd" ]]; then
        err_msg=$(cat /tmp/seed_replay_err 2>/dev/null | head -1)
        printf "${YEL}[SKIP]${NC} %-52s — 명령 구성 실패: %s\n" "$filename" "$err_msg"
        ((SKIP++)) || true
        continue
    fi

    if [[ $VERBOSE -eq 1 ]]; then
        printf "${CYN}[CMD]${NC}  %s\n" "$nvme_cmd"
    fi

    # 실행
    out=$(timeout "${TIMEOUT}s" bash -c "$nvme_cmd" 2>&1)
    rc=$?

    if [[ $rc -eq 0 ]]; then
        printf "${GRN}[PASS]${NC} %-52s  rc=0\n" "$filename"
        ((PASS++)) || true
    elif [[ $rc -eq 124 ]]; then
        printf "${YEL}[TOUT]${NC} %-52s  timeout (>%ss)\n" "$filename" "$TIMEOUT"
        [[ $VERBOSE -eq 1 ]] && printf "       CMD: %s\n" "$nvme_cmd"
        ((FAIL++)) || true
    else
        # nvme-cli는 status code를 포함한 메시지를 stderr로 출력
        status_msg=$(echo "$out" | grep -oP 'NVMe status: .*' | head -1 || true)
        printf "${RED}[FAIL]${NC} %-52s  rc=%d  %s\n" "$filename" "$rc" "$status_msg"
        [[ $VERBOSE -eq 1 ]] && printf "       CMD: %s\n       OUT: %s\n" \
            "$nvme_cmd" "$(echo "$out" | head -2 | tr '\n' '|')"
        ((FAIL++)) || true
    fi

done < <(find "$CORPUS_DIR" -maxdepth 1 -type f -print0 | sort -z)

# ── 결과 요약 ───────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════"
echo "  결과 요약"
echo "════════════════════════════════════════════════"
printf "  전체   : %d\n"                  "$TOTAL"
printf "  ${GRN}PASS${NC}   : %d\n"      "$PASS"
printf "  ${RED}FAIL${NC}   : %d\n"      "$FAIL"
printf "  ${YEL}SKIP${NC}   : %d\n"      "$SKIP"
echo "════════════════════════════════════════════════"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "  실패한 시드가 있습니다."
    exit 1
else
    echo ""
    echo -e "  ${GRN}모든 시드가 PASS를 반환했습니다.${NC}"
    exit 0
fi
