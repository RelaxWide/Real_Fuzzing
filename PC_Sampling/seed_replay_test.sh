#!/usr/bin/env bash
# seed_replay_test.sh
# 퍼저의 _generate_default_seeds() 초기 시드를 NVMe passthru로 직접 실행하여
# 모두 정상 응답(rc=0)을 반환하는지 확인한다.
#
# 사용법:
#   sudo ./seed_replay_test.sh [옵션]
#
# 옵션:
#   -d DEVICE    NVMe 장치          (기본: /dev/nvme0)
#   -n NAMESPACE NVMe 네임스페이스  (기본: 1)
#   -t TIMEOUT   명령 타임아웃(초)  (기본: 10)
#   -v           상세 출력 (nvme 명령어 전체 표시)
#   -h           도움말

set -uo pipefail

DEVICE="/dev/nvme0"
NAMESPACE=1
TIMEOUT=10
VERBOSE=0

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'

usage() { sed -n 's/^# \?//p' "$0" | head -16; exit 0; }

while getopts "d:n:t:vh" opt; do
    case $opt in
        d) DEVICE="$OPTARG"    ;;
        n) NAMESPACE="$OPTARG" ;;
        t) TIMEOUT="$OPTARG"   ;;
        v) VERBOSE=1           ;;
        h) usage               ;;
        *) echo "알 수 없는 옵션: -$OPTARG" >&2; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR${NC}: NVMe passthru는 root 권한이 필요합니다 (sudo 사용)"
    exit 1
fi
if ! command -v nvme &>/dev/null; then
    echo -e "${RED}ERROR${NC}: nvme-cli가 설치되지 않았습니다"; exit 1
fi
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}ERROR${NC}: python3가 필요합니다"; exit 1
fi

# ── 임시 디렉토리 (write 시드용 데이터 파일) ────────────────────────
TMPDIR_SEED=$(mktemp -d)
trap 'rm -rf "$TMPDIR_SEED"' EXIT

# ── Python: 초기 시드 목록 생성 후 JSON Lines로 출력 ────────────────
#
# 퍼저의 NVME_COMMANDS + _generate_default_seeds() 를 그대로 재현.
# 각 시드를 JSON 한 줄로 출력 → bash가 읽어서 nvme 명령 실행.
#
SEED_JSON=$(python3 - "$TMPDIR_SEED" <<'PYEOF'
import sys, json, struct, os, tempfile

tmpdir = sys.argv[1]

# ── 커맨드 정의 (fuzzer NVME_COMMANDS와 동일) ─────────────────────
#   (name, opcode, type, needs_namespace, needs_data)
COMMANDS = [
    # DEFAULT
    ("Identify",               0x06, "admin", True,  False),
    ("GetLogPage",             0x02, "admin", True,  False),
    ("GetFeatures",            0x0A, "admin", True,  False),
    ("Read",                   0x02, "io",    True,  False),
    ("Write",                  0x01, "io",    True,  True ),
    # EXTENDED
    ("SetFeatures",            0x09, "admin", True,  True ),
    ("FWDownload",             0x11, "admin", True,  True ),
    ("FWCommit",               0x10, "admin", True,  False),
    ("FormatNVM",              0x80, "admin", False, False),
    ("Sanitize",               0x84, "admin", False, False),
    ("TelemetryHostInitiated", 0x02, "admin", True,  False),
    ("Flush",                  0x00, "io",    True,  False),
    ("DatasetManagement",      0x09, "io",    True,  True ),
]
CMD_MAP = {name: (opcode, ctype, needs_ns, needs_data)
           for name, opcode, ctype, needs_ns, needs_data in COMMANDS}

# ── 시드 템플릿 (fuzzer _generate_default_seeds() 와 동일) ──────────
SEED_TEMPLATES = {
    "Identify": [
        dict(cdw10=0x01, desc="Identify Controller"),
        dict(cdw10=0x00, desc="Identify Namespace"),
        dict(cdw10=0x02, desc="Active NS ID list"),
        dict(cdw10=0x03, desc="NS Identification Descriptor list"),
    ],
    "GetLogPage": [
        dict(cdw10=(0x0F << 16) | 0x01, desc="Error Information Log (64B)"),
        dict(cdw10=(0x7F << 16) | 0x02, desc="SMART / Health Log (512B)"),
    ],
    "GetFeatures": [
        dict(cdw10=0x06, desc="Volatile Write Cache"),
        dict(cdw10=0x07, desc="Number of Queues"),
        dict(cdw10=0x0B, desc="Async Event Configuration"),
    ],
    "Read": [
        dict(cdw10=0,          cdw11=0, cdw12=0,      desc="Read LBA 0, 1 block"),
        dict(cdw10=1,          cdw11=0, cdw12=0,      desc="Read LBA 1, 1 block"),
        dict(cdw10=0,          cdw11=0, cdw12=7,      desc="Read LBA 0, 8 blocks"),
        dict(cdw10=0,          cdw11=0, cdw12=31,     desc="Read LBA 0, 32 blocks"),
        dict(cdw10=0,          cdw11=0, cdw12=127,    desc="Read LBA 0, 128 blocks"),
        dict(cdw10=0,          cdw11=0, cdw12=255,    desc="Read LBA 0, 256 blocks (128KB)"),
        dict(cdw10=0,          cdw11=0, cdw12=0xFFFF, desc="Read LBA 0, NLB max (32MB)"),
        dict(cdw10=500,        cdw11=0, cdw12=0,      desc="Read LBA 500"),
        dict(cdw10=1000,       cdw11=0, cdw12=0,      desc="Read LBA 1000"),
        dict(cdw10=5000,       cdw11=0, cdw12=0,      desc="Read LBA 5000"),
        dict(cdw10=10000,      cdw11=0, cdw12=0,      desc="Read LBA 10000"),
        dict(cdw10=0,          cdw11=0, cdw12=(1<<14), desc="Read LBA 0, FUA"),
        dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0, desc="Read LBA 4G (OOR)"),
        dict(cdw10=0xFFFF0000, cdw11=0xFFFFFFFF, cdw12=0, desc="Read SLBA 64-bit max (OOR)"),
    ],
    "Write": [
        dict(cdw10=0,     cdw11=0, cdw12=0,       data=b'\x00'*512,       desc="Write LBA 0, zeros"),
        dict(cdw10=0,     cdw11=0, cdw12=0,       data=b'\xAA'*512,       desc="Write LBA 0, 0xAA"),
        dict(cdw10=0,     cdw11=0, cdw12=0,       data=b'\xFF'*512,       desc="Write LBA 0, 0xFF"),
        dict(cdw10=0,     cdw11=0, cdw12=0,       data=bytes(range(256))*2, desc="Write LBA 0, 0x00-0xFF"),
        dict(cdw10=0,     cdw11=0, cdw12=7,       data=b'\x00'*(8*512),   desc="Write LBA 0, 8 blocks"),
        dict(cdw10=0,     cdw11=0, cdw12=31,      data=b'\x00'*(32*512),  desc="Write LBA 0, 32 blocks"),
        dict(cdw10=0,     cdw11=0, cdw12=127,     data=b'\x00'*(128*512), desc="Write LBA 0, 128 blocks"),
        dict(cdw10=0,     cdw11=0, cdw12=255,     data=b'\x00'*(256*512), desc="Write LBA 0, 256 blocks"),
        dict(cdw10=500,   cdw11=0, cdw12=0,       data=b'\x00'*512,       desc="Write LBA 500"),
        dict(cdw10=1000,  cdw11=0, cdw12=0,       data=b'\x00'*512,       desc="Write LBA 1000"),
        dict(cdw10=5000,  cdw11=0, cdw12=0,       data=b'\x00'*512,       desc="Write LBA 5000"),
        dict(cdw10=10000, cdw11=0, cdw12=0,       data=b'\x00'*512,       desc="Write LBA 10000"),
        dict(cdw10=0,     cdw11=0, cdw12=(1<<14), data=b'\x00'*512,       desc="Write LBA 0, FUA"),
        dict(cdw10=0x00000000, cdw11=0x00000001, cdw12=0, data=b'\x00'*512, desc="Write LBA 4G (OOR)"),
        dict(cdw10=0xFFFF0000, cdw11=0xFFFFFFFF, cdw12=0, data=b'\x00'*512, desc="Write SLBA 64-bit max (OOR)"),
    ],
    "SetFeatures": [
        dict(cdw10=0x07, cdw11=0x00010001, desc="Number of Queues (1 SQ + 1 CQ)"),
    ],
    "FWDownload": [
        dict(cdw10=0xFF, cdw11=0, data=b'\x00'*1024, desc="FW Download offset=0, 1KB"),
    ],
    "FWCommit": [
        dict(cdw10=0x01, desc="Commit Action 1, Slot 0"),
        dict(cdw10=0x09, desc="Commit Action 1, Slot 1"),
    ],
    "FormatNVM": [
        dict(cdw10=0x00, desc="Format LBAF 0, no secure erase"),
    ],
    "Sanitize": [
        dict(cdw10=0x01, desc="Block Erase"),
    ],
    "TelemetryHostInitiated": [
        dict(cdw10=(0x1FF << 16) | 0x07, desc="Telemetry Host-Initiated Log"),
    ],
    "Flush": [
        dict(desc="Flush (no parameters)"),
    ],
    "DatasetManagement": [
        dict(cdw10=0, cdw11=0x04,
             data=struct.pack('<IIIII', 0, 0, 0, 0, 8),
             desc="TRIM LBA 0, 8 blocks"),
    ],
}

MAX_DATA_BUF = 65536
ADMIN_FIXED_RESPONSE = {"Identify": 4096, "GetFeatures": 4096, "TelemetryHostInitiated": 4096}
WRITE_CMDS = {"Write", "FWDownload", "DatasetManagement"}

seeds = []
seed_idx = 0

for cmd_name, templates in SEED_TEMPLATES.items():
    if cmd_name not in CMD_MAP:
        continue
    opcode, ctype, needs_ns, needs_data = CMD_MAP[cmd_name]

    for tmpl in templates:
        cdw10 = tmpl.get("cdw10", 0)
        cdw11 = tmpl.get("cdw11", 0)
        cdw12 = tmpl.get("cdw12", 0)
        cdw13 = tmpl.get("cdw13", 0)
        cdw14 = tmpl.get("cdw14", 0)
        cdw15 = tmpl.get("cdw15", 0)
        data  = tmpl.get("data",  b"")
        desc  = tmpl.get("desc",  cmd_name)

        # data_len + write_direction (fuzzer _send_nvme_command 동일 로직)
        is_write = cmd_name in WRITE_CMDS
        write_direction = False
        data_len = 0

        if is_write and len(data) > 0:
            data_len = min(len(data), MAX_DATA_BUF)
            write_direction = True
        elif ctype == "io" and cmd_name not in ("Flush", "DatasetManagement"):
            nlb = cdw12 & 0xFFFF
            data_len = min(max(512, (nlb + 1) * 512), MAX_DATA_BUF)
        elif cmd_name == "GetLogPage":
            numdl = (cdw10 >> 16) & 0x7FF
            data_len = min(max(4, (numdl + 1) * 4), MAX_DATA_BUF)
        elif cmd_name in ADMIN_FIXED_RESPONSE:
            data_len = ADMIN_FIXED_RESPONSE[cmd_name]

        # write 데이터 파일 준비
        data_file = ""
        if write_direction and data_len > 0:
            data_file = os.path.join(tmpdir, f"seed_{seed_idx}.bin")
            with open(data_file, "wb") as f:
                f.write(data[:data_len])

        seeds.append({
            "idx":       seed_idx,
            "cmd":       cmd_name,
            "opcode":    opcode,
            "type":      ctype,
            "needs_ns":  needs_ns,
            "cdw10": cdw10, "cdw11": cdw11, "cdw12": cdw12,
            "cdw13": cdw13, "cdw14": cdw14, "cdw15": cdw15,
            "data_len":  data_len,
            "write":     write_direction,
            "data_file": data_file,
            "desc":      desc,
        })
        seed_idx += 1

for s in seeds:
    print(json.dumps(s))
PYEOF
)

if [[ -z "$SEED_JSON" ]]; then
    echo -e "${RED}ERROR${NC}: 시드 생성 실패"
    exit 1
fi

TOTAL=$(echo "$SEED_JSON" | wc -l)

echo "════════════════════════════════════════════════"
echo "  Initial Seed Replay Test (default seeds)"
echo "════════════════════════════════════════════════"
printf "  Device    : %s\n"  "$DEVICE"
printf "  Namespace : %s\n"  "$NAMESPACE"
printf "  Timeout   : %ss\n" "$TIMEOUT"
printf "  시드 수   : %d개\n" "$TOTAL"
echo "════════════════════════════════════════════════"
echo ""

PASS=0; FAIL=0

while IFS= read -r line; do
    # JSON 파싱
    read -r idx cmd opcode ctype needs_ns cdw10 cdw11 cdw12 cdw13 cdw14 cdw15 \
             data_len write data_file desc <<< "$(python3 -c "
import json, sys
s = json.loads(sys.stdin.read())
print(s['idx'], s['cmd'], s['opcode'], s['type'], int(s['needs_ns']),
      s['cdw10'], s['cdw11'], s['cdw12'], s['cdw13'], s['cdw14'], s['cdw15'],
      s['data_len'], int(s['write']), repr(s['data_file']), repr(s['desc']))
" <<< "$line")"

    # passthru 타입 / 타겟 장치
    if [[ "$ctype" == "admin" ]]; then
        passthru="admin-passthru"
        target="$DEVICE"
    else
        passthru="io-passthru"
        target="${DEVICE}n${NAMESPACE}"
    fi

    # nsid
    if [[ "$needs_ns" == "1" ]]; then
        nsid="$NAMESPACE"
    else
        nsid="0"
    fi

    # nvme 명령 구성
    nvme_cmd="nvme $passthru $target"
    nvme_cmd+=" --opcode=$(python3 -c "print(hex($opcode))")"
    nvme_cmd+=" --namespace-id=$nsid"
    nvme_cmd+=" --cdw10=$(python3 -c "print(hex($cdw10))")"
    nvme_cmd+=" --cdw11=$(python3 -c "print(hex($cdw11))")"
    nvme_cmd+=" --cdw12=$(python3 -c "print(hex($cdw12))")"
    nvme_cmd+=" --cdw13=$(python3 -c "print(hex($cdw13))")"
    nvme_cmd+=" --cdw14=$(python3 -c "print(hex($cdw14))")"
    nvme_cmd+=" --cdw15=$(python3 -c "print(hex($cdw15))")"
    nvme_cmd+=" --timeout=$(( TIMEOUT * 1000 ))"

    if [[ "$data_len" -gt 0 ]]; then
        nvme_cmd+=" --data-len=$data_len"
        if [[ "$write" == "1" ]]; then
            # data_file 은 repr() 로 감싸져 있으므로 strip
            real_file=$(python3 -c "print($data_file)")
            nvme_cmd+=" --input-file=$real_file -w"
        else
            nvme_cmd+=" -r"
        fi
    fi

    label=$(printf "[%3d] %-24s %s" "$idx" "$cmd" "$(python3 -c "print($desc)")")

    [[ $VERBOSE -eq 1 ]] && printf "${CYN}[CMD]${NC} %s\n" "$nvme_cmd"

    out=$(timeout "${TIMEOUT}s" bash -c "$nvme_cmd" 2>&1) && rc=0 || rc=$?

    if [[ $rc -eq 0 ]]; then
        printf "${GRN}[PASS]${NC} %s\n" "$label"
        ((PASS++)) || true
    elif [[ $rc -eq 124 ]]; then
        printf "${YEL}[TOUT]${NC} %s  — timeout\n" "$label"
        [[ $VERBOSE -eq 1 ]] && printf "       CMD: %s\n" "$nvme_cmd"
        ((FAIL++)) || true
    else
        status=$(printf '%s' "$out" | grep -oP 'NVMe status:.*' | head -1 || true)
        printf "${RED}[FAIL]${NC} %s  rc=%d  %s\n" "$label" "$rc" "$status"
        [[ $VERBOSE -eq 1 ]] && printf "       CMD: %s\n       OUT: %s\n" \
            "$nvme_cmd" "$(printf '%s' "$out" | head -2 | tr '\n' '|')"
        ((FAIL++)) || true
    fi

done <<< "$SEED_JSON"

echo ""
echo "════════════════════════════════════════════════"
echo "  결과 요약"
echo "════════════════════════════════════════════════"
printf "  전체  : %d\n"        "$TOTAL"
printf "  ${GRN}PASS${NC}  : %d\n"  "$PASS"
printf "  ${RED}FAIL${NC}  : %d\n"  "$FAIL"
echo "════════════════════════════════════════════════"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n  ${RED}실패한 시드가 있습니다. -v 옵션으로 상세 확인하세요.${NC}"
    exit 1
else
    echo -e "\n  ${GRN}모든 초기 시드가 PASS를 반환했습니다.${NC}"
    exit 0
fi
