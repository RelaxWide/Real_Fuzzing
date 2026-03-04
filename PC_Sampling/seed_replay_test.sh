#!/usr/bin/env bash
# seed_replay_test.sh
# 퍼저의 _generate_default_seeds() 초기 시드를 NVMe passthru로 직접 실행하여
# 정상 응답(rc=0)을 반환하는지 확인한다.
#
# 사용법:
#   sudo ./seed_replay_test.sh [옵션]
#
# 옵션:
#   -d DEVICE        NVMe 장치                (기본: /dev/nvme0)
#   -n NAMESPACE     NVMe 네임스페이스 ID     (기본: 1)
#   -t TIMEOUT       명령 타임아웃(초)        (기본: 10)
#   -f FIRMWARE.BIN  FWDownload/FWCommit용 펌웨어 바이너리 (기본: ./FW.bin)
#   -s FW_SLOT       FWCommit 슬롯 번호       (기본: 1)
#   -x XFER_SIZE     FWDownload 청크 크기(바이트, 기본: 32768 = nvme fw-download -x 32768)
#   -v               상세 출력 (nvme 명령어 전체 표시)
#   -h               도움말
#
# 결과 분류:
#   [PASS]  rc=0, 정상
#   [FAIL]  rc≠0, 예상치 못한 실패
#   [XFAIL] rc≠0, 예상된 실패 (OOR, 사전조건 없음 등) — FAIL 카운트에 미포함
#   [SKIP]  실행 안 함 (FW 없이 FW 관련 커맨드, 위험 동작 등)

set -uo pipefail

DEVICE="/dev/nvme0"
NAMESPACE=1
TIMEOUT=10
FW_BIN="FW.bin"
FW_SLOT=1
FW_XFER=32768
VERBOSE=0

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; CYN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

usage() { sed -n 's/^# \?//p' "$0" | head -22; exit 0; }

while getopts "d:n:t:f:s:vh" opt; do
    case $opt in
        d) DEVICE="$OPTARG"    ;;
        n) NAMESPACE="$OPTARG" ;;
        t) TIMEOUT="$OPTARG"   ;;
        f) FW_BIN="$OPTARG"    ;;
        s) FW_SLOT="$OPTARG"   ;;
        x) FW_XFER="$OPTARG"   ;;
        v) VERBOSE=1           ;;
        h) usage               ;;
        *) echo "알 수 없는 옵션: -$OPTARG" >&2; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR${NC}: NVMe passthru는 root 권한이 필요합니다 (sudo 사용)"
    exit 1
fi
for bin in nvme python3; do
    command -v "$bin" &>/dev/null || { echo -e "${RED}ERROR${NC}: $bin 가 없습니다"; exit 1; }
done
if [[ ! -f "$FW_BIN" ]]; then
    echo -e "${RED}ERROR${NC}: 펌웨어 파일이 없습니다: $FW_BIN (FW.bin을 현재 디렉토리에 두거나 -f로 지정)"; exit 1
fi

TMPDIR_SEED=$(mktemp -d)
trap 'rm -rf "$TMPDIR_SEED"' EXIT

# ── Python: 초기 시드 목록 → JSON Lines ────────────────────────────
SEED_JSON=$(python3 - "$TMPDIR_SEED" "$NAMESPACE" "$FW_BIN" "$FW_SLOT" "$FW_XFER" <<'PYEOF'
import sys, json, struct, os

tmpdir, namespace, fw_bin, fw_slot, fw_xfer = sys.argv[1:]
namespace = int(namespace)
fw_slot   = int(fw_slot)
fw_xfer   = int(fw_xfer)
MAX_DATA_BUF = 65536

# ── FUA 비트 위치 수정: CDW12[29] (NVMe spec) ──
# 이전 코드는 (1<<14) 를 사용해 NLB=0x4000 이 되어 버퍼 불일치 → rc=2
FUA_BIT = (1 << 29)  # CDW12[29] = Force Unit Access

ADMIN_FIXED_RESPONSE = {"Identify": 4096, "GetFeatures": 4096, "TelemetryHostInitiated": 4096}
WRITE_CMDS = {"Write", "FWDownload", "DatasetManagement"}

# xfail: 예상된 실패 (OOR, 사전조건 없음 등)
# skip:  실행 자체를 건너뜀

seeds = []
idx = 0

def add(cmd, opcode, ctype, needs_ns, needs_data, cdw10=0, cdw11=0, cdw12=0,
        cdw13=0, cdw14=0, cdw15=0, data=b"", desc="", xfail=False,
        skip=False, nsid_override=None):
    global idx

    is_write = cmd in WRITE_CMDS
    write_dir = False
    data_len  = 0

    if is_write and len(data) > 0:
        data_len  = min(len(data), MAX_DATA_BUF)
        write_dir = True
    elif ctype == "io" and cmd not in ("Flush", "DatasetManagement"):
        nlb      = cdw12 & 0xFFFF
        data_len = min(max(512, (nlb + 1) * 512), MAX_DATA_BUF)
    elif cmd == "GetLogPage":
        numdl    = (cdw10 >> 16) & 0x7FF
        data_len = min(max(4, (numdl + 1) * 4), MAX_DATA_BUF)
    elif cmd in ADMIN_FIXED_RESPONSE:
        data_len = ADMIN_FIXED_RESPONSE[cmd]

    data_file = ""
    if write_dir and data_len > 0:
        data_file = os.path.join(tmpdir, f"seed_{idx}.bin")
        with open(data_file, "wb") as f:
            f.write(data[:data_len])

    # nsid 결정
    if nsid_override is not None:
        nsid = nsid_override
    elif needs_ns:
        nsid = namespace
    else:
        nsid = 0

    seeds.append({"idx": idx, "cmd": cmd, "opcode": opcode, "type": ctype,
                  "nsid": nsid, "cdw10": cdw10, "cdw11": cdw11, "cdw12": cdw12,
                  "cdw13": cdw13, "cdw14": cdw14, "cdw15": cdw15,
                  "data_len": data_len, "write": write_dir, "data_file": data_file,
                  "desc": desc, "xfail": xfail, "skip": skip})
    idx += 1

# ── Identify ──────────────────────────────────────────────────────
# CNS=0x01(Identify Controller): NSID는 Reserved → nsid_override=0
add("Identify", 0x06, "admin", True,  False, cdw10=0x01, desc="Identify Controller",                nsid_override=0)
add("Identify", 0x06, "admin", True,  False, cdw10=0x00, desc="Identify Namespace")
add("Identify", 0x06, "admin", True,  False, cdw10=0x02, desc="Active NS ID list")
add("Identify", 0x06, "admin", True,  False, cdw10=0x03, desc="NS Identification Descriptor")

# ── GetLogPage ────────────────────────────────────────────────────
# Error Info(0x01), SMART(0x02): 컨트롤러 범위 → NSID=0
add("GetLogPage", 0x02, "admin", True, False, cdw10=(0x0F << 16)|0x01, desc="Error Info Log",       nsid_override=0)
add("GetLogPage", 0x02, "admin", True, False, cdw10=(0x7F << 16)|0x02, desc="SMART/Health Log",     nsid_override=0)

# ── GetFeatures ───────────────────────────────────────────────────
add("GetFeatures", 0x0A, "admin", True, False, cdw10=0x06, desc="Volatile Write Cache")
add("GetFeatures", 0x0A, "admin", True, False, cdw10=0x07, desc="Number of Queues")
add("GetFeatures", 0x0A, "admin", True, False, cdw10=0x0B, desc="Async Event Config")

# ── Read ──────────────────────────────────────────────────────────
add("Read", 0x02, "io", True, False, cdw10=0,     cdw11=0, cdw12=0,      desc="Read LBA 0, 1 block")
add("Read", 0x02, "io", True, False, cdw10=1,     cdw11=0, cdw12=0,      desc="Read LBA 1")
add("Read", 0x02, "io", True, False, cdw10=0,     cdw11=0, cdw12=7,      desc="Read LBA 0, 8 blocks")
add("Read", 0x02, "io", True, False, cdw10=0,     cdw11=0, cdw12=31,     desc="Read LBA 0, 32 blocks")
add("Read", 0x02, "io", True, False, cdw10=0,     cdw11=0, cdw12=127,    desc="Read LBA 0, 128 blocks")
add("Read", 0x02, "io", True, False, cdw10=0,     cdw11=0, cdw12=255,    desc="Read LBA 0, 256 blocks")
# NLB max: data_len이 MAX_DATA_BUF에 cap → NLB 불일치 → 예상 실패
add("Read", 0x02, "io", True, False, cdw10=0,     cdw11=0, cdw12=0xFFFF, desc="Read NLB max (OOR buffer mismatch)", xfail=True)
add("Read", 0x02, "io", True, False, cdw10=500,   cdw11=0, cdw12=0,      desc="Read LBA 500")
add("Read", 0x02, "io", True, False, cdw10=1000,  cdw11=0, cdw12=0,      desc="Read LBA 1000")
add("Read", 0x02, "io", True, False, cdw10=5000,  cdw11=0, cdw12=0,      desc="Read LBA 5000")
add("Read", 0x02, "io", True, False, cdw10=10000, cdw11=0, cdw12=0,      desc="Read LBA 10000")
# FUA: CDW12[29]=1, NLB=0 (1 block)
add("Read", 0x02, "io", True, False, cdw10=0, cdw11=0, cdw12=FUA_BIT,    desc="Read LBA 0, FUA")
# OOR LBA → 예상 실패
add("Read", 0x02, "io", True, False, cdw10=0x00000000, cdw11=0x00000001, cdw12=0, desc="Read LBA 4G (OOR)", xfail=True)
add("Read", 0x02, "io", True, False, cdw10=0xFFFF0000, cdw11=0xFFFFFFFF, cdw12=0, desc="Read SLBA 64bit max (OOR)", xfail=True)

# ── Write ─────────────────────────────────────────────────────────
add("Write", 0x01, "io", True, True, cdw10=0,     cdw11=0, cdw12=0,      data=b'\x00'*512,       desc="Write LBA 0, zeros")
add("Write", 0x01, "io", True, True, cdw10=0,     cdw11=0, cdw12=0,      data=b'\xAA'*512,       desc="Write LBA 0, 0xAA")
add("Write", 0x01, "io", True, True, cdw10=0,     cdw11=0, cdw12=0,      data=b'\xFF'*512,       desc="Write LBA 0, 0xFF")
add("Write", 0x01, "io", True, True, cdw10=0,     cdw11=0, cdw12=0,      data=bytes(range(256))*2, desc="Write LBA 0, sequential")
add("Write", 0x01, "io", True, True, cdw10=0,     cdw11=0, cdw12=7,      data=b'\x00'*(8*512),   desc="Write LBA 0, 8 blocks")
add("Write", 0x01, "io", True, True, cdw10=0,     cdw11=0, cdw12=31,     data=b'\x00'*(32*512),  desc="Write LBA 0, 32 blocks")
add("Write", 0x01, "io", True, True, cdw10=0,     cdw11=0, cdw12=127,    data=b'\x00'*(128*512), desc="Write LBA 0, 128 blocks")
add("Write", 0x01, "io", True, True, cdw10=0,     cdw11=0, cdw12=255,    data=b'\x00'*(256*512), desc="Write LBA 0, 256 blocks")
add("Write", 0x01, "io", True, True, cdw10=500,   cdw11=0, cdw12=0,      data=b'\x00'*512,       desc="Write LBA 500")
add("Write", 0x01, "io", True, True, cdw10=1000,  cdw11=0, cdw12=0,      data=b'\x00'*512,       desc="Write LBA 1000")
add("Write", 0x01, "io", True, True, cdw10=5000,  cdw11=0, cdw12=0,      data=b'\x00'*512,       desc="Write LBA 5000")
add("Write", 0x01, "io", True, True, cdw10=10000, cdw11=0, cdw12=0,      data=b'\x00'*512,       desc="Write LBA 10000")
# FUA: CDW12[29]=1, NLB=0
add("Write", 0x01, "io", True, True, cdw10=0, cdw11=0, cdw12=FUA_BIT,   data=b'\x00'*512,        desc="Write LBA 0, FUA")
# OOR → 예상 실패
add("Write", 0x01, "io", True, True, cdw10=0x00000000, cdw11=0x00000001, cdw12=0, data=b'\x00'*512, desc="Write LBA 4G (OOR)", xfail=True)
add("Write", 0x01, "io", True, True, cdw10=0xFFFF0000, cdw11=0xFFFFFFFF, cdw12=0, data=b'\x00'*512, desc="Write SLBA 64bit max (OOR)", xfail=True)

# ── SetFeatures ───────────────────────────────────────────────────
# 큐 설정은 초기화 이후 변경 불가 → 예상 실패 (0x0C Command Sequence Error)
add("SetFeatures", 0x09, "admin", True, True, cdw10=0x07, cdw11=0x00010001, desc="Number of Queues", xfail=True)

# ── FWDownload / FWCommit ─────────────────────────────────────────
# bash에서 'nvme fw-download -x fw_xfer' / 'nvme fw-commit' 로 실행
# (단일 CLI 명령 = 단일 시드)
fw_size = os.path.getsize(fw_bin)
seeds.append({"idx": idx, "cmd": "FWDownload", "opcode": 0x11, "type": "fw",
              "nsid": 0, "cdw10": 0, "cdw11": 0, "cdw12": 0,
              "cdw13": 0, "cdw14": 0, "cdw15": 0,
              "data_len": 0, "write": False, "data_file": "",
              "desc": f"fw-download -f {os.path.basename(fw_bin)} -x {fw_xfer} ({fw_size}B)",
              "xfail": False, "skip": False})
idx += 1
add("FWCommit", 0x10, "admin", True, False, cdw10=(fw_slot << 3) | 0x01,
    desc=f"fw-commit slot={fw_slot} action=1 (activate on reset)")

# ── FormatNVM ─────────────────────────────────────────────────────
# SES=0 (No secure erase), LBAF=0. CDW10[11:9]=0, CDW10[3:0]=0 → 0x00
add("FormatNVM", 0x80, "admin", True, False, cdw10=0x00, desc="Format LBAF 0 SES=0")

# ── TelemetryHostInitiated ───────────────────────────────────────
# NSID=0 으로 수정 (GetLogPage 컨트롤러 범위)
add("TelemetryHostInitiated", 0x02, "admin", True, False,
    cdw10=(0x1FF << 16)|0x07, desc="Telemetry Host-Initiated", nsid_override=0)

# ── Flush ─────────────────────────────────────────────────────────
add("Flush", 0x00, "io", True, False, desc="Flush")

# ── DatasetManagement ─────────────────────────────────────────────
add("DatasetManagement", 0x09, "io", True, True,
    cdw10=0, cdw11=0x04, data=struct.pack('<IIIII', 0, 0, 0, 0, 8), desc="TRIM LBA 0, 8 blocks")

for s in seeds:
    print(json.dumps(s))
PYEOF
)

if [[ -z "$SEED_JSON" ]]; then
    echo -e "${RED}ERROR${NC}: 시드 생성 실패"; exit 1
fi

TOTAL=$(echo "$SEED_JSON" | wc -l)
FW_INFO=" | FW: $(basename "$FW_BIN") slot=$FW_SLOT xfer=${FW_XFER}B"

echo "════════════════════════════════════════════════════════"
echo "  Initial Seed Replay Test"
echo "════════════════════════════════════════════════════════"
printf "  Device    : %s\n"  "$DEVICE"
printf "  Namespace : %s\n"  "$NAMESPACE"
printf "  Timeout   : %ss%s\n" "$TIMEOUT" "$FW_INFO"
printf "  시드 수   : %d개\n" "$TOTAL"
echo "════════════════════════════════════════════════════════"
echo ""

PASS=0; FAIL=0; XFAIL=0; SKIP=0

while IFS= read -r line; do
    eval "$(python3 -c "
import json, sys
s = json.loads('''$line'''.replace(\"'''\", '\"\"\"'))
print('IDX=%d CMD=%s OPCODE=%d CTYPE=%s NSID=%d' % (s['idx'],s['cmd'],s['opcode'],s['type'],s['nsid']))
print('CDW10=%d CDW11=%d CDW12=%d CDW13=%d CDW14=%d CDW15=%d' % (s['cdw10'],s['cdw11'],s['cdw12'],s['cdw13'],s['cdw14'],s['cdw15']))
print('DATA_LEN=%d WRITE=%d' % (s['data_len'], int(s['write'])))
print('DATA_FILE=%s' % repr(s['data_file']))
print('DESC=%s' % repr(s['desc']))
print('XFAIL=%d SKIP=%d' % (int(s['xfail']), int(s['skip'])))
")"

    label=$(printf "[%3d] %-22s %s" "$IDX" "$CMD" "$DESC")

    if [[ $SKIP -eq 1 ]]; then
        printf "${DIM}[SKIP]${NC} %s\n" "$label"
        ((SKIP++)) || true
        continue
    fi

    # nvme 명령 구성
    if [[ "$CMD" == "FWDownload" ]]; then
        # high-level 명령어 (단일 시드 = 단일 CLI)
        nvme_cmd="nvme fw-download $DEVICE -f $FW_BIN -x $FW_XFER"
    elif [[ "$CMD" == "FWCommit" ]]; then
        nvme_cmd="nvme fw-commit $DEVICE -s $FW_SLOT -a 1"
    else
        # passthru 타입 / 타겟 장치
        if [[ "$CTYPE" == "admin" ]]; then
            PASSTHRU="admin-passthru"; TARGET="$DEVICE"
        else
            PASSTHRU="io-passthru";    TARGET="${DEVICE}n${NAMESPACE}"
        fi
        nvme_cmd="nvme $PASSTHRU $TARGET"
        nvme_cmd+=" --opcode=$(python3 -c "print(hex($OPCODE))")"
        nvme_cmd+=" --namespace-id=$NSID"
        nvme_cmd+=" --cdw10=$(python3 -c "print(hex($CDW10))")"
        nvme_cmd+=" --cdw11=$(python3 -c "print(hex($CDW11))")"
        nvme_cmd+=" --cdw12=$(python3 -c "print(hex($CDW12))")"
        nvme_cmd+=" --cdw13=$(python3 -c "print(hex($CDW13))")"
        nvme_cmd+=" --cdw14=$(python3 -c "print(hex($CDW14))")"
        nvme_cmd+=" --cdw15=$(python3 -c "print(hex($CDW15))")"
        nvme_cmd+=" --timeout=$(( TIMEOUT * 1000 ))"
        if [[ $DATA_LEN -gt 0 ]]; then
            nvme_cmd+=" --data-len=$DATA_LEN"
            if [[ $WRITE -eq 1 ]]; then
                real_file="$DATA_FILE"
                nvme_cmd+=" --input-file=$real_file -w"
            else
                nvme_cmd+=" -r"
            fi
        fi
    fi

    [[ $VERBOSE -eq 1 ]] && printf "${CYN}[CMD]${NC} %s\n" "$nvme_cmd"

    out=$(timeout "${TIMEOUT}s" bash -c "$nvme_cmd" 2>&1) && rc=0 || rc=$?

    if [[ $rc -eq 0 ]]; then
        printf "${GRN}[PASS]${NC}  %s\n" "$label"
        ((PASS++)) || true
    elif [[ $XFAIL -eq 1 ]]; then
        printf "${DIM}[XFAIL]${NC} %s  rc=%d (예상된 실패)\n" "$label" "$rc"
        ((XFAIL++)) || true
    elif [[ $rc -eq 124 ]]; then
        printf "${YEL}[TOUT]${NC}  %s  timeout\n" "$label"
        [[ $VERBOSE -eq 1 ]] && printf "        CMD: %s\n" "$nvme_cmd"
        ((FAIL++)) || true
    else
        status=$(printf '%s' "$out" | grep -oP 'NVMe status:.*' | head -1 || true)
        printf "${RED}[FAIL]${NC}  %s  rc=%d  %s\n" "$label" "$rc" "$status"
        [[ $VERBOSE -eq 1 ]] && printf "        CMD: %s\n        OUT: %s\n" \
            "$nvme_cmd" "$(printf '%s' "$out" | head -2 | tr '\n' '|')"
        ((FAIL++)) || true
    fi

done <<< "$SEED_JSON"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  결과 요약"
echo "════════════════════════════════════════════════════════"
printf "  전체   : %d\n"                 "$TOTAL"
printf "  ${GRN}PASS${NC}   : %d\n"     "$PASS"
printf "  ${RED}FAIL${NC}   : %d\n"     "$FAIL"
printf "  ${DIM}XFAIL${NC}  : %d (예상된 실패, 퍼징용 경계값)\n" "$XFAIL"
printf "  ${DIM}SKIP${NC}   : %d\n"     "$SKIP"
echo "════════════════════════════════════════════════════════"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n  ${RED}예상치 못한 실패가 있습니다. -v 옵션으로 상세 확인하세요.${NC}"
    exit 1
else
    echo -e "\n  ${GRN}모든 시드가 정상 범위 내에서 실행됐습니다.${NC}"
    exit 0
fi
