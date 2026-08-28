#!/usr/bin/env python3
"""SF-E76 Secure JTAG (PKC/ECDSA) 인증 — clavis.cmm 의 J-Link(pylink) 포팅.

T32 `clavis.cmm` 이 하는 secure-JTAG challenge-response 를 J-Link 으로 재현한다.
그 스크립트는 코어를 halt 하지 않고 **`APB3:`(=APBAP3) 접근**으로
SJTAG 레지스터 블록을 두드려 `AUTH_PASS` 를 세운다.

**가설(이 프로그램으로 검증하려는 것):** 이 인증이 DM 앞단의 외부
게이트를 여는 **가장 강한 후보**다(STATUS §0.3/§0.36). "인증 뒤에야 DM 이 살아난다"
는 아직 증명 전이며, 이 도구의 인증 전/후 dmstatus A/B 가 그 증거를 만든다.

이 모듈이 당신에게서 받는 것은 딱 둘이다 (CONFIG 또는 CLI):
  1) SJTAG_BASE  — clavis 의 `&base` (SJTAG 레지스터 블록의 APB 주소)
  2) SIGN_TOOL   — clavis 의 `&tool` (challenge 에 P-521 서명하는 외부 실행파일)
이 둘을 뺀 상태머신·레지스터맵·폴링은 clavis.cmm 를 옮겼다. 키/서명은 전적으로
SIGN_TOOL 안에 있고 이 파일엔 어떤 비밀값도 없다.

★ 안전 기본값: **쓰기를 하지 않는다.** `--execute` 를 명시해야만 인증(쓰기)을 한다.
   그 전까지는 read-only probe (DAP 전원·APBAP3 IDR·HW/STATE·default-slave 판정).

⚠ 실기 전에 실측으로 확정할 것:
  - 워드 **주소 매핑 순서**(T32 area.line 음수 인덱스) → `--word-order` 필수 인자.
  - `SJTAG_BASE` 가 APBAP3 뒤 유효 블록인지 → probe 단계 검증 게이트가 확인.
  - dmstatus stride(`base+(0x11<<2)`)는 **미검증**(STATUS §1.2). after=무효는
    "그 게이트가 닫힘" 이 아니라 "추정 경로에서 유효 dmstatus 를 못 얻음" 이다.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import shlex
import subprocess
import sys
import time
from collections import namedtuple

from sfe76_link import (require_api, Link, LinkError, AP_MAP, add_common_args,
                        CORE_BASE_MAIN, CORE_BASE_NCORE, RISCV_ADDRS, ADDRS_REAL,
                        EXIT_OK, EXIT_CONNECT_FAIL, EXIT_INSUFFICIENT)
from dap_access import (Dap, OFF_CSW, OFF_TAR, OFF_DRW, OFF_IDR,
                          csw_usable, hx)

VERSION = "sjtag_unlock 2026-08-13.2"
require_api(5, "sjtag_unlock.py")


# ══════════════════════════════════════════════════════════════════════
#  ★ CONFIG — 여기 두 줄만 당신 값으로 채우면 된다 (또는 --base / --tool)
# ══════════════════════════════════════════════════════════════════════
SJTAG_BASE = None          # 예: 0x........  (clavis 의 &base)
SIGN_TOOL  = None          # 예: "/path/to/signer" 또는 r"C:\...\signer.exe"
# ★ 서명 도구가 Windows .exe 인데 이 스크립트를 **리눅스에서** 돌린다면 PE 를
#   네이티브로 exec 할 수 없다. wine 등 런처를 앞에 붙인다(빈칸/따옴표 shlex 분리).
#   예: "wine"  또는  "wine64"  또는  r"wine C:\\path\\wrap".  CLI --tool-prefix 우선.
TOOL_PREFIX = ""           # 예: "wine"  (비면 도구를 직접 exec)

# clavis 가 서명 도구를 부르는 방식과 동일한 인자.
#   os.area &tool -s3 -f5           → 공개키 Qx,Qy (34 워드) 를 stdout 으로
#   os.area &tool -s1 -f5 &challenge → 서명 r,s (34 워드) 를 stdout 으로
PUBKEY_FLAGS = ["-s3", "-f5"]
SIGN_FLAGS   = ["-s1", "-f5"]
TOOL_TIMEOUT = 120         # 서명 도구가 오래 걸릴 수 있다(초)


# ── SJTAG 레지스터맵 (clavis.cmm 유래) — 기밀이라 외부 JSON 에서 로드 ──────
#   실제 값: sjtag_addrs.json(.gitignore). 없으면 example placeholder(테스트만).
def _a(v, default=0):
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return default
    return v if isinstance(v, int) else default

# runtime 기본값 — sjtag_addrs.json 의 "runtime" 에서 base/tool/prefix/word-order 를 받는다.
# (CLI 로 주면 CLI 우선; json 에 있으면 인자 없이도 동작 → 오케스트레이터가 간단해진다.)
_RT = RISCV_ADDRS.get("runtime", {})
if _RT.get("sjtag_base"):
    SJTAG_BASE = _a(_RT["sjtag_base"])
if _RT.get("sign_tool"):
    SIGN_TOOL = _RT["sign_tool"]
if _RT.get("tool_prefix"):
    TOOL_PREFIX = _RT["tool_prefix"]
_RT_WORD_ORDER = _RT.get("word_order") or None      # --word-order 기본값

_OFF = RISCV_ADDRS.get("sjtag_offsets", {})
_BIT = RISCV_ADDRS.get("sjtag_state_bits", {})

OFF_HW_VERSION  = _a(_OFF.get("hw_version"))
OFF_STATE       = _a(_OFF.get("state"))
OFF_CHIP_ID0    = _a(_OFF.get("chip_id0"))
OFF_CHIP_ID1    = _a(_OFF.get("chip_id1"))
OFF_RESP_DOMAIN = _a(_OFF.get("resp_domain"))
OFF_RESP_LV0    = _a(_OFF.get("resp_lv0"))
OFF_RESP_LV1    = _a(_OFF.get("resp_lv1"))
OFF_DBG_CONTROL = _a(_OFF.get("dbg_control"))
OFF_REQUEST     = _a(_OFF.get("request"))     # 공개키 Qx,Qy 주입
OFF_CHALLENGE   = _a(_OFF.get("challenge"))   # Nonce 읽기
OFF_RESPONSE    = _a(_OFF.get("response"))    # 서명 r,s 주입
OFF_TOP         = OFF_RESPONSE + 4 * 33        # 이 블록이 쓰는 최상단 오프셋

# STATE 비트
AUTH_PASS       = _a(_BIT.get("auth_pass"))
SOFT_LOCK       = _a(_BIT.get("soft_lock"))
REQUEST_READY   = _a(_BIT.get("request_ready"))
RESPONSE_READY  = _a(_BIT.get("response_ready"))
STATE_INFO_MASK = _a(_BIT.get("state_info_mask"))
INVALID_PUBKEY  = _a(_BIT.get("invalid_pubkey"))
SW_RESET_MASK   = _a(_BIT.get("sw_reset_mask"))

PUBKEY_WORDS   = 34         # Qx,Qy  (P-521: 17+17)
SIG_WORDS      = 34         # r,s
NONCE_WORDS    = 16
# challenge = 0xFFFFFFFF*3 + ChipID0 + ChipID1 + Nonce[0..15]  = 21 워드
CHALLENGE_PREFIX = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF]

# 인증 후 권한값. clavis 는 %LONG 에 0xFFFFFFFFF(F 9개)를 쓴다. T32 %LONG 은
# 32비트 트랜잭션이므로 버스에는 하위 32비트 0xFFFFFFFF 가 실린다 — 그 값을 쓴다.
# ⚠ "T32 가 정말 하위 32비트만 쓴다" 는 실측으로 재확인하면 더 안전하다.
RESPONSE_GRANT = 0xFFFFFFFF

APBAP3_IDR_EXPECT = _a(RISCV_ADDRS.get("apbap3_idr_expect"))   # 실측 APB-AP IDR

# MEM-AP 로 유효값 대신 나오는 미매핑/default-slave 지문 (STATUS §0.5)
DEAD_FINGERPRINTS = {_a(x) for x in RISCV_ADDRS.get("dead_fingerprints", [])}
# STATE 는 0x0 이 유효 초기값일 수 있어 지문에서 뺀다(HW_VERSION 은 0 도 의심).
STATE_DEAD = DEAD_FINGERPRINTS - {0x00000000}

# 종료 코드 (sfe76_link 의 0/2/3/4/5/6 과 겹치지 않게)
EXIT_AUTH_FAIL      = 7     # 인증 절차는 돌았으나 AUTH_PASS 안 뜸
EXIT_TOOL_FAIL      = 8     # 서명 도구 실행/출력 문제
EXIT_CONFIG         = 9     # base/tool 미설정, AP/base 검증 실패, AP 접근 불가
EXIT_VERIFY_WEAK    = 10    # 인증 성공 but DM A/B 불충분 (추정 경로서 dmstatus 무효)
EXIT_CAUSE_UNPROVEN = 11    # challenge-response 와 DM 접근 사이 인과 미입증:
                            #   인증 전부터 dmstatus 유효 / 이미 unlock / SOFT_LOCK
                            #   미설정(인증 미수행) 을 모두 포함한다


def ap_base(name):
    for n, addr, _typ in AP_MAP:
        if n == name:
            return addr
    raise KeyError(name)

APBAP3_BASE = ap_base("APBAP3")   # SJTAG 인증 블록
APBAP1_BASE = ap_base("APBAP1")   # hcore 계열 DM
APBAP2_BASE = ap_base("APBAP2")   # Ncore DM

# core_base → 그 DM 이 매달린 MEM-AP (STATUS §1.2 실측)
DM_AP = {CORE_BASE_MAIN: APBAP1_BASE, CORE_BASE_NCORE: APBAP2_BASE}
DMSTATUS_OFF = 0x11 << 2          # dmstatus 후보 오프셋 (미검증, STATUS §1.2)
DMCONTROL_OFF = 0x10 << 2         # dmcontrol (dmactive=bit0 로 DM 리셋 해제)
DM_DATA0_OFF     = 0x04 << 2      # abstract data0
DM_ABSTRACTCS_OFF = 0x16 << 2     # abstractcs (busy=bit12, cmderr=bits10:8)
DM_COMMAND_OFF   = 0x17 << 2      # abstract command (access register)


class SecureJtagError(RuntimeError):
    def __init__(self, msg, exit_code=EXIT_AUTH_FAIL):
        super().__init__(msg)
        self.exit_code = exit_code


def valid_timeout(t):
    """유한한 양수만 허용. nan 은 'monotonic() >= nan' 이 항상 False 라 폴링이
    영원히 끝나지 않고, inf/0/음수도 폴링 의미가 없다."""
    return isinstance(t, (int, float)) and not isinstance(t, bool) \
        and math.isfinite(t) and t > 0


def valid_base(base):
    """(ok, reason). SJTAG_BASE 가 쓰기·읽기에 안전한 32비트 정수 주소인지.
    CONFIG 를 사용자 입력으로 보고 타입까지 본다(문자열/float/bool 거부)."""
    if isinstance(base, bool) or not isinstance(base, int):
        return False, f"base 가 정수가 아니다 (type={type(base).__name__})"
    max_base = 0xFFFFFFFF - OFF_TOP
    if not (0 <= base <= max_base):
        return False, f"base {base:#x} 가 유효범위 밖 (0 ~ {max_base:#x}; 블록 상단 +{OFF_TOP:#x})"
    if base % 4:
        return False, f"base {base:#x} 4바이트 정렬 아님"
    return True, ""


# unlock() 결과 분류 — "인증 성공" 과 "인증 불필요로 열림" 을 섞지 않는다.
UnlockResult = namedtuple("UnlockResult", "status state")
ST_ALREADY           = "ALREADY_UNLOCKED"     # 최초 STATE 에 이미 AUTH_PASS
ST_OPEN_NO_SOFT_LOCK = "OPEN_NO_SOFT_LOCK"    # SOFT_LOCK 미설정 → 인증 불필요
ST_AUTHENTICATED     = "AUTHENTICATED"        # challenge-response 후 AUTH_PASS


# ── AP 메모리 쓰기 + posted-write/sticky 확인 ────────────────────────
class MemDap(Dap):
    # DP CTRL/STAT 오류 비트 (ADIv5/v6 정의):
    #   bit7 = WDATAERR, bit5 = STICKYERR, bit1 = STICKYORUN
    STICKY_ERR = (1 << 7) | (1 << 5) | (1 << 1)
    DP_CTRL_STAT = 1
    DP_RDBUFF = 3

    def dp_sticky_error(self):
        """쓰기 후 posted AP write 를 flush 하고 DP CTRL/STAT 오류비트를 본다.
        RDBUFF read 로 이전 AP 트랜잭션을 밀어낸 뒤 CTRL/STAT 를 확인한다.
        RDBUFF read 자체가 실패하면(=flush 실패) 완료를 보장할 수 없어 None."""
        flushed = self.dp_read(self.DP_RDBUFF)       # posted write flush
        if flushed is None:
            return None
        v = self.dp_read(self.DP_CTRL_STAT)
        return None if v is None else bool(v & self.STICKY_ERR)

    def mem_write32(self, base, addr, val):
        """MEM-AP 로 32비트 쓰기. TAR 되읽기 + posted-write 완료/오류를 확인한다.
        진입부 CSW 가 STICKYERR 로 SUSPECT(0x80000000) 면 한 번 sticky 를 클리어하고
        재읽기 — 직전 워드의 sticky 가 다음 워드를 연쇄로 죽이는 것을 끊는다."""
        csw = self.ap_read(base, OFF_CSW)
        if not csw_usable(csw):
            self.clear_sticky()                       # 연쇄 방지: 한 번 복구 시도
            csw = self.ap_read(base, OFF_CSW)
        if not csw_usable(csw):
            self.last = {'why': f"CSW 의심값 {hx(csw)} — 쓰지 않고 중단"}
            return False
        if not self.ap_write(base, OFF_CSW, (csw & ~0x37) | 0x02):   # Size=word
            return False
        if not self.ap_write(base, OFF_TAR, addr):
            return False
        back = self.ap_read(base, OFF_TAR)
        if back is None or back != (addr & 0xFFFFFFFF):
            self.last = {'why': f"TAR 불일치 쓴값={hx(addr)} 읽은값={hx(back)}"}
            return False
        if not self.ap_write(base, OFF_DRW, val):
            self.last = {'why': "DRW 쓰기 API 실패"}
            return False
        err = self.dp_sticky_error()
        if err is None:
            self.last = {'why': "posted-write flush(RDBUFF)/CTRL-STAT 확인 실패"}
            return False
        if err:
            self.last = {'why': "DP sticky 오류 — posted write 미완료 가능"}
            self.clear_sticky()
            return False
        return True


# ── 서명 도구 인터페이스 (clavis 의 os.area &tool ...) ────────────────
_WORD_RE = re.compile(r"(?:0[xX])?([0-9a-fA-F]{8})")   # 줄 = 정확히 8자리 hex(옵션 0x/0X)


def _parse_words(text, want):
    """도구 stdout 을 파싱한다. 각 비어있지 않은 줄은 **정확히** 8자리 hex 한 개
    여야 한다(옵션 0x). 라벨/여분 토큰이 섞인 줄은 거부한다 — 인덱스나 잡토큰을
    값으로 오독하는 것을 막는다. 원문은 로깅/노출하지 않는다."""
    words, bad = [], 0
    for line in text.splitlines():
        t = line.strip()
        if not t:
            continue
        m = _WORD_RE.fullmatch(t)
        if m:
            words.append(int(m.group(1), 16))
        else:
            bad += 1
    if bad or len(words) != want:
        raise SecureJtagError(
            f"서명 도구 출력 파싱 실패: 유효워드 {len(words)}/{want}, 비정형 줄 {bad}. "
            f"기대 형식은 '줄당 8자리 hex 하나(옵션 0x)'. (원문은 로깅하지 않음)",
            EXIT_TOOL_FAIL)
    return words


def _decode_tool_output(raw):
    """도구 stdout(bytes)을 텍스트로. Windows .exe 는 UTF-16/BOM 로 뱉을 수 있어
    text=True 의 로케일 디코드로는 깨진다. BOM 을 먼저 보고, 없으면 UTF-8→UTF-16
    순으로 시도해 hex 워드가 실제로 나오는 인코딩을 고른다. 마지막은 replace."""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")           # BOM 이 LE/BE 를 지정
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace")
    # NUL 이 많으면 UTF-16(BOM 없는) 일 가능성이 큼 — 그쪽을 먼저 시도.
    order = ("utf-16-le", "utf-8") if raw.count(0) > len(raw) // 4 else ("utf-8", "utf-16-le")
    for enc in order:
        try:
            txt = raw.decode(enc)
            if _WORD_RE.search(txt):          # 이 인코딩에서 hex 워드가 보이면 채택
                return txt
        except (UnicodeError, ValueError):
            continue
    return raw.decode("utf-8", "replace")


def run_tool(tool, args, want, label, prefix=()):
    # prefix = wine 등 런처(리눅스에서 .exe 를 돌릴 때). 비면 도구를 직접 exec.
    cmd = [*prefix, tool, *args]
    try:
        # bytes 로 받아 우리가 인코딩을 판별한다(로케일 자동디코드에 맡기지 않음).
        proc = subprocess.run(cmd, capture_output=True, timeout=TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        hint = ""
        if isinstance(e, OSError) and not prefix and str(tool).lower().endswith(".exe") \
                and sys.platform != "win32":
            hint = ("  (Windows .exe 를 리눅스에서 직접 exec 함 — "
                    "--tool-prefix wine 로 감싸라)")
        raise SecureJtagError(f"{label}: 서명 도구 실행 실패 — {e}{hint}", EXIT_TOOL_FAIL)
    # 비밀 가능성(서명값)을 로그에 남기지 않는다 — 원시 bytes 해시·줄수만.
    digest = hashlib.sha256(proc.stdout).hexdigest()[:16]
    out = _decode_tool_output(proc.stdout)
    nlines = len([l for l in out.splitlines() if l.strip()])
    print(f"    [{label}] 도구 종료코드={proc.returncode} 비어있지않은줄={nlines} "
          f"stdout_sha256={digest}..")
    if proc.returncode != 0:
        raise SecureJtagError(f"{label}: 서명 도구 종료코드 {proc.returncode}",
                              EXIT_TOOL_FAIL)
    return _parse_words(out, want)


def order_words(words, word_order):
    """워드를 주소 증가순으로 어떻게 매핑할지.
    't32-negative' = T32 area.line(0..-33) = **stdout 역순**.
    'stdout'       = stdout 그대로.
    ⚠ 미확정이라 --word-order 를 필수로 받는다. pubkey 단계에서
      INVALID_PUBLIC_KEY 로 죽으면 반대값으로 재시도."""
    if word_order == "t32-negative":
        return list(reversed(words))
    if word_order == "stdout":
        return list(words)
    raise ValueError(word_order)


def analyze_pubkey(tool, tool_prefix):
    """오프라인 pubkey 정적 분석 — HW/J-Link/인증 불필요, 카운터 무소모.
    (a) -s3 를 2회 실행해 정적 키 동일성, (b) 두 word-order 로 늘어놓고 P-521 좌표
    구조(각 17워드, 최상위 워드가 패딩/작은값 < 0x200)로 후보를 좁힌다."""
    print(f"\n{'=' * 66}\n  PUBKEY 정적 분석 (오프라인 — HW/인증 무관)\n{'=' * 66}")
    w1 = run_tool(tool, PUBKEY_FLAGS, PUBKEY_WORDS, "pubkey#1", tool_prefix)
    w2 = run_tool(tool, PUBKEY_FLAGS, PUBKEY_WORDS, "pubkey#2", tool_prefix)
    if w1 != w2:
        print("  ⚠ 2회 실행 결과가 다르다 — 정적이어야 할 공개키가 비결정적. 툴/키 확인.")
    else:
        print(f"  ✓ 2회 동일 ({PUBKEY_WORDS}워드) — 정적 키 정상.")

    SMALL = 0x200                    # P-521: 좌표 < 2^521 → 최상위 32비트 워드 < 0x200
    HALF = PUBKEY_WORDS // 2         # 17
    print(f"\n  P-521 좌표 = {HALF}워드씩 2개(Qx,Qy). 각 좌표 최상위 워드는 < 0x{SMALL:X}.")
    for name in ("stdout", "t32-negative"):
        words = order_words(w1, name)
        smalls = [i for i, x in enumerate(words) if x < SMALL]
        last, first = {HALF - 1, 2 * HALF - 1}, {0, HALF}     # {16,33} / {0,17}
        if set(smalls) >= last:
            verdict = f"작은워드가 좌표 끝 {sorted(last)} → MSW-last 정렬(정합)"
        elif set(smalls) >= first:
            verdict = f"작은워드가 좌표 앞 {sorted(first)} → MSW-first 정렬(정합)"
        else:
            verdict = "작은워드 위치가 좌표경계와 안 맞음 (이 배열 부정합 의심)"
        print(f"\n  [--word-order {name}]  작은워드(<0x{SMALL:X}) index={smalls}")
        print(f"    → {verdict}")
        print(f"    Qx: [0]={hx(words[0])} [{HALF-1}]={hx(words[HALF-1])} | "
              f"Qy: [{HALF}]={hx(words[HALF])} [{2*HALF-1}]={hx(words[2*HALF-1])}")
    print("\n  해석: 두 배열은 서로 거울상이라 '구조 정합'은 양쪽 다 나올 수 있다"
          "(한쪽 MSW-first, 한쪽 MSW-last). 이 분석은 (1) 키가 정상 2×17 구조임을 확정,"
          " (2) 후보를 정확히 2개로 좁힌다. device 가 어느 엔디안을 원하는지가 최종 미지수"
          " — clavis 관례를 알면 택1, 모르면 점4 단 1회로 확정.")
    return EXIT_OK


# ── 폴링 / 접근 헬퍼 (전부 APBAP3; addr = 절대 APB 주소) ─────────────
def poll_bit(dap, addr, mask, want, timeout, label, abort_mask=0):
    deadline = time.monotonic() + timeout
    while True:
        v = None
        for _ in range(3):                       # 일시적 sticky 흡수
            v = dap.mem_read32(APBAP3_BASE, addr)
            if v is not None:
                break
            dap.clear_sticky()
        if v is None:
            raise SecureJtagError(f"{label}: 읽기 실패 ({dap.last.get('why')})", EXIT_CONFIG)
        if abort_mask and (v & abort_mask) == abort_mask:
            raise SecureJtagError(f"{label}: abort STATE={hx(v)} (INVALID_PUBLIC_KEY)")
        if (v & mask) == want:
            print(f"    {label} 완료 STATE={hx(v)}")
            return v
        if time.monotonic() >= deadline:
            raise SecureJtagError(f"{label}: 타임아웃({timeout}s) STATE={hx(v)}")
        time.sleep(1.0)


def w(dap, addr, val, label, retries=3):
    """일시적 AP 에러(STICKYERR→CSW SUSPECT)를 sticky 클리어 후 재시도로 흡수한다.
    34워드 주입 중 한 워드가 순간 끊겨도 자가복구해 시퀀스를 완주시키는 것이 목적."""
    for attempt in range(retries):
        if dap.mem_write32(APBAP3_BASE, addr, val):
            if attempt:
                print(f"    ↻ {label}: sticky {attempt}회 클리어 후 성공(자가복구)")
            return
        dap.clear_sticky()
    raise SecureJtagError(
        f"{label}: APBAP3 쓰기 {retries}회 실패 ({dap.last.get('why')})", EXIT_CONFIG)


def rd(dap, addr, label, retries=3):
    # 읽기도 write 처럼 일시적 AP 에러(STICKYERR→TAR 잘림/CSW SUSPECT)를 sticky 클리어
    # 후 재시도로 흡수한다. (직전 다른 AP 접근이 남긴 sticky 가 첫 읽기를 죽이는 것 방지)
    for attempt in range(retries):
        v = dap.mem_read32(APBAP3_BASE, addr)
        if v is not None:
            if attempt:
                print(f"    ↻ {label}: sticky {attempt}회 클리어 후 성공(자가복구)")
            return v
        dap.clear_sticky()
    raise SecureJtagError(f"{label}: APBAP3 읽기 {retries}회 실패 ({dap.last.get('why')})",
                          EXIT_CONFIG)


# ── 쓰기 전 검증 게이트 (Critical #1) ────────────────────────────────
def scan_sjtag(dap, base, window=0, step=0x1000):
    """진단(읽기전용): base 의 SJTAG 알려진 오프셋들을 읽어 default-slave/live 분류.
    window>0 이면 base±window 를 step 으로 훑어 HW/STATE 둘 다 live 인 후보 base 를 찾는다.
    → base 가 맞는지(=live 다수), 아니면 진짜 위치를 실측으로 가린다. base 는 노출 안 함."""
    named = [("HW_VERSION", OFF_HW_VERSION), ("STATE", OFF_STATE),
             ("CHIP_ID0", OFF_CHIP_ID0), ("CHIP_ID1", OFF_CHIP_ID1),
             ("DBG_CONTROL", OFF_DBG_CONTROL), ("REQUEST", OFF_REQUEST),
             ("CHALLENGE", OFF_CHALLENGE), ("RESPONSE", OFF_RESPONSE)]

    def _live(v):
        return v is not None and v not in DEAD_FINGERPRINTS

    print(f"\n  [scan] base 의 SJTAG 오프셋 (각 3회 읽기):")
    live = 0
    for nm, off in named:
        vals = [dap.mem_read32(APBAP3_BASE, base + off) for _ in range(3)]
        if any(v is None for v in vals):
            cls = "read-fail"
        elif len(set(vals)) != 1:
            cls = f"VARIES {[hx(v) for v in vals]}"
        elif vals[0] in DEAD_FINGERPRINTS:
            cls = "default-slave"
        else:
            cls = "LIVE"
            live += 1
        _v = hx(vals[0]) if (vals and vals[0] is not None) else "?"
        print(f"    +0x{off:04X} {nm:12} = {_v}  [{cls}]")
    print(f"  [scan] LIVE {live}/{len(named)} → "
          + ("base 가 SJTAG 블록으로 보임" if live >= 2
             else "default-slave 위주 — base 의심/미도달"))

    if window > 0:
        lo = max(0, base - window)
        hi = min(0xFFFFFFFF - OFF_TOP, base + window)
        print(f"\n  [scan] base±0x{window:X} 스윕(step 0x{step:X}) — HW·STATE 둘 다 live 인 후보:")
        found, cand = 0, lo
        while cand <= hi:
            hwv = dap.mem_read32(APBAP3_BASE, cand + OFF_HW_VERSION)
            stv = dap.mem_read32(APBAP3_BASE, cand + OFF_STATE)
            if _live(hwv) and _live(stv):
                print(f"    후보 base=0x{cand:X}  HW={hx(hwv)} STATE={hx(stv)}")
                found += 1
            cand += max(step, 4)
        print(f"  [scan] live 후보 {found}개"
              + ("" if found else " — 이 범위엔 SJTAG 블록 없음(범위/접근방식 재검토)"))


def validate_target(dap, base, reads=3):
    """쓰기 전에 base/AP 가 진짜 SJTAG 블록인지 확인한다.
    반환: (ok, problems, info). 실기 쓰기는 problems 가 비었을 때만 허용."""
    if reads < 1:
        raise ValueError("reads 는 1 이상이어야 한다")
    problems, info = [], {}

    # ★ 주소 유효성은 **읽기 전에** 강제한다. 타입/음수/범위밖/미정렬이면 AP·메모리
    #   read 를 한 번도 하지 않고 즉시 실패로 돌린다 — DAP 계층에서 32비트로
    #   마스킹돼 엉뚱한 주소(예: -4 → 0xFFFFFFFC)를 건드리는 것을 막는다.
    ok_base, reason = valid_base(base)
    if not ok_base:
        return False, [reason], info

    idr = dap.ap_read(APBAP3_BASE, OFF_IDR)
    info['apbap3_idr'] = idr
    if idr != APBAP3_IDR_EXPECT:
        problems.append(f"APBAP3 IDR={hx(idr)} != 기대 0x{APBAP3_IDR_EXPECT:08X}")

    # HW_VERSION / STATE 를 독립적으로 여러 번 읽어 일치·유효성 확인
    hw = [dap.mem_read32(APBAP3_BASE, base + OFF_HW_VERSION) for _ in range(reads)]
    st = [dap.mem_read32(APBAP3_BASE, base + OFF_STATE) for _ in range(reads)]
    info['hw'], info['state'] = hw, st
    for name, vals, dead in (("HW_VERSION", hw, DEAD_FINGERPRINTS),
                             ("STATE", st, STATE_DEAD)):
        if any(v is None for v in vals):
            problems.append(f"{name} 읽기 실패 포함")
        elif len(set(vals)) != 1:
            problems.append(f"{name} 반복 읽기 불일치 {[hx(v) for v in vals]}")
        elif vals[0] in dead:
            problems.append(f"{name}={hx(vals[0])} = default-slave 지문 (미매핑 의심)")
    # 서로 다른 두 레지스터가 같은 상수 = 인터커넥트가 한 줄로 응답하는 지문
    if hw[0] is not None and hw[0] == st[0]:
        problems.append(f"HW_VERSION==STATE={hx(hw[0])} 동일 상수 (미매핑 default-slave 의심)")
    return (not problems), problems, info


# ── 인증 상태머신 (clavis.cmm 그대로) ────────────────────────────────
def unlock(dap, base, tool, word_order, timeout=60.0, tool_prefix=()):
    """base = SJTAG_BASE. 반환: UnlockResult(status, state).
    status 는 ST_ALREADY / ST_OPEN_NO_SOFT_LOCK / ST_AUTHENTICATED.
    AUTH_PASS 를 못 얻고 인증을 끝까지 갔으면 예외."""
    # 모듈 API 로 직접 호출될 수 있으므로 진입부에서 timeout 을 검증한다.
    # (main 을 거치지 않으면 nan 이 poll_bit 를 무한 루프시킨다)
    if not valid_timeout(timeout):
        raise SecureJtagError(f"timeout 은 유한한 양수여야 한다 (받음: {timeout})",
                              EXIT_CONFIG)

    def A(off):
        return base + off

    dap.clear_sticky()          # 직전 다른 AP(DM) 접근이 남긴 sticky 를 지우고 시작
    state = rd(dap, A(OFF_STATE), "STATE 최초읽기")
    print(f"  [0] STATE={hx(state)}  HW={hx(rd(dap, A(OFF_HW_VERSION), 'HW'))}")
    if state & AUTH_PASS:
        print("  ✅ Secure JTAG 이미 unlock 됨 (최초 STATE 에 AUTH_PASS)")
        return UnlockResult(ST_ALREADY, state)

    w(dap, A(OFF_STATE), 0x2, "STATE<=0x2")
    state = rd(dap, A(OFF_STATE), "STATE")
    if not (state & SOFT_LOCK):
        print("  ✅ Secure JTAG 열림 (SOFT_LOCK 미설정 — 인증 불필요, AUTH_PASS 아님)")
        return UnlockResult(ST_OPEN_NO_SOFT_LOCK, state)

    print("  [1] PKC-based Secure JTAG 시작")
    if (state & STATE_INFO_MASK) or (state & RESPONSE_READY):
        print("  [2] 비초기 상태 → SW_RESET")
        w(dap, A(OFF_DBG_CONTROL), 0x1, "DBG_CONTROL<=SW_RESET")
        deadline = time.monotonic() + timeout
        while True:
            c = rd(dap, A(OFF_DBG_CONTROL), "DBG_CONTROL")
            if (c & SW_RESET_MASK) == 0:
                break
            if time.monotonic() >= deadline:
                raise SecureJtagError("SW_RESET 클리어 타임아웃")
            time.sleep(1.0)

    print("  [3] Challenge-Response 시작 (STATE<=0x1)")
    w(dap, A(OFF_STATE), 0x1, "STATE<=0x1")
    poll_bit(dap, A(OFF_STATE), REQUEST_READY, REQUEST_READY, timeout, "REQUEST_READY")

    print("  [4] 공개키 수신·주입")
    pub = order_words(run_tool(tool, PUBKEY_FLAGS, PUBKEY_WORDS, "pubkey", tool_prefix), word_order)
    for k, word in enumerate(pub):
        w(dap, A(OFF_REQUEST) + 4 * k, word, f"REQUEST[{k}]")
    time.sleep(0.5)
    poll_bit(dap, A(OFF_STATE), RESPONSE_READY, RESPONSE_READY, timeout,
             "RESPONSE_READY", abort_mask=INVALID_PUBKEY)

    print("  [5] Challenge(ChipID+Nonce) 읽기")
    chip0 = rd(dap, A(OFF_CHIP_ID0), "CHIP_ID0")
    chip1 = rd(dap, A(OFF_CHIP_ID1), "CHIP_ID1")
    nonce = [rd(dap, A(OFF_CHALLENGE) + 4 * i, f"Nonce[{i}]") for i in range(NONCE_WORDS)]
    challenge = CHALLENGE_PREFIX + [chip0, chip1] + nonce        # no[0..20]
    chal_args = [f"0x{x:08X}" for x in reversed(challenge)]       # no[20]..no[0]

    print("  [6] 서명 수신·주입")
    sig = order_words(run_tool(tool, SIGN_FLAGS + chal_args, SIG_WORDS, "sign", tool_prefix), word_order)
    for k, word in enumerate(sig):
        w(dap, A(OFF_RESPONSE) + 4 * k, word, f"RESPONSE[{k}]")

    print("  [7] Response Domain/LV0/LV1 기입")
    for off, name in ((OFF_RESP_DOMAIN, "DOMAIN"), (OFF_RESP_LV0, "LV0"),
                      (OFF_RESP_LV1, "LV1")):
        w(dap, A(off), RESPONSE_GRANT, f"RESP_{name}")
        time.sleep(0.1)

    print("  [8] AUTH_PASS 대기")
    state = poll_bit(dap, A(OFF_STATE), AUTH_PASS, AUTH_PASS, timeout, "AUTH_PASS")
    print("  ✅ Secure JTAG Authentication Done  (SJTAG_FINISH)")
    return UnlockResult(ST_AUTHENTICATED, state)


# ── DM 검증 (인증 전/후 A/B) ─────────────────────────────────────────
def classify_verdict(status, before, after):
    """DM A/B 결과를 unlock status 에 맞춰 해석한다. (exit_code, lines) 반환.
    ★ 인과("인증이 게이트를 열었다")는 **ST_AUTHENTICATED 일 때만** 말한다.
    before/after 는 read_dmstatus 결과 (raw, tag, alive) 또는 None."""
    b_alive = bool(before and before[2])
    a_alive = bool(after and after[2])

    if status == ST_AUTHENTICATED:
        if b_alive:
            return EXIT_CAUSE_UNPROVEN, [
                "⚠ 인증 전에도 dmstatus 가 유효했다 — DM 은 이미 열려 있었다. "
                "이 인증이 원인이라는 증거가 못 된다."]
        if a_alive:
            return EXIT_OK, [
                "★★★ 인증 전=무응답 → 후=유효(추정 경로). challenge-response 인증이 "
                "게이트를 여는 강한 증거 (STATUS §0.35 A/B). ⚠ stride 미검증이라 "
                "dmstatus 확정은 아니다."]
        return EXIT_VERIFY_WEAK, [
            "⚠ AUTH_PASS 는 떴으나 추정 dmstatus 경로에서 유효값을 못 얻었다. "
            "판단 가능한 것: '이 AP/stride 경로로는 유효 dmstatus 미확인'. "
            "DM 앞단 게이트가 더 있거나(리셋/전원/firewall) stride 가 틀렸을 수 있다."]

    if status == ST_ALREADY:
        # 이번 실행에서 인증을 수행하지 않았다 → 인과 판정 불가.
        return EXIT_CAUSE_UNPROVEN, [
            f"이미 unlock(AUTH_PASS) 상태였다. 이번 실행은 인증을 수행하지 않았으므로 "
            f"DM 접근({'유효' if a_alive else '무효'})은 **관찰**일 뿐 인과 판정 불가."]

    if status == ST_OPEN_NO_SOFT_LOCK:
        # 수행한 쓰기는 STATE<=0x2 뿐, AUTH_PASS 아님.
        return EXIT_CAUSE_UNPROVEN, [
            f"SOFT_LOCK 미설정으로 열린 설정(AUTH_PASS 아님). 수행한 쓰기는 STATE<=0x2 "
            f"초기화뿐이다. DM 접근({'유효' if a_alive else '무효'})은 challenge-response "
            f"인과가 아니다."]

    # 알 수 없는 status — 조용히 오분류하지 않고 드러낸다(오타/신규 상태 방지).
    raise ValueError(f"알 수 없는 unlock status: {status!r}")


def read_dmstatus(dap, core_base):
    """core_base 에 맞는 MEM-AP 로 dmstatus **후보** 주소를 읽는다.
    반환 (raw, tag, alive). alive 는 '추정 경로에서 유효해 보임' 이지 확정 아님."""
    dm_ap = DM_AP.get(core_base)
    if dm_ap is None:
        return None, f"core_base 0x{core_base:X} 매핑 미상", False
    v = dap.mem_read32(dm_ap, core_base + DMSTATUS_OFF)
    dap.clear_sticky()          # DM(APBAP1) 접근 실패가 이후 APBAP3 접근을 오염시키지 않게
    if v is None:
        return None, "읽기실패", False
    ver = v & 0xF
    alive = (ver in (2, 3)) and (v not in DEAD_FINGERPRINTS)
    tag = (f"version={ver} " + ("유효(추정 경로)" if alive else "무응답/무효 패턴"))
    return v, tag, alive


def dm_scan(dap, core_base, window=0x100):
    """DM 의 AP(APBAP1/2)로 core_base 주변을 훑어 RISC-V dmstatus(version 2/3)를 **실측**한다.
    dmstatus 는 [3:0]=version(2=0.13,3=1.0), [31:23]=reserved(0), [7]=authenticated 로
    시그니처가 뚜렷하다. auth 후 이게 잡히면 'AUTH_PASS 가 DM 을 열었다' 확정.
    read-only(dmcontrol 등 쓰기 없음) — 인증 카운터 무관."""
    dm_ap = DM_AP.get(core_base)
    if dm_ap is None:
        print(f"  [dm-scan] core_base 0x{core_base:X} AP 매핑 미상")
        return []
    print(f"\n  [dm-scan] DM AP(DP:0x{dm_ap:X}) @ 0x{core_base:X} +0..0x{window:X} 스캔:")
    found = []
    for off in range(0, window, 4):
        v = dap.mem_read32(dm_ap, core_base + off)
        if v is None:
            dap.clear_sticky()                  # 실패가 다음 읽기를 연쇄로 죽이지 않게
            continue
        if v in DEAD_FINGERPRINTS:
            continue
        if (v & 0xF) in (2, 3) and (v >> 23) == 0:        # dmstatus 시그니처
            ver, auth = v & 0xF, (v >> 7) & 1
            allh, allr = (v >> 9) & 1, (v >> 11) & 1
            print(f"    +0x{off:03X} = 0x{v:08X}  ← dmstatus 후보 "
                  f"(version={ver} authenticated={auth} allhalted={allh} allrunning={allr})")
            found.append((off, v))
    if found:
        print(f"  [dm-scan] ✅ dmstatus 후보 {len(found)}개 — AUTH_PASS 가 DM 을 열었다(강한 증거). "
              f"JLinkExe 엔 이 DM base(0x{core_base:X})/AP 를 알려주면 접근 가능.")
    else:
        print("  [dm-scan] ✗ 유효 dmstatus 없음 — DM 이 비활성(dmactive=0)이거나 이 AP/주소로 "
              "안 열림. --dm-activate 로 dmcontrol.dmactive=1 을 써보면 갈린다.")
    return found


def dm_activate(dap, core_base):
    """RISC-V DM 을 dmcontrol.dmactive(bit0)=1 로 리셋에서 깨운다. dmactive=0 이면 DM 이
    리셋 상태라 dmstatus 등이 0 으로 읽힌다. auth 로 DM 게이트가 열렸다면 이 write 가 먹고
    dmstatus 가 version 2/3 으로 살아난다. 안 먹으면(리드백 0) DM 이 이 AP/주소로 안 열린 것.
    ★ dmactive 는 코어를 멈추지 않는 표준 DM 기동 write — SJTAG 인증과 무관(카운터 무소모)."""
    dm_ap = DM_AP.get(core_base)
    if dm_ap is None:
        print(f"  [dm-activate] core_base 0x{core_base:X} AP 매핑 미상")
        return False
    print(f"\n  [dm-activate] dmcontrol(@0x{core_base + DMCONTROL_OFF:X}) <= dmactive=1")
    dap.clear_sticky()
    ok = dap.mem_write32(dm_ap, core_base + DMCONTROL_OFF, 0x1)
    dap.clear_sticky()
    back = dap.mem_read32(dm_ap, core_base + DMCONTROL_OFF)
    st = dap.mem_read32(dm_ap, core_base + DMSTATUS_OFF)
    dap.clear_sticky()
    print(f"    write={'OK' if ok else '실패'}  dmcontrol 리드백={hx(back)}  dmstatus={hx(st)}")
    if back is not None and (back & 0x1) and st is not None and (st & 0xF) in (2, 3):
        print(f"    ✅ DM 활성화 성공 (dmactive=1, dmstatus version={st & 0xF}) — "
              "AUTH_PASS 가 DM 을 열었다 확정. JLinkExe 엔 DM base/AP 만 알려주면 됨.")
        return True
    if back is None or not (back & 0x1):
        print("    ✗ dmcontrol write 가 안 먹음(리드백에 dmactive 없음) — DM 이 이 AP/주소로 "
              "안 열림. 추가 게이트(리셋/전원/firewall) 또는 DM base/AP 재확인 필요.")
    else:
        print("    ⚠ dmactive 는 섰으나 dmstatus 무효 — DM 코어측 별도 문제(리셋 홀드 등).")
    return False


def _abstract_exec(dap, dm_ap, core_base, cmd):
    """abstract command 1개 실행: cmderr 클리어 → command 기입 → busy 대기 → cmderr 반환.
    반환 0=성공, >0=cmderr 코드, -1=읽기실패."""
    acs = core_base + DM_ABSTRACTCS_OFF
    dap.mem_write32(dm_ap, acs, 0x00000700)                # cmderr W1C 클리어
    if not dap.mem_write32(dm_ap, core_base + DM_COMMAND_OFF, cmd):
        return -1
    st = None
    for _ in range(40):
        st = dap.mem_read32(dm_ap, acs)
        if st is not None and not ((st >> 12) & 1):        # busy=0
            break
        time.sleep(0.005)
    return (st >> 8) & 7 if st is not None else -1


def _dm_read_csr(dap, dm_ap, core_base, regno):
    """abstract command(access register)로 CSR/GPR 직접 읽기. aarsize 32→64 시도.
    성공 시 값, 실패 None. (일부 DM 은 CSR 직접 접근 미지원 → progbuf 필요)"""
    for aarsize in (2, 3):
        cmd = (aarsize << 20) | (1 << 17) | (regno & 0xFFFF)   # transfer=1, read
        if _abstract_exec(dap, dm_ap, core_base, cmd) == 0:
            return dap.mem_read32(dm_ap, core_base + DM_DATA0_OFF)
    return None


def _dm_read_csr_progbuf(dap, dm_ap, core_base, csr):
    """progbuf 경유 CSR 읽기 — 직접 abstract CSR 접근이 미지원(cmderr=2)일 때.
    progbuf 에 `csrr s0,csr; ebreak` 를 넣고 postexec 로 실행(→ s0=csr), 그 뒤 s0(x8)을
    abstract 로 읽는다. J-Link 가 progbuf 코어에서 misa 를 읽는 방식과 동일."""
    pb0 = core_base + (0x20 << 2)                          # progbuf0 @ DMI 0x20
    csrr_s0 = (csr << 20) | (0b010 << 12) | (8 << 7) | 0x73   # csrrs x8, csr, x0
    if not dap.mem_write32(dm_ap, pb0, csrr_s0):
        return None
    dap.mem_write32(dm_ap, pb0 + 4, 0x00100073)           # ebreak
    if _abstract_exec(dap, dm_ap, core_base, (2 << 20) | (1 << 18)) != 0:   # postexec 실행
        return None
    if _abstract_exec(dap, dm_ap, core_base, (2 << 20) | (1 << 17) | 0x1008) != 0:  # read x8
        return None
    return dap.mem_read32(dm_ap, core_base + DM_DATA0_OFF)


def dm_halt(dap, core_base, hart=0):
    """dmcontrol.haltreq=1 로 hart 를 halt 시도 → dmstatus.allhalted 확인 후 resume 한다.
    J-Link 의 'identify'(=halt 후 misa 읽기)가 하는 halt 를 직접 재현해서, 코어 디버그가
    auth 후 실제로 되는지(=J-Link 'Failed to identify' 는 J-Link 설정/시퀀스 문제) vs
    안 되는지(=코어측 추가 게이트)를 가른다.
    ★ 잠깐 코어를 멈췄다 재개한다(디버그 표준 동작). SJTAG 인증 카운터 무관."""
    dm_ap = DM_AP.get(core_base)
    if dm_ap is None:
        print(f"  [dm-halt] core_base 0x{core_base:X} AP 매핑 미상")
        return False
    HALTREQ, RESUMEREQ, DMACTIVE = 1 << 31, 1 << 30, 0x1
    hs = (hart & 0x3FF) << 16                       # hartsello (dmcontrol[25:16])
    ctl, sts = core_base + DMCONTROL_OFF, core_base + DMSTATUS_OFF
    print(f"\n  [dm-halt] hart{hart} haltreq=1 (코어 잠깐 멈춤)…")
    dap.clear_sticky()
    dap.mem_write32(dm_ap, ctl, HALTREQ | DMACTIVE | hs)
    st = None
    for _ in range(30):
        time.sleep(0.02)
        st = dap.mem_read32(dm_ap, sts)
        if st is not None and (st >> 9) & 1:       # allhalted
            break
    halted = bool(st and (st >> 9) & 1)
    print(f"    dmstatus={hx(st)}  allhalted={int(halted)} "
          f"anyhalted={int(bool(st and (st >> 8) & 1))}")
    dap.mem_write32(dm_ap, ctl, DMACTIVE | hs)      # haltreq 내림
    misa = acs0 = acs1 = None
    misa_via = ""
    if halted:
        acs0 = dap.mem_read32(dm_ap, core_base + DM_ABSTRACTCS_OFF)   # 능력(progbuf/datacount)
        misa = _dm_read_csr(dap, dm_ap, core_base, 0x301)             # ① abstract 직접
        if misa is not None:
            misa_via = "abstract"
        else:                                                        # ② progbuf 폴백
            misa = _dm_read_csr_progbuf(dap, dm_ap, core_base, 0x301)
            if misa is not None:
                misa_via = "progbuf"
        acs1 = dap.mem_read32(dm_ap, core_base + DM_ABSTRACTCS_OFF)   # 명령 후 cmderr
        dap.mem_write32(dm_ap, ctl, RESUMEREQ | DMACTIVE | hs)        # 코어 원상복구(resume)
        time.sleep(0.05)
        dap.mem_write32(dm_ap, ctl, DMACTIVE | hs)
    dap.clear_sticky()
    if not halted:
        print("  [dm-halt] ✗ halt 안 됨 — DM 은 열렸으나 코어 halt 가 안 됨 = 코어측 추가 게이트.")
        return False
    # abstractcs 디코드 — abstract command 이 왜 되나/안 되나
    if acs0 is not None:
        ERRS = {0: "none", 1: "busy", 2: "not-supported", 3: "exception",
                4: "halt/resume", 5: "bus", 7: "other"}
        datacount, progbuf = acs0 & 0xF, (acs0 >> 24) & 0x1F
        cmderr = (acs1 >> 8) & 7 if acs1 is not None else -1
        print(f"    abstractcs=0x{(acs1 or acs0):08X}  datacount={datacount} "
              f"progbufsize={progbuf} cmderr={cmderr}({ERRS.get(cmderr, '?')})")
    if misa is not None:
        exts = "".join(c for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ") if misa & (1 << i))
        print(f"    misa=0x{misa:08X}  확장=[{exts}]  (읽기경로={misa_via})")
        print(f"  [dm-halt] ✅ halt + misa 읽기 성공(via {misa_via}) — J-Link 의 identify 를 "
              "우리가 완수. 코어는 progbuf 로 읽힌다.")
        if misa_via == "progbuf":
            print("  → J-Link 도 이 progbuf 코어에서 misa 를 읽을 수 있어야 한다. 'Failed to "
                  "identify' 는 J-Link 가 progbuf 방식을 안 쓰거나 connect 리셋으로 어긋난 것. "
                  "JLinkScript 에 UseMemAccTypeWhileCoreHalted = MEM_ACC_PROG_BUF 명시 + "
                  "reset 없는 connect 를 시도하라.")
        return True
    # misa 실패 — 원인을 abstractcs 로 안내
    if acs0 is not None and (acs0 & 0xF) == 0:
        print("  [dm-halt] ⚠ datacount=0 — abstract data 레지스터가 없다(이 DM 은 abstract "
              "레지스터 접근 미지원). J-Link 는 progbuf/SBA 로 접근해야 함.")
    if acs0 is not None and ((acs0 >> 24) & 0x1F) == 0:
        print("  [dm-halt] ⚠ progbufsize=0 — program buffer 없음. abstract+progbuf 둘 다 없으면 "
              "레지스터 접근은 SBA/AAM 로만 → J-Link mem-access-type 설정이 필요.")
    print("  [dm-halt] halt 는 성공. misa(abstract cmd) 실패 원인 = 위 abstractcs 참고. "
          "J-Link 도 같은 이유로 identify 실패한 것 — DM 능력에 맞는 접근방식을 J-Link 에 지정해야.")
    return True


# ── 세션 준비 — CMM 방식(prepare-only, connect 없음) ─────────────────
def diag_sweep(dap):
    """현재 전원 상태로 6개 AP 의 IDR 을 훑는다 — '인증/디버그전원 없이 어디에 닿나'.
    APBAP3(SJTAG)가 디버그 도메인이라 지금 전원으론 못 닿는지, 아니면 시스템계열
    AP 는 닿는지, 아니면 전부 실패(=링크/전원요청 자체 문제)인지를 가른다."""
    print("\n  [diag] AP IDR 스윕 (지금 전원으로 닿는 AP 판별):")
    live, susp, fail = 0, 0, 0
    for name, base, kind in AP_MAP:
        idr = dap.ap_read(base, OFF_IDR)
        if idr is None:
            cls, fail = "실패(None)", fail + 1
        elif idr == 0x80000000:
            cls, susp = "SUSPECT(읽기에러)", susp + 1
        elif idr in (0, 0xFFFFFFFF):
            cls, fail = f"{hx(idr)}(미응답)", fail + 1
        else:
            cls, live = "LIVE", live + 1
        print(f"    {name:8}(0x{base:X}, {kind:7}) IDR={hx(idr):>12}  [{cls}]")
    print(f"  [diag] sticky: {dap.sticky()}")
    print(f"  [diag] LIVE {live} / SUSPECT {susp} / 실패 {fail}")
    if live == 0:
        print("  → 아무 AP도 안 닿음: 도메인 논쟁 이전에 링크/전원요청부터 문제. "
              "(위 'CDBG req 안 섬' 경고와 함께 보면 전원요청 write 경로 의심)")
    elif susp or fail:
        print("  → 일부만 닿음: LIVE 인 AP = 지금 전원으로 접근 가능. "
              "APBAP3만 실패고 AXI/AHB가 LIVE면 '인증경로=시스템도메인 AP' 가설↑.")
    else:
        print("  → 모든 AP LIVE: 디버그 전원이 이미 확보됨. APBAP3 인증 진행 가능.")


def read_burst(dap, base, passes, retries=3, delay=0.0):
    """write 루프와 동일한 주소(REQUEST 34워드)를 passes 회 연속 읽어 AP transport
    안정성을 실증한다. reads 는 상태머신을 안 건드리므로 **인증 카운터 무소모**.

    드롭 순간 **DPIDR·CTRL/STAT 를 캡처**해 원인을 가른다:
      - DPIDR 도 깨짐 → escape/reset 이 링크/DP 까지 리셋 = cJTAG KEEPER escape.
      - DPIDR 정상, CDBG ACK 만 0 → 전원 도메인만 회수(전면 링크리셋 아님).
    delay>0 이면 읽기 사이에 쉰다 — 드롭이 '시간 기반'인지 '트랜잭션 기반'인지 판별용."""
    addrs = [OFF_REQUEST + 4 * k for k in range(PUBKEY_WORDS)]     # 34워드
    print(f"\n  [read-burst] REQUEST {PUBKEY_WORDS}워드 × {passes}회"
          + (f", 읽기간 delay {delay * 1000:.0f}ms" if delay else "")
          + " (카운터 무소모):")
    total = recovered = hard_fail = 0
    first_hard = None
    for p in range(passes):
        for k, off in enumerate(addrs):
            total += 1
            ok = False
            for attempt in range(retries):
                if dap.mem_read32(APBAP3_BASE, base + off) is not None:
                    ok = True
                    if attempt:
                        recovered += 1
                    break
                dap.clear_sticky()
            if not ok:
                hard_fail += 1
                if first_hard is None:               # 첫 드롭 순간 링크/전원 캡처
                    first_hard = (p, k, dap.dp_read(0), dap.dp_read(1))
            if delay:
                time.sleep(delay)
    print(f"  [read-burst] 총 {total}, 재시도복구 {recovered}, 최종실패 {hard_fail}")
    if hard_fail == 0:
        print(f"  → 재시도가 일시적 AP 에러를 전부 흡수. {PUBKEY_WORDS}워드 완주 가능 확신↑ "
              f"(복구 {recovered}회 = 실제로 sticky 가 떴다는 증거)")
        return True
    p0, k0, dpidr, ctrl = first_hard
    tx = p0 * PUBKEY_WORDS + k0
    print(f"  [drop] 첫 드롭 @ pass {p0} word {k0} (tx≈{tx})  "
          f"DPIDR={hx(dpidr)}  CTRL/STAT={hx(ctrl)}")
    if dpidr is None or dpidr in (0x80000000, 0x0, 0xFFFFFFFF):
        print("  → ★ DPIDR도 깨짐: escape/reset 이 링크/DP까지 리셋 = cJTAG KEEPER escape 강력 시사.")
    elif ctrl is not None and not (ctrl & (1 << 29)):
        print("  → ★ DPIDR 정상인데 CDBGPWRUPACK만 0: 전면 링크리셋 아님 = 전원 도메인만 회수 "
              "(KEEPER escape보다 전원게이트 쪽 원인).")
    else:
        print("  → DPIDR·CTRL 정상인데 AP만 실패: AP/APB 수준 문제(전원·링크 아님).")
    return False


def prepare_session(lk, power, tap_note, tif_init=True, strict=True):
    """CMM 의 'DAPDBGPWRUPREQ ON / DAPSYSPWRUPREQ OFF / sys.m.prepare' 재현.
    connect() 를 하지 않는다 — CPU 탐지가 TAP/reset 을 건드리는 것을 피한다.
    raw AP 접근은 DAP 전원만으로 성립함이 확인돼 있다(open_dap 주석).

    ★ connect() 가 없으면 **cJTAG TIF 를 초기화하는 주체가 없다.**
      standalone.py:1276 에서 이미 확인된 버그 — connect 없이
      perform_tif_init=False 면 모든 읽기가 None 이 된다. 그래서 이 경로는
      **최초 활성화이므로 tif_init=True** 가 기본이다.

    ⚠ NOKEEPER: CMM 은 `CJTAGFLAGS NOKEEPER USEOAC` 로 붙는다. CJTAG_MODE=1 이
      USEOAC 계열에 대응하나, **NOKEEPER 에 해당하는 J-Link 설정은 여기 없다.**
      이 J-Link HW 가 no-KEEPER workaround 를 자동 적용하지 않으면 T32 와 물리
      링크 조건이 달라 인증 코드가 맞아도 실패할 수 있다(ASK.md §6). 이건 코드로
      막을 수 없는 transport 변수라 read-only probe 에서 먼저 확인해야 한다."""
    if not lk.apply_settings():
        raise SecureJtagError("설정(AP map) 적용 실패", EXIT_CONFIG)
    jl = lk.jl
    try:
        jl.coresight_configure(ir_pre=0, dr_pre=0, ir_post=0, dr_post=0,
                               ir_len=4, perform_tif_init=tif_init)
    except TypeError:
        # 구형 pylink 가 이 kwargs 를 모르는 **인자 호환성** 문제만 fallback.
        # 인자 없는 fallback 은 switching sequence 를 출력한다(= tif_init on).
        # 그래서 off 를 요청했으면 fallback 하지 않고 실패시킨다(리뷰 #2).
        if not tif_init:
            raise SecureJtagError(
                "tif-init=off configure 실패 — 인자없는 fallback 은 switching "
                "sequence 를 출력(on)하므로 중단", EXIT_CONFIG)
        try:
            jl.coresight_configure()
        except Exception as e:      # fallback 자체 실패도 EXIT_CONFIG 로 분류
            raise SecureJtagError(f"coresight_configure fallback 실패: {e}", EXIT_CONFIG)
    except Exception as e:
        # 통신/J-Link 오류는 호환성 문제가 아니다 — 원 오류로 실패시킨다.
        raise SecureJtagError(f"coresight_configure 실패: {e}", EXIT_CONFIG)

    # req = 요청 비트(CSYS=bit30, CDBG=bit28), need = 진행 게이트로 요구하는 ACK.
    #   dbg-only : CDBG 요청, CDBG ACK 필수  (기존 — 비-secure 타깃 기준)
    #   both     : 둘 다 요청, 둘 다 ACK 필수
    #   sys-only : 둘 다 **요청**하되(CDBG req 를 미리 걸어둬야 인증 후 ACK 가 올라옴,
    #              T32 clavis 의 DAPDBGPWERUPREQ ON 과 동일), 진행은 **CSYS ACK 만**
    #              요구. → secure 타깃에서 CDBG ACK 가 인증 뒤에야 뜨는 가설을 시험.
    if power == "dbg-only":
        req, need = 0x10000000, (1 << 29)                     # CDBGPWRUPACK
    elif power == "sys-only":
        req, need = 0x50000000, (1 << 31)                     # 요청=SYS+DBG, 진행=CSYS ACK
    else:
        req, need = 0x50000000, (1 << 29) | (1 << 31)         # CDBG+CSYSPWRUPACK
    # ── 콜드 warmup ──────────────────────────────────────────────────
    # 실측: cJTAG 활성화 직후엔 DP 가 아직 동기 전이라 첫 트랜잭션(전원요청 write)이
    # 통째로 안 먹는다(CTRL/STAT=0x0, req 리드백 0). 그래서 DP SELECT/DPIDR priming 으로
    # DP 를 깨우고, ABORT·req 를 **주기적으로 재기입**하며 길게 폴링해 warmup 중에 전원을
    # latch 시킨다. (예전엔 --diag 의 AP IDR 스윕이 이 warmup 을 우연히 대신 해줬다.)
    jl.coresight_write(2, 0x00000000, ap=False)               # DP SELECT=0 (CTRL/STAT 뱅크)
    for _ in range(3):
        jl.coresight_read(0, ap=False)                        # DPIDR priming (반환 버림)
    last, ack = None, None
    for i in range(80):
        if i % 4 == 0:                                        # 주기적 재-어서트
            jl.coresight_write(0, 0x0000001E, ap=False)       # ABORT: sticky 클리어
            jl.coresight_write(1, req, ap=False)              # 전원요청 재기입
        time.sleep(0.02)
        v = jl.coresight_read(1, ap=False)
        if v is not None and v >= 0:
            last = v & 0xFFFFFFFF
            if (v & need) == need:
                ack = last
                break
    report = ack if ack is not None else last
    # REQ 비트가 리드백에 서는지까지 찍는다 — "요청이 실제로 latch됐나"가 핵심 진단.
    if report is not None:
        b = lambda n: "1" if report & (1 << n) else "0"
        print(f"  [prepare] CTRL/STAT={hx(report)} (요청={power}, TAP={tap_note})  "
              f"CSYS req/ack={b(30)}/{b(31)}  CDBG req/ack={b(28)}/{b(29)}")
        if report & (1 << 28) == 0 and req & (1 << 28):
            print("    ⚠ CDBG req 를 썼는데 리드백에 안 섬 — 전원요청 write 가 "
                  "안 먹는다(ACK 실패의 진짜 원인일 수 있음).")
    if ack is None:
        msg = (f"DAP 전원 ACK 실패 (power={power}, 필요비트=0x{need:08X}, "
               f"CTRL/STAT={hx(report)})")
        if strict:
            raise SecureJtagError(msg, EXIT_CONNECT_FAIL)
        print(f"  ⚠ {msg} — diag 로 계속")
        lk.ctrl_stat = report
        lk.dap_power_ok = False
        return report
    lk.ctrl_stat = ack
    lk.dap_power_ok = True
    if power == "sys-only" and not (ack & (1 << 29)):
        print("    → CDBG 미ACK (예상됨). 시스템 전원으로 APB 인증 선수행 후 "
              "CDBGPWRUPACK 전이를 관찰한다.")
    return ack


def gen_jlinkscript(out_path, template="sf_e76.JLinkScript.template"):
    """sjtag_addrs.json 값으로 sf_e76.JLinkScript 를 생성한다 — 주소 단일 출처(json)
    유지 + 수동 편집 제거. 템플릿의 placeholder 를 실제 AP/DM 주소로 치환한다.
    (오프라인 — HW 불필요. 생성물은 .gitignore 라 실주소는 json 에만 남는다.)"""
    subs = {"<APBAP1_DP_BASE>": f"0x{APBAP1_BASE:X}",       # DM 붙은 APB-AP
            "<DM_BASE>": f"0x{CORE_BASE_MAIN:X}"}           # DM/DMI 위치
    try:
        with open(template, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        print(f"템플릿 못 읽음({template}): {e}", file=sys.stderr)
        return EXIT_CONFIG
    for k, v in subs.items():
        if k not in text:
            print(f"⚠ 템플릿에 placeholder {k} 없음", file=sys.stderr)
        text = text.replace(k, v)

    # ── N-Trace 설정(json "trace" 있으면 자동 삽입) — ViewNexusTracedump.cmm 등가 ──
    #   RISCV_SetTEBaseAddr(인코더)/SetTFBaseAddr(funnel)/SetSRAMBaseAddr(온칩 sink).
    #   MemTypeToUse: 2=SBA(T32 SB:), 1=DMI, 0=Core. 커버리지(Ozone Trace)용.
    tr = RISCV_ADDRS.get("trace", {})
    trace_msg = ""
    if tr.get("te_base") and tr.get("sram_sink_base"):
        mt = tr.get("mem_type", 2)
        lines = [f'  JLINK_ExecCommand("RISCV_SetTEBaseAddr = 0x{_a(tr["te_base"]):X} '
                 f'MemTypeToUse={mt}");']
        if tr.get("funnel_base"):
            lines.append(f'  JLINK_ExecCommand("RISCV_SetTFBaseAddr = '
                         f'0x{_a(tr["funnel_base"]):X} MemTypeToUse={mt}");')
        lines.append(f'  JLINK_ExecCommand("RISCV_SetSRAMBaseAddr = '
                     f'0x{_a(tr["sram_sink_base"]):X} MemTypeToUse={mt}");')
        block = "\n  // ── N-Trace (커버리지) ──\n" + "\n".join(lines) + "\n"
        # ConfigTargetSettings 의 return 0; 앞에 삽입.
        text = text.replace("\n  return 0;", block + "\n  return 0;", 1)
        trace_msg = f", TE=0x{_a(tr['te_base']):X}, SRAM=0x{_a(tr['sram_sink_base']):X}"

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        print(f"생성 실패({out_path}): {e}", file=sys.stderr)
        return EXIT_CONFIG
    print(f"생성: {out_path}  (APBAP1={subs['<APBAP1_DP_BASE>']}, "
          f"DM_BASE={subs['<DM_BASE>']}{trace_msg})  ← sjtag_addrs.json 값")
    return EXIT_OK


# ── main ─────────────────────────────────────────────────────────────
def main():
    ap = add_common_args(argparse.ArgumentParser(
        description="SF-E76 Secure JTAG (clavis) 인증 — J-Link 포팅"))
    ap.add_argument("--base", type=lambda x: int(x, 0), default=None,
                    help="SJTAG_BASE (clavis 의 &base). CONFIG 값보다 우선")
    ap.add_argument("--tool", default=None, help="서명 도구 경로. CONFIG 값보다 우선")
    ap.add_argument("--tool-prefix", default=None,
                    help="서명 도구 앞에 붙일 런처(예: 'wine'). 리눅스에서 .exe 실행 시. "
                         "CONFIG TOOL_PREFIX 보다 우선. shlex 로 분리")
    ap.add_argument("--execute", action="store_true",
                    help="★ 실제 인증(쓰기)을 한다. 없으면 read-only probe 만.")
    ap.add_argument("--word-order", choices=("t32-negative", "stdout"),
                    default=_RT_WORD_ORDER,
                    help="공개키/서명 워드 주소순서. --execute 시 필수.")
    ap.add_argument("--power", choices=("dbg-only", "both", "sys-only"),
                    default="dbg-only",
                    help="DAP 전원요청. dbg-only=CDBG ACK 필수(기존). "
                         "sys-only=CSYS ACK 만으로 진행(secure 타깃: 인증 후 CDBG 열림 가설). "
                         "both=둘 다 ACK 필수")
    ap.add_argument("--tap-script", choices=("on", "off"), default="off",
                    help="수동 TAP 체인 선언. 기본 off = CMM 방식(NOKEEPER USEOAC만). "
                         "⚠ STATUS §1.1 은 ScriptFile 경로를 폐기로, sfe76_link 는 "
                         "수동체인을 현재 fix 로 본다 — 실기서 둘 다 시험할 것.")
    ap.add_argument("--tif-init", choices=("on", "off"), default="on",
                    help="cJTAG TIF 초기화. 기본 on — connect() 없이 붙으므로 "
                         "TIF 를 초기화할 주체가 이것뿐이다(standalone.py:1276). "
                         "off 는 이미 활성화된 링크 재사용 실험용.")
    ap.add_argument("--timeout", type=float, default=60.0, help="각 폴링 단계 타임아웃(초)")
    ap.add_argument("--diag", action="store_true",
                    help="전원/AP 진단: CDBG 요청 latch 여부 + 6개 AP IDR 스윕 + sticky. "
                         "전원 ACK 실패해도 죽지 않고 계속(어디에 닿는지 실측)")
    ap.add_argument("--analyze-pubkey", action="store_true",
                    help="오프라인: 툴 -s3 를 2회 실행해 정적키 동일성 + word-order 후보 분석 "
                         "(HW/J-Link/인증 불필요, 카운터 무소모). --tool 필요")
    ap.add_argument("--gen-jlinkscript", nargs="?", const="sf_e76.JLinkScript",
                    default=None, metavar="PATH",
                    help="오프라인: sjtag_addrs.json 값으로 JLinkScript 생성(수동편집 불필요). "
                         "기본 출력 sf_e76.JLinkScript. HW 불필요")
    ap.add_argument("--read-burst", type=int, default=0, metavar="N",
                    help="transport 검증: REQUEST 34워드를 N회 연속 읽어 AP 안정성 실증 "
                         "(read-only, 인증 카운터 무소모). 드롭 시 DPIDR·CTRL/STAT 캡처")
    ap.add_argument("--burst-delay", type=float, default=0.0, metavar="MS",
                    help="read-burst 읽기 사이 지연(ms). 드롭이 시간기반인지 tx기반인지 판별용")
    ap.add_argument("--dm-scan", action="store_true",
                    help="DM 스캔: DM AP(APBAP1/2)로 core_base 주변을 읽어 RISC-V dmstatus"
                         "(version 2/3) 실측. auth 후 DM 열림 확정용(read-only). 인증 잔존 시 단독 사용 가능")
    ap.add_argument("--dm-window", type=lambda x: int(x, 0), default=0x100, metavar="N",
                    help="dm-scan 스캔 폭(기본 0x100)")
    ap.add_argument("--dm-activate", action="store_true",
                    help="DM 기동: dmcontrol.dmactive=1 을 써 DM 을 리셋해제 후 dmstatus 확인. "
                         "auth 잔존 시 단독으로 'DM 열림' 확정용(표준 write, 인증 무관)")
    ap.add_argument("--dm-halt", action="store_true",
                    help="hart 를 halt 시도(dmcontrol.haltreq)→allhalted 확인 후 resume. "
                         "J-Link 'Failed to identify'가 J-Link 설정 문제인지 코어측 게이트인지 판별. "
                         "★코어 잠깐 멈춤(인증 무관)")
    ap.add_argument("--scan", action="store_true",
                    help="probe 진단: base 기준 SJTAG 알려진 오프셋들을 읽어 "
                         "default-slave/live 분류. --scan-window 주면 base 주변도 스윕.")
    ap.add_argument("--scan-window", type=lambda x: int(x, 0), default=0,
                    help="--scan 시 base±window 를 step 으로 훑어 live 후보 base 탐색(0=끔).")
    ap.add_argument("--scan-step", type=lambda x: int(x, 0), default=0x1000,
                    help="--scan-window 스윕 간격 (기본 0x1000).")
    a = ap.parse_args()

    # ★ 기밀 주소 맵이 실제 값인지 확인. placeholder(example)면 실기 불가.
    if not ADDRS_REAL:
        print("주소 맵 미설정: sjtag_addrs.example.json 을 sjtag_addrs.json 으로 복사해 "
              "실제 T32/clavis 값으로 채우세요 (이 파일은 .gitignore 됩니다).", file=sys.stderr)
        return EXIT_CONFIG

    # 이 도구의 커버리지 대상은 hcore(=CORE_BASE_MAIN). 사용자가 --core-base 를
    # 명시하지 않았으면 Ncore 기본값 대신 MAIN 으로 바꾼다.
    if not any(x == "--core-base" or x.startswith("--core-base=") for x in sys.argv[1:]):
        a.core_base = CORE_BASE_MAIN

    base = a.base if a.base is not None else SJTAG_BASE
    tool = a.tool if a.tool is not None else SIGN_TOOL
    prefix_str = a.tool_prefix if a.tool_prefix is not None else TOOL_PREFIX
    try:
        tool_prefix = shlex.split(prefix_str or "")
    except ValueError as e:
        print(f"--tool-prefix 파싱 실패(따옴표 확인): {e}", file=sys.stderr)
        return EXIT_CONFIG

    # ── 오프라인 JLinkScript 생성 — HW/J-Link 불필요 ──
    if a.gen_jlinkscript is not None:
        if not ADDRS_REAL:
            print("⚠ 실제 sjtag_addrs.json 이 아니라 placeholder(example) — 생성 무의미. "
                  "실기 값 채운 json 에서 실행하라.", file=sys.stderr)
            return EXIT_CONFIG
        return gen_jlinkscript(a.gen_jlinkscript)

    # ── 오프라인 pubkey 분석 — HW/J-Link 없이 즉시 (base 불필요) ──
    if a.analyze_pubkey:
        if tool is None:
            print("--analyze-pubkey 에는 --tool <서명도구> 가 필요하다", file=sys.stderr)
            return EXIT_CONFIG
        try:
            return analyze_pubkey(tool, tool_prefix)
        except SecureJtagError as e:
            print(f"  pubkey 분석 실패: {e}")
            return e.exit_code

    if base is None:
        print("설정 필요: --base 0x.... (또는 CONFIG SJTAG_BASE)", file=sys.stderr)
        return EXIT_CONFIG
    # base 유효성은 J-Link 를 열기 **전에** 본다(fail-fast + CONFIG 오타 방어).
    ok_base, reason = valid_base(base)
    if not ok_base:
        print(f"--base/CONFIG 오류: {reason}", file=sys.stderr)
        return EXIT_CONFIG
    if a.execute:
        if tool is None:
            print("--execute 에는 --tool <서명도구> 가 필요하다", file=sys.stderr)
            return EXIT_CONFIG
        if a.word_order is None:
            print("--execute 에는 --word-order {t32-negative|stdout} 가 필요하다",
                  file=sys.stderr)
            return EXIT_CONFIG
        if not tool_prefix and str(tool).lower().endswith(".exe") \
                and sys.platform != "win32":
            print("  ⚠ 도구가 .exe 인데 리눅스에서 런처 없이 직접 exec 하려 한다. "
                  "실행 안 되면 --tool-prefix wine 를 붙여라.", file=sys.stderr)
    if a.core_base not in DM_AP:
        print(f"core_base 0x{a.core_base:X} 는 DM-AP 매핑에 없다 "
              f"(가능: {', '.join(hex(k) for k in DM_AP)})", file=sys.stderr)
        return EXIT_CONFIG
    if not valid_timeout(a.timeout):
        print(f"--timeout 은 유한한 양수여야 한다 (받음: {a.timeout})", file=sys.stderr)
        return EXIT_CONFIG

    mode = "EXECUTE(쓰기)" if a.execute else "PROBE(read-only)"
    print(f"\n{'=' * 66}\n {VERSION}  [{mode}]\n{'=' * 66}")
    print(f"  SJTAG_BASE=0x{base:X} (APBAP3 DP:0x{APBAP3_BASE:X})  tool={tool}"
          + (f"  launcher={' '.join(tool_prefix)}" if tool_prefix else ""))
    print(f"  DM 검증 CoreBase=0x{a.core_base:X}→AP DP:0x{DM_AP[a.core_base]:X}  "
          f"power={a.power}  tif-init={a.tif_init}  tap={a.tap_script}  "
          f"word-order={a.word_order}")

    lk = Link(core_base=a.core_base, hart=a.hart, device=a.device,
              serial=a.serial, ap_count=getattr(a, "ap_count", None))
    # 컨텍스트 매니저(__enter__)는 open(tap_script=True) 를 강제하므로 쓰지 않는다.
    # tap_script 를 우리가 정해서 직접 open 하고, finally 로 close 한다.
    try:
        lk.open(tap_script=(a.tap_script == "on"))
    except Exception as e:
        print(f"  J-Link open 실패: {e}")
        return EXIT_INSUFFICIENT
    try:
        try:
            # --diag 는 전원 ACK 실패해도 계속(non-strict)해서 어디에 닿는지 본다.
            prepare_session(lk, a.power, a.tap_script,
                            tif_init=(a.tif_init == "on"), strict=not a.diag)
        except SecureJtagError as e:
            print(f"  세션 준비 실패: {e}")
            return e.exit_code
        dap = MemDap(lk.jl)

        # ── 전원/AP 진단 (읽기만) — 디버그전원·도메인 판정 ──
        if a.diag:
            diag_sweep(dap)
            return EXIT_OK

        # ── transport 검증 (읽기만) — write 수정이 34워드 완주시키는지 실증 ──
        if a.read_burst:
            read_burst(dap, base, a.read_burst, delay=a.burst_delay / 1000.0)
            return EXIT_OK

        # ── DM 스캔/기동/halt — auth 잔존 상태에서 DM·코어 디버그 실측 ──
        if a.dm_halt:
            dm_activate(dap, a.core_base)
            dm_halt(dap, a.core_base, a.hart or 0)
            return EXIT_OK
        if a.dm_activate:
            dm_activate(dap, a.core_base)
            dm_scan(dap, a.core_base, a.dm_window)
            return EXIT_OK
        if a.dm_scan:
            dm_scan(dap, a.core_base, a.dm_window)
            return EXIT_OK

        # ── 진단 스캔 (읽기만) — base 가 SJTAG 블록인지/어디인지 실측 ──
        if a.scan:
            scan_sjtag(dap, base, a.scan_window, a.scan_step)
            return EXIT_OK

        # ── 쓰기 전 검증 게이트 (probe/execute 공통) ─────────────────
        ok, problems, info = validate_target(dap, base)
        print(f"  [validate] APBAP3 IDR={hx(info.get('apbap3_idr'))} "
              f"HW={[hx(v) for v in info.get('hw', [])]} "
              f"STATE={[hx(v) for v in info.get('state', [])]}")
        for p in problems:
            print(f"    ✗ {p}")
        if not ok:
            print("  ❌ 검증 실패 — SJTAG 블록으로 확정 안 됨. 쓰기 금지.")
            return EXIT_CONFIG
        print("  ✅ 검증 통과 — APBAP3 뒤 유효 SJTAG 블록으로 보임")

        # STATE 비트 디코드 — AUTH_PASS 지속 여부를 한눈에 (probe 로 인증 잔존 확인)
        st0 = next((v for v in info.get('state', []) if v is not None), None)
        if st0 is not None:
            flags = [nm for m, nm in ((AUTH_PASS, "AUTH_PASS"), (SOFT_LOCK, "SOFT_LOCK"),
                                      (REQUEST_READY, "REQUEST_READY"),
                                      (RESPONSE_READY, "RESPONSE_READY")) if st0 & m]
            print(f"  [state] STATE=0x{st0:08X}  [{' | '.join(flags) or '플래그 없음'}]  "
                  + ("→ 이미 인증됨(AUTH_PASS 지속)" if st0 & AUTH_PASS
                     else "→ AUTH_PASS 없음(미인증/리셋됨)"))

        before = read_dmstatus(dap, a.core_base)
        print(f"  [before] dmstatus(추정) @0x{a.core_base + DMSTATUS_OFF:X} "
              f"= {hx(before[0])}  {before[1]}")

        if not a.execute:
            print("\n  PROBE 모드 — 쓰기 없음. 인증하려면 --execute --word-order ...")
            return EXIT_OK

        try:
            result = unlock(dap, base, tool, a.word_order, timeout=a.timeout,
                            tool_prefix=tool_prefix)
        except SecureJtagError as e:
            print(f"\n  ❌ Secure JTAG 실패: {e}")
            return e.exit_code

        # 세 결과를 섞지 않는다(리뷰 #1). 아래 DM A/B 는 이와 **별개인** 인과 검증.
        status_msg = {
            ST_AUTHENTICATED:     "✅ challenge-response 인증 성공 (AUTH_PASS 확인)",
            ST_ALREADY:           "✅ 이미 unlock 상태였음 — 인증 미수행 (최초 AUTH_PASS)",
            ST_OPEN_NO_SOFT_LOCK: "✅ SOFT_LOCK 미설정 — 인증 불필요로 열림 (AUTH_PASS 아님)",
        }[result.status]
        print(f"\n  {status_msg}. 이하는 별개의 DM 관찰/인과 검증.")

        # ── ★ 직접 증거: 인증 전/후 CDBGPWRUPACK 전이 (dmstatus stride 추정보다 강함) ──
        #   가설: secure 타깃은 디버그 전원을 SJTAG 인증 성공 후에야 연다.
        #   prepare 에서 CDBG req 는 이미 걸어뒀으니, 인증 뒤 ACK(bit29)가 뜨면
        #   "인증이 디버그 전원 게이트를 열었다"는 직접 증명이 된다.
        CDBG_ACK = 1 << 29
        cs_before = lk.ctrl_stat or 0                         # prepare 시점(인증 전)

        def _read_cs():
            v = lk.jl.coresight_read(1, ap=False)
            return (v & 0xFFFFFFFF) if (v is not None and v >= 0) else None

        cs_after = _read_cs()
        # 인증 직후 CDBG ACK 가 아직이면, req 를 재-어서트하고 잠깐 더 기다린다.
        # (게이트가 인증 상태 반영에 몇 ms 걸릴 수 있어 즉시 0 을 단정하지 않는다)
        if not ((cs_after or 0) & CDBG_ACK):
            lk.jl.coresight_write(1, 0x50000000, ap=False)    # CSYS+CDBG req 재요청
            for _ in range(20):
                time.sleep(0.02)
                cs_after = _read_cs()
                if (cs_after or 0) & CDBG_ACK:
                    break
        dbg_b = bool(cs_before & CDBG_ACK)
        dbg_a = bool((cs_after or 0) & CDBG_ACK)
        print(f"  [power A/B] CTRL/STAT before={hx(cs_before)} after={hx(cs_after)}  "
              f"CDBGPWRUPACK {int(dbg_b)}→{int(dbg_a)}")
        if result.status == ST_AUTHENTICATED and not dbg_b and dbg_a:
            print("  ★★★ CDBGPWRUPACK 0→1: SJTAG 인증이 디버그 전원 게이트를 "
                  "열었다 — 직접 증명 (전원영역 신호, stride 추정 불필요).")
        elif result.status == ST_AUTHENTICATED and not dbg_a:
            print("  ⚠ 인증 성공(AUTH_PASS) 했으나 CDBGPWRUPACK 은 여전히 0. "
                  "디버그 전원 게이트가 이 신호로는 안 열림 — 다른 앞단 게이트/리셋 "
                  "필요하거나 CDBG req 재요청이 필요할 수 있다.")

        # ── DM 실측 (같은 세션에서 이어서) — auth 가 DM 을 열었는지 확정 ──
        #   세션을 닫지 않고 인증 직후 그대로: DM 을 dmactive=1 로 깨운 뒤 스캔한다.
        #   (dmactive 안 세우면 DM 이 리셋 상태라 dmstatus 가 0 으로 읽힘)
        dm_activate(dap, a.core_base)
        dm_scan(dap, a.core_base, a.dm_window)

        after = read_dmstatus(dap, a.core_base)
        print(f"  [after ] dmstatus(추정) @0x{a.core_base + DMSTATUS_OFF:X} "
              f"= {hx(after[0])}  {after[1]}")

        # ── 결과 분류 — status 별로 인과 표현을 분리한다(리뷰 #1) ────────
        code, lines = classify_verdict(result.status, before, after)
        for line in lines:
            print(f"\n  {line}")
        return code
    except Exception as e:
        print(f"  예외: {e}")
        return EXIT_INSUFFICIENT
    finally:
        lk.close()


if __name__ == "__main__":
    raise SystemExit(main())
