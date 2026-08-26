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
        """MEM-AP 로 32비트 쓰기. TAR 되읽기 + posted-write 완료/오류를 확인한다."""
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


def run_tool(tool, args, want, label):
    try:
        # errors="replace" — 도구 출력이 비-UTF-8 이어도 예외가 최상위로 새어
        # EXIT_INSUFFICIENT 로 잘못 분류되지 않게 한다. 깨진 문자는 파서가 거른다.
        proc = subprocess.run([tool, *args], capture_output=True, text=True,
                              errors="replace", timeout=TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as e:
        raise SecureJtagError(f"{label}: 서명 도구 실행 실패 — {e}", EXIT_TOOL_FAIL)
    # 비밀 가능성(서명값)을 로그에 남기지 않는다 — 해시·줄수만.
    digest = hashlib.sha256(proc.stdout.encode("utf-8", "replace")).hexdigest()[:16]
    nlines = len([l for l in proc.stdout.splitlines() if l.strip()])
    print(f"    [{label}] 도구 종료코드={proc.returncode} 비어있지않은줄={nlines} "
          f"stdout_sha256={digest}..")
    if proc.returncode != 0:
        raise SecureJtagError(f"{label}: 서명 도구 종료코드 {proc.returncode}",
                              EXIT_TOOL_FAIL)
    return _parse_words(proc.stdout, want)


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


# ── 폴링 / 접근 헬퍼 (전부 APBAP3; addr = 절대 APB 주소) ─────────────
def poll_bit(dap, addr, mask, want, timeout, label, abort_mask=0):
    deadline = time.monotonic() + timeout
    while True:
        v = dap.mem_read32(APBAP3_BASE, addr)
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


def w(dap, addr, val, label):
    if not dap.mem_write32(APBAP3_BASE, addr, val):
        raise SecureJtagError(f"{label}: APBAP3 쓰기 실패 ({dap.last.get('why')})",
                              EXIT_CONFIG)


def rd(dap, addr, label):
    v = dap.mem_read32(APBAP3_BASE, addr)
    if v is None:
        raise SecureJtagError(f"{label}: APBAP3 읽기 실패 ({dap.last.get('why')})",
                              EXIT_CONFIG)
    return v


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
def unlock(dap, base, tool, word_order, timeout=60.0):
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
    pub = order_words(run_tool(tool, PUBKEY_FLAGS, PUBKEY_WORDS, "pubkey"), word_order)
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
    sig = order_words(run_tool(tool, SIGN_FLAGS + chal_args, SIG_WORDS, "sign"), word_order)
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
    if v is None:
        return None, "읽기실패", False
    ver = v & 0xF
    alive = (ver in (2, 3)) and (v not in DEAD_FINGERPRINTS)
    tag = (f"version={ver} " + ("유효(추정 경로)" if alive else "무응답/무효 패턴"))
    return v, tag, alive


# ── 세션 준비 — CMM 방식(prepare-only, connect 없음) ─────────────────
def prepare_session(lk, power, tap_note, tif_init=True):
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

    # 요청한 도메인의 ACK 를 모두 확인한다. both 인데 CDBG 만 뜨면 실패로 본다.
    if power == "dbg-only":
        req, need = 0x10000000, (1 << 29)                     # CDBGPWRUPACK
    else:
        req, need = 0x50000000, (1 << 29) | (1 << 31)         # CDBG+CSYSPWRUPACK
    jl.coresight_write(0, 0x0000001E, ap=False)               # ABORT: sticky 클리어
    jl.coresight_write(1, req, ap=False)
    ack = None
    for _ in range(50):
        time.sleep(0.01)
        v = jl.coresight_read(1, ap=False)
        if v is not None and v >= 0 and (v & need) == need:
            ack = v & 0xFFFFFFFF
            break
    if ack is None:
        raise SecureJtagError(
            f"DAP 전원 ACK 실패 (prepare, power={power}, 필요비트=0x{need:08X})",
            EXIT_CONNECT_FAIL)
    lk.ctrl_stat = ack
    lk.dap_power_ok = True
    print(f"  [prepare] connect 없이 DAP 전원 확보 CTRL/STAT={hx(ack)} "
          f"(요청={power}, TAP={tap_note})")
    return ack


# ── main ─────────────────────────────────────────────────────────────
def main():
    ap = add_common_args(argparse.ArgumentParser(
        description="SF-E76 Secure JTAG (clavis) 인증 — J-Link 포팅"))
    ap.add_argument("--base", type=lambda x: int(x, 0), default=None,
                    help="SJTAG_BASE (clavis 의 &base). CONFIG 값보다 우선")
    ap.add_argument("--tool", default=None, help="서명 도구 경로. CONFIG 값보다 우선")
    ap.add_argument("--execute", action="store_true",
                    help="★ 실제 인증(쓰기)을 한다. 없으면 read-only probe 만.")
    ap.add_argument("--word-order", choices=("t32-negative", "stdout"), default=None,
                    help="공개키/서명 워드 주소순서. --execute 시 필수.")
    ap.add_argument("--power", choices=("dbg-only", "both"), default="dbg-only",
                    help="DAP 전원요청. 기본 dbg-only = CMM 방식(CSYSPWRUPREQ OFF)")
    ap.add_argument("--tap-script", choices=("on", "off"), default="off",
                    help="수동 TAP 체인 선언. 기본 off = CMM 방식(NOKEEPER USEOAC만). "
                         "⚠ STATUS §1.1 은 ScriptFile 경로를 폐기로, sfe76_link 는 "
                         "수동체인을 현재 fix 로 본다 — 실기서 둘 다 시험할 것.")
    ap.add_argument("--tif-init", choices=("on", "off"), default="on",
                    help="cJTAG TIF 초기화. 기본 on — connect() 없이 붙으므로 "
                         "TIF 를 초기화할 주체가 이것뿐이다(standalone.py:1276). "
                         "off 는 이미 활성화된 링크 재사용 실험용.")
    ap.add_argument("--timeout", type=float, default=60.0, help="각 폴링 단계 타임아웃(초)")
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
    if a.core_base not in DM_AP:
        print(f"core_base 0x{a.core_base:X} 는 DM-AP 매핑에 없다 "
              f"(가능: {', '.join(hex(k) for k in DM_AP)})", file=sys.stderr)
        return EXIT_CONFIG
    if not valid_timeout(a.timeout):
        print(f"--timeout 은 유한한 양수여야 한다 (받음: {a.timeout})", file=sys.stderr)
        return EXIT_CONFIG

    mode = "EXECUTE(쓰기)" if a.execute else "PROBE(read-only)"
    print(f"\n{'=' * 66}\n {VERSION}  [{mode}]\n{'=' * 66}")
    print(f"  SJTAG_BASE=0x{base:X} (APBAP3 DP:0x{APBAP3_BASE:X})  tool={tool}")
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
            prepare_session(lk, a.power, a.tap_script, tif_init=(a.tif_init == "on"))
        except SecureJtagError as e:
            print(f"  세션 준비 실패: {e}")
            return e.exit_code
        dap = MemDap(lk.jl)

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

        before = read_dmstatus(dap, a.core_base)
        print(f"  [before] dmstatus(추정) @0x{a.core_base + DMSTATUS_OFF:X} "
              f"= {hx(before[0])}  {before[1]}")

        if not a.execute:
            print("\n  PROBE 모드 — 쓰기 없음. 인증하려면 --execute --word-order ...")
            return EXIT_OK

        try:
            result = unlock(dap, base, tool, a.word_order, timeout=a.timeout)
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
