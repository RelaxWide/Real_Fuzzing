#!/usr/bin/env python3
"""SF-E76 — ① AP 주소 디코드 폭(aliasing) ② 디버그 전원 사이클.

════════════════════════════════════════════════════════════════════
왜 이 둘인가
════════════════════════════════════════════════════════════════════
지금 상태가 모순처럼 보인다:

    AP 주소공간 0x0 을 읽으면   → 0x81480003  (DM 을 가리키는 값)
    0x81480000 을 읽으면        → 무응답 상수

지금까지는 **주소를 찍어보는** 방식이었고 그건 정보 없이는 안 된다.
이 둘은 성격이 다르다 — **가설이 명확하고 결과가 이분법**이다.

────────────────────────────────────────────────────────────────────
[A] aliasing — AP 창이 32비트를 다 디코드하지 않는가
────────────────────────────────────────────────────────────────────
하위 N비트만 디코드하면 `0x81480000` 은 잘려서 엉뚱한 곳으로 간다.
그런데 **TAR 되읽기는 통과한다** — TAR 은 버스가 무시하는 비트도 담기 때문이다.
지금 증상과 정확히 맞는다.

★ 판정법: **주소를 추측하지 않고 wrap 지점을 찾는다.**
  AP 가 N비트를 디코드하면 주소 `2^N` 은 주소 `0` 과 **같은 곳**을 가리킨다.
  `0x0` 은 이미 live 값(`0x81480003`)을 준다 — 이걸 기준으로 삼는다.

    ref = read(0x0)
    for N in 12..31:  read(1<<N) 이 ref 와 같은가?
    가장 작은 N = 디코드 폭

  우연한 일치를 배제하려고 `read((1<<N)+4)` 가 `read(4)` 와도 같은지 **함께** 본다.
  두 쌍이 동시에 맞아야 wrap 으로 인정한다.

  폭 W 가 나오면 **DM 의 진짜 접근 주소** = `0x81480000 & (2^W - 1)` 이다.
  그 자리를 바로 읽어본다. → 벤더 없이 끝난다.

────────────────────────────────────────────────────────────────────
[B] 디버그 전원 사이클 — T32 의 DOWN → 500ms → UP
────────────────────────────────────────────────────────────────────
T32 의 HCore 시퀀스에 `SYStem.DOWN` → **WAIT 500ms** → `SYStem.UP` 이 있다.
**우리는 전원을 내렸다 올린 적이 한 번도 없다.** 리셋 없이 DM 을 깨우는
시퀀스일 수 있다. 여기서는 `CDBGPWRUPREQ` 를 내리고 기다렸다 다시 올린다
(T32 처럼 **DBG 만**, `CSYSPWRUPREQ` 는 쓰지 않는다).

사용:
    sudo python3 probe_alias_power.py --brief
    sudo python3 probe_alias_power.py --only A
"""

import argparse
import sys
import time

from sfe76_link import (require_api, Link, LinkError, AP_MAP,
                        add_common_args, EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-11.8  alias / powercycle"

DP_ABORT, DP_CTRL_STAT, DP_SELECT = 0, 1, 2
OFF_CSW, OFF_TAR, OFF_DRW = 0xD00, 0xD04, 0xD0C
SUSPECT = 0x80000000
DEAD = {0x00000000, 0xFFFFFFFF, 0xEAFFFFFE, 0xEAFFFFFC, 0x00000001, 0x00040700}

TARGET_APS = ['APBAP1', 'APBAP2']
DM_TARGET = 0x81480000
WRAP_BITS = range(12, 32)          # 4KB ~ 2GB


def hx(v):
    return "----" if v is None else f"{v & 0xFFFFFFFF:08X}"


def live(v):
    return v is not None and v not in DEAD


class Mem:
    """AP 하나에 대한 32비트 읽기. CSW 원본을 보존하고 복구한다."""

    def __init__(self, jl, base):
        self.jl, self.base, self.sel = jl, base, None
        self.csw0 = self._ap_r(OFF_CSW)

    def _sel(self, addr):
        v = addr & 0xFFFFFFF0
        if self.sel == v:
            return True
        try:
            self.jl.coresight_write(DP_SELECT, v, ap=False)
        except Exception:
            return False
        self.sel = v
        try:
            self.jl.coresight_read(0, ap=True)      # priming
        except Exception:
            pass
        return True

    def _ap_r(self, off):
        if not self._sel(self.base + off):
            return None
        try:
            v = self.jl.coresight_read((off >> 2) & 3, ap=True)
            return None if (v is None or v < 0) else v & 0xFFFFFFFF
        except Exception:
            return None

    def _ap_w(self, off, val):
        if not self._sel(self.base + off):
            return False
        try:
            self.jl.coresight_write((off >> 2) & 3, val & 0xFFFFFFFF, ap=True)
            return True
        except Exception:
            return False

    def _abort(self):
        try:
            self.jl.coresight_write(DP_ABORT, 0x1E, ap=False)
        except Exception:
            pass
        self.sel = None

    def read32(self, addr):
        self._abort()
        if self.csw0 is None or self.csw0 == SUSPECT:
            return None
        if not self._ap_w(OFF_CSW, (self.csw0 & ~0x37) | 0x02):
            return None
        if not self._ap_w(OFF_TAR, addr):
            return None
        if self._ap_r(OFF_TAR) != (addr & 0xFFFFFFFF):
            return None
        return self._ap_r(OFF_DRW)

    def restore(self):
        if self.csw0 is not None and self.csw0 != SUSPECT:
            self._ap_w(OFF_CSW, self.csw0)


# ══════════════════════════════════════════════════════════════════
def test_alias(jl, name, base, verbose=True):
    """wrap 지점을 찾아 디코드 폭을 구한다. 반환: dict"""
    m = Mem(jl, base)
    r = {'ap': name, 'width': None, 'ref0': None, 'ref4': None,
         'dm_alias': None, 'dm_alias_val': None, 'matches': []}
    ref0, ref4 = m.read32(0x0), m.read32(0x4)
    r['ref0'], r['ref4'] = hx(ref0), hx(ref4)
    if not live(ref0):
        r['note'] = '기준 주소 0x0 이 live 가 아니다 — 이 AP 로는 판정 불가'
        m.restore()
        return r

    if verbose:
        print(f"\n  [{name}] 기준 0x0={hx(ref0)}  0x4={hx(ref4)}")
    for n in WRAP_BITS:
        a = 1 << n
        v0 = m.read32(a)
        # ★ 두 쌍이 **동시에** 맞아야 wrap 으로 인정한다 (우연 배제)
        v4 = m.read32(a + 4) if v0 == ref0 else None
        ok = (v0 == ref0) and (v4 == ref4)
        if verbose:
            print(f"      2^{n:<2d} (0x{a:08X}) = {hx(v0)}"
                  + (f"  +4={hx(v4)}" if v4 is not None else "")
                  + ("   ★ wrap" if ok else ""))
        if ok:
            r['matches'].append(n)
            if r['width'] is None:
                r['width'] = n
    if r['width'] is not None:
        mask = (1 << r['width']) - 1
        r['dm_alias'] = DM_TARGET & mask
        r['dm_alias_val'] = hx(m.read32(r['dm_alias']))
        if verbose:
            print(f"      → 디코드 폭 {r['width']}비트. "
                  f"DM 의 실제 주소 후보 0x{r['dm_alias']:08X} = {r['dm_alias_val']}")
    m.restore()
    return r


def test_powercycle(jl, name, base, wait_ms, verbose=True):
    """CDBGPWRUPREQ 를 내렸다 기다렸다 올린다 (T32 의 DOWN→wait→UP 흉내)."""
    def ctrl():
        try:
            v = jl.coresight_read(DP_CTRL_STAT, ap=False)
            return None if (v is None or v < 0) else v & 0xFFFFFFFF
        except Exception:
            return None

    m = Mem(jl, base)
    before = m.read32(DM_TARGET)
    m.restore()
    if verbose:
        print(f"\n  [{name}] 전원 사이클 전 0x{DM_TARGET:08X} = {hx(before)}")

    try:
        jl.coresight_write(DP_ABORT, 0x1E, ap=False)
        jl.coresight_write(DP_CTRL_STAT, 0x00000000, ap=False)   # DOWN
    except Exception:
        pass
    time.sleep(wait_ms / 1000.0)
    down = ctrl()
    try:
        jl.coresight_write(DP_CTRL_STAT, 0x10000000, ap=False)   # UP (DBG 만)
    except Exception:
        pass
    up = None
    for _ in range(50):
        time.sleep(0.01)
        up = ctrl()
        if up is not None and (up & (1 << 29)):
            break

    m2 = Mem(jl, base)
    after = m2.read32(DM_TARGET)
    m2.restore()
    if verbose:
        print(f"      DOWN 후 CTRL/STAT={hx(down)}   UP 후={hx(up)}")
        print(f"      전원 사이클 후 0x{DM_TARGET:08X} = {hx(after)}")
    return {'ap': name, 'before': hx(before), 'after': hx(after),
            'down': hx(down), 'up': hx(up),
            'ack': bool(up and up & (1 << 29)),
            'changed': (before != after), 'now_live': live(after)}


# ══════════════════════════════════════════════════════════════════
def one_session(a, i):
    out = {'valid': False, 'alias': [], 'pwr': []}
    lk = Link(device=a.device, serial=a.serial, verbose=not a.brief)
    try:
        with lk:
            try:
                lk.open_dap(tries=a.tries)
            except LinkError as e:
                out['error'] = str(e)
                return out
            out['valid'] = True
            for name, base, _t in AP_MAP:
                if name not in TARGET_APS:
                    continue
                if a.only in (None, 'A'):
                    out['alias'].append(test_alias(lk.jl, name, base, not a.brief))
                if a.only in (None, 'B'):
                    out['pwr'].append(
                        test_powercycle(lk.jl, name, base, a.wait_ms, not a.brief))
    except Exception as e:
        out['error'] = str(e)
    return out


def main():
    require_api(3, "probe_alias_power.py")
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--only', choices=['A', 'B'], help='A=aliasing  B=전원 사이클')
    ap.add_argument('--sessions', type=int, default=3)
    ap.add_argument('--wait-ms', type=int, default=500, help='T32 와 같은 500ms')
    ap.add_argument('--brief', action='store_true')
    ap.add_argument('--version', action='store_true')
    a = ap.parse_args()
    if a.version:
        print(f"probe_alias_power {VERSION}")
        return EXIT_OK

    if not a.brief:
        print(f"\n{'=' * 66}\n [A] 주소 디코드 폭  [B] 디버그 전원 사이클 "
              f"(v{VERSION})\n{'=' * 66}")

    runs = []
    for i in range(a.sessions):
        if not a.brief:
            print(f"\n{'-' * 66}\n 세션 {i + 1}/{a.sessions}\n{'-' * 66}")
        runs.append(one_session(a, i))
        time.sleep(0.4)

    valid = [r for r in runs if r['valid']]
    print(f"\nv={VERSION.split()[0]}  valid={len(valid)}/{a.sessions}")

    # [A] 전 세션에서 같은 폭이 나와야 인정한다
    verdict = []
    for name in TARGET_APS:
        ws = [x['width'] for r in valid for x in r['alias'] if x['ap'] == name]
        refs = {x['ref0'] for r in valid for x in r['alias'] if x['ap'] == name}
        al = [x for r in valid for x in r['alias'] if x['ap'] == name]
        if not al:
            continue
        w = ws[0] if ws and len(set(ws)) == 1 and ws[0] is not None else None
        dm = al[-1].get('dm_alias')
        print(f"{name} ref0={sorted(refs)} width={ws}"
              + (f" dmalias=0x{dm:08X} val={al[-1]['dm_alias_val']}" if dm else ""))
        if w is not None:
            verdict.append(f"ALIAS_W{w}_{name}"
                           + ("_DMLIVE" if live_str(al[-1]['dm_alias_val']) else "_DMDEAD"))
        elif refs and all(x != '----' for x in refs):
            verdict.append(f"NO_ALIAS_{name}")

    for name in TARGET_APS:
        pw = [x for r in valid for x in r['pwr'] if x['ap'] == name]
        if not pw:
            continue
        print(f"{name} pwr before={pw[-1]['before']} after={pw[-1]['after']} "
              f"ack={pw[-1]['ack']} changed={any(x['changed'] for x in pw)}")
        if any(x['now_live'] for x in pw):
            verdict.append(f"PWRCYCLE_OPENED_{name}")

    if len(valid) < 3:
        print("VERDICT: INSUFFICIENT_VALID_SESSIONS")
        return EXIT_INSUFFICIENT
    print("VERDICT:", " ".join(verdict) if verdict else "NO_SIGNAL")
    return EXIT_OK if verdict else EXIT_INSUFFICIENT


def live_str(s):
    if s in (None, '----'):
        return False
    try:
        return int(s, 16) not in DEAD
    except ValueError:
        return False


if __name__ == '__main__':
    sys.exit(main())
