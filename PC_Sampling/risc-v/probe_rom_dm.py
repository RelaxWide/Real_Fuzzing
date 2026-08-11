#!/usr/bin/env python3
"""SF-E76 — MEM-AP 전송이 **어느 단계에서** 깨지는지 확정한다. 표적 진단기.

════════════════════════════════════════════════════════════════════
왜 `--map` 이 아니라 이것인가 (feedback 2026-08-11 §6)
════════════════════════════════════════════════════════════════════
전 4GB 를 1MB 간격으로 훑는 `--map` 은 다음 이유로 다음 단계로 쓰지 않는다:

  · 좁은 컴포넌트를 **간격 사이로 놓친다**
  · 고정 기본 응답을 **live 영역으로 오판**한다
  · **읽기 부작용이 있는 MMIO** 를 건드릴 수 있다  ← 실기에서 위험하다

지금 가장 부족한 정보는 "어디가 보이나" 가 아니라 **이것 하나**다:

  > J-Link 이 APBAP1 을 통해 `0x81480000` 을 읽을 때,
  > MEM-AP 전송의 **어느 단계에서 어떤 AP/DP 오류**가 나는가?

그래서 접근을 **최소 범위로 좁히고**, 대신 **각 전송의 전후 상태를 전부** 남긴다.

════════════════════════════════════════════════════════════════════
측정 항목 (feedback §5 그대로)
════════════════════════════════════════════════════════════════════
    AP IDR / BASE / CFG
    CSW 원본, 설정 후 되읽기
    CSW.DeviceEn / SDeviceEn / Prot / Type
    TAR write 성공 여부와 readback
    DRW 반환값
    전송 전후 DP CTRL/STAT
    STICKYERR / WDATAERR / STICKYORUN
    ABORT 후 오류 해제 여부

★ **CSW 는 원본을 보존하고 세션 종료 전에 되돌린다.** 지금까지 우리는
  CSW 를 고쳐 쓰고 그대로 나왔다 — 다음 세션에 상태를 물려주는 원인이다.

════════════════════════════════════════════════════════════════════
⚠ CIDR 검사에 기대지 않는다 (feedback §2.4)
════════════════════════════════════════════════════════════════════
`T32 COREDEBUG.Base = CoreSight component base` 라고 가정하고 `+0xFF0` 에서
CIDR 을 읽었는데, **RISC-V DM 은 CoreSight 컴포넌트가 아닐 수 있다.**
`COREDEBUG.Base` 가 곧 **DMI aperture base** 라면 CIDR 검사는 애초에 의미가 없다.
→ CIDR 부재를 "DM 없음" 의 근거로 쓰지 않는다. 참고 자료로만 기록한다.

════════════════════════════════════════════════════════════════════
판정 (여섯 갈래로 분리한다)
════════════════════════════════════════════════════════════════════
    ROM_CONFIRMED_DM_REACHABLE            ROM 확정 + DM 영역 접근됨
    ROM_CONFIRMED_DM_BLOCKED              ROM 확정 + DM 영역만 막힘
    ROM_ENTRY_LIKE_NOT_CONFIRMED          ROM 처럼 보이나 확정 불가
    MEM_AP_TRANSFER_BROKEN                전송 자체가 성립 안 함
    ACCESS_ATTRIBUTE_OR_SECURITY_SUSPECTED 전송은 되는데 특정 영역만 거부
    INSUFFICIENT_VALID_SESSIONS           유효 세션 3회 미만 → **결론 금지**

사용:
    sudo python3 probe_rom_dm.py --brief          # 한 줄 판정
    sudo python3 probe_rom_dm.py --json out.json  # 상세 로그
"""

import argparse
import json
import sys
import time

from sfe76_link import (require_api, Link, LinkError, AP_MAP,
                        add_common_args, EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-11.7  표적 진단"

DP_ABORT, DP_CTRL_STAT, DP_SELECT = 0, 1, 2
OFF_CSW, OFF_TAR, OFF_DRW = 0xD00, 0xD04, 0xD0C
OFF_CFG, OFF_BASE, OFF_IDR = 0xDF4, 0xDF8, 0xDFC
SUSPECT = 0x80000000

# 우선 측정 대상 — APBAP1/APBAP2 만 (feedback §6)
TARGET_APS = ['APBAP1', 'APBAP2']

# ROM 후보: AP 주소공간 앞쪽 엔트리 + ID 레지스터
ROM_ADDRS = [0x0, 0x4, 0x8, 0xC] + [0xFE0, 0xFE4, 0xFE8, 0xFEC,
                                    0xFF0, 0xFF4, 0xFF8, 0xFFC]
# DM 후보: 제한 접근만
DM_BASES = [0x81480000, 0x81481000]
DM_OFFS = [0x000, 0x004, 0x040, 0x044]

DEAD = {0x00000000, 0xFFFFFFFF, 0xEAFFFFFE, 0xEAFFFFFC, 0x00000001, 0x00040700}


def hx(v):
    return "----" if v is None else f"{v & 0xFFFFFFFF:08X}"


class Probe:
    def __init__(self, jl):
        self.jl = jl
        self.sel = None
        self.log = []

    # ── 원시 접근 ────────────────────────────────────────────────
    def dp_r(self, r):
        try:
            v = self.jl.coresight_read(r, ap=False)
            return None if (v is None or v < 0) else v & 0xFFFFFFFF
        except Exception:
            return None

    def dp_w(self, r, v):
        try:
            self.jl.coresight_write(r, v & 0xFFFFFFFF, ap=False)
            return True
        except Exception:
            return False

    def err(self):
        """DP CTRL/STAT 의 오류 비트를 구조화해서 돌려준다."""
        v = self.dp_r(DP_CTRL_STAT)
        if v is None:
            return {'ctrl': None}
        return {'ctrl': f"0x{v:08X}",
                'STICKYERR': bool(v & (1 << 5 + 2)), 'STICKYORUN': bool(v & (1 << 1)),
                'WDATAERR': bool(v & (1 << 7)), 'READOK': bool(v & (1 << 6)),
                'DBGACK': bool(v & (1 << 29))}

    def abort(self):
        ok = self.dp_w(DP_ABORT, 0x0000001E)
        self.sel = None
        return {'abort_written': ok, 'after': self.err()}

    def sel_w(self, addr):
        val = addr & 0xFFFFFFF0
        if self.sel == val:
            return True
        if not self.dp_w(DP_SELECT, val):
            return False
        self.sel = val
        try:                                  # priming (근거는 약하다 — 기록만)
            self.jl.coresight_read(0, ap=True)
        except Exception:
            pass
        return True

    def ap_r(self, base, off):
        if not self.sel_w(base + off):
            return None
        try:
            v = self.jl.coresight_read((off >> 2) & 3, ap=True)
            return None if (v is None or v < 0) else v & 0xFFFFFFFF
        except Exception:
            return None

    def ap_w(self, base, off, val):
        if not self.sel_w(base + off):
            return False
        try:
            self.jl.coresight_write((off >> 2) & 3, val & 0xFFFFFFFF, ap=True)
            return True
        except Exception:
            return False

    # ── 한 번의 메모리 읽기 = 전 단계 기록 ──────────────────────
    def read32(self, ap, base, addr, csw_orig):
        """전송의 **각 단계와 전후 DP 상태**를 전부 남긴다."""
        rec = {'ap': ap, 'addr': f"0x{addr:08X}", 'before': self.err()}
        self.abort()
        if csw_orig is None or csw_orig == SUSPECT:
            rec['stage'] = 'csw_unusable'
            rec['csw_orig'] = hx(csw_orig)
            self.log.append(rec)
            return None, rec
        want = (csw_orig & ~0x37) | 0x02          # Size=word, AddrInc=off
        rec['csw_write'] = f"0x{want:08X}"
        rec['csw_ok'] = self.ap_w(base, OFF_CSW, want)
        rec['csw_back'] = hx(self.ap_r(base, OFF_CSW))
        rec['tar_ok'] = self.ap_w(base, OFF_TAR, addr)
        back = self.ap_r(base, OFF_TAR)
        rec['tar_back'] = hx(back)
        rec['tar_match'] = (back == (addr & 0xFFFFFFFF))
        if not rec['tar_match']:
            rec['stage'] = 'tar_mismatch'
            rec['after'] = self.err()
            self.log.append(rec)
            return None, rec
        v = self.ap_r(base, OFF_DRW)
        rec['drw'] = hx(v)
        rec['after'] = self.err()
        rec['abort_clears'] = self.abort()
        rec['stage'] = 'ok' if v is not None else 'drw_fail'
        rec['dead_pattern'] = (v in DEAD) if v is not None else None
        self.log.append(rec)
        return v, rec


def run_session(a, idx):
    out = {'session': idx, 'valid': False, 'aps': {}, 'log': []}
    lk = Link(device=a.device, serial=a.serial, verbose=not a.brief)
    try:
        with lk:
            try:
                conn, _ = lk.open_dap(tries=a.tries)
            except LinkError as e:
                out['error'] = str(e)
                return out
            out['valid'] = True
            out['connect_ok'] = conn
            p = Probe(lk.jl)

            for name, base, _t in AP_MAP:
                if name not in TARGET_APS:
                    continue
                ap = {'base': f"0x{base:05X}"}
                ap['IDR'] = hx(p.ap_r(base, OFF_IDR))
                ap['BASE'] = hx(p.ap_r(base, OFF_BASE))
                ap['CFG'] = hx(p.ap_r(base, OFF_CFG))
                csw = p.ap_r(base, OFF_CSW)
                ap['CSW_orig'] = hx(csw)
                if csw is not None and csw != SUSPECT:
                    ap['DeviceEn'] = bool(csw & (1 << 6))
                    ap['SDeviceEn'] = bool(csw & (1 << 23))
                    ap['Prot'] = f"0x{(csw >> 24) & 0x7F:02X}"
                    ap['Type'] = csw & 0xF

                ap['rom'] = {}
                for off in ROM_ADDRS:
                    v, _r = p.read32(name, base, off, csw)
                    ap['rom'][f"0x{off:03X}"] = hx(v)

                ap['dm'] = {}
                for b in DM_BASES:
                    for o in DM_OFFS:
                        v, _r = p.read32(name, base, b + o, csw)
                        ap['dm'][f"0x{b + o:08X}"] = hx(v)

                # ★ CSW 원본 복구 — 다음 세션에 상태를 물려주지 않는다
                if csw is not None and csw != SUSPECT:
                    ap['csw_restored'] = p.ap_w(base, OFF_CSW, csw)
                out['aps'][name] = ap
            out['log'] = p.log
    except Exception as e:
        out['error'] = str(e)
    return out


def judge(sessions):
    """여섯 갈래 판정. **유효 세션 3회 미만이면 결론 금지.**"""
    valid = [s for s in sessions if s.get('valid')]
    if len(valid) < 3:
        return 'INSUFFICIENT_VALID_SESSIONS', {}

    ev = {}
    for name in TARGET_APS:
        aps = [s['aps'][name] for s in valid if name in s.get('aps', {})]
        if not aps:
            continue
        # 전 세션 일치값만 인정
        def agree(d, k):
            vs = {a[d].get(k) for a in aps if d in a}
            return vs.pop() if len(vs) == 1 else None
        rom0 = agree('rom', '0x000')
        rom4 = agree('rom', '0x004')
        dm0 = agree('dm', f"0x{DM_BASES[0]:08X}")
        ev[name] = {'rom0': rom0, 'rom4': rom4, 'dm0': dm0,
                    'idr': {a.get('IDR') for a in aps},
                    'devEn': {a.get('DeviceEn') for a in aps}}

    def live(x):
        return x not in (None, '----') and int(x, 16) not in DEAD

    rom_like = any(live(e['rom0']) for e in ev.values())
    dm_live = any(live(e['dm0']) for e in ev.values())
    any_live = any(live(v) for e in ev.values() for v in (e['rom0'], e['rom4'], e['dm0']))

    if not any_live:
        return 'MEM_AP_TRANSFER_BROKEN', ev
    if rom_like and dm_live:
        return 'ROM_CONFIRMED_DM_REACHABLE', ev
    if rom_like and not dm_live:
        # ROM 은 읽히는데 그것이 가리키는 DM 만 막힌다
        return 'ROM_CONFIRMED_DM_BLOCKED', ev
    if any_live and not rom_like:
        return 'ACCESS_ATTRIBUTE_OR_SECURITY_SUSPECTED', ev
    return 'ROM_ENTRY_LIKE_NOT_CONFIRMED', ev


def main():
    require_api(5, "probe_rom_dm.py")
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--sessions', type=int, default=3)
    ap.add_argument('--brief', action='store_true', help='한 줄 판정만')
    ap.add_argument('--json', default=None, help='상세 로그를 JSON 으로 저장')
    ap.add_argument('--version', action='store_true')
    a = ap.parse_args()
    if a.version:
        print(f"probe_rom_dm {VERSION}")
        return EXIT_OK

    if not a.brief:
        print(f"\n{'=' * 66}\n MEM-AP 전송 표적 진단 (v{VERSION})\n{'=' * 66}")
        print(f"  대상 AP: {TARGET_APS}   세션 {a.sessions}회")
        print("  ROM 후보 0x0~0xC + ID 레지스터, DM 은 제한 접근만.")
        print("  CSW 는 원본 보존 후 세션 종료 전에 복구한다.")

    sessions = []
    for i in range(a.sessions):
        if not a.brief:
            print(f"\n{'-' * 66}\n 세션 {i + 1}/{a.sessions}\n{'-' * 66}")
        sessions.append(run_session(a, i))
        time.sleep(0.4)

    verdict, ev = judge(sessions)
    nvalid = sum(1 for s in sessions if s.get('valid'))

    print(f"\nv={VERSION.split()[0]}  valid={nvalid}/{a.sessions}")
    for name, e in ev.items():
        print(f"{name} rom0={e['rom0']} rom4={e['rom4']} dm0={e['dm0']} "
              f"idr={sorted(x for x in e['idr'] if x)} devEn={sorted(map(str, e['devEn']))}")
    print(f"VERDICT: {verdict}")

    if a.json:
        with open(a.json, 'w') as f:
            json.dump({'version': VERSION, 'sessions': sessions,
                       'verdict': verdict}, f, ensure_ascii=False, indent=1)
        print(f"(상세 로그 {a.json})")

    if not a.brief and verdict != 'INSUFFICIENT_VALID_SESSIONS':
        print(f"\n{'=' * 66}")
        print({
            'ROM_CONFIRMED_DM_REACHABLE':
                "  ★★ DM 영역까지 읽힌다 → J-Link CoreBase 설정으로 바로 간다",
            'ROM_CONFIRMED_DM_BLOCKED':
                "  ★ ROM 은 읽히는데 **그것이 가리키는 DM 만 막힌다.**\n"
                "     주소가 AP 공간이 아닌 다른 버스 기준이거나, 그 구간만 접근 제한.\n"
                "     → ASK.md §5-1 이 정확히 이 질문이다.",
            'MEM_AP_TRANSFER_BROKEN':
                "  전송 자체가 성립하지 않는다 → 우리 AP 접근 코드부터 재검토",
            'ACCESS_ATTRIBUTE_OR_SECURITY_SUSPECTED':
                "  전송은 되는데 특정 영역만 거부된다 → Prot/Type/SDeviceEn 조합 시험",
            'ROM_ENTRY_LIKE_NOT_CONFIRMED':
                "  ROM 처럼 보이나 확정 불가 → BASE/PIDR/CIDR 과 상대 오프셋 재확인",
        }.get(verdict, ""))
    return EXIT_OK if verdict.startswith('ROM_CONFIRMED') else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
