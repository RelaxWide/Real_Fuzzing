#!/usr/bin/env python3
"""SF-E76 — 트레이스 레지스터에 **DM 없이** 닿는지 시험한다.

════════════════════════════════════════════════════════════════════
목적 (이 도구가 답하려는 질문 하나)
════════════════════════════════════════════════════════════════════

  **`0xFD000000`(TE) / `0xFD180000`(TF·ETB) 를 MEM-AP 로 직접 읽을 수 있는가?**

왜 이게 중요한가:

  T32 는 이 주소들을 `ESB:` 로 읽는다 = **SBA(System Bus Access), 코어 실행 중**.
  SBA 는 Debug Module 의 일부인데, **우리는 지금 DM 이 `dmactive` 로 안 깨어난다.**

  그런데 트레이스 블록은 시스템 버스에 매핑된 주변장치다. **AXI-AP 나 AHB-AP 로
  직접 보일 수 있다.** 그렇다면 DM 을 아예 거치지 않고 읽을 수 있고,
  **지금 블로커를 통째로 우회한다.**

  → 이 시험이 성공하면: 커버리지 경로가 즉시 열린다(디코더만 남는다)
  → 실패하면    : DM(`dmactive`)을 먼저 풀어야 한다는 것이 확정된다

어느 쪽이든 **다음에 뭘 할지가 정해진다.** 그게 이 도구의 전부다.

════════════════════════════════════════════════════════════════════
주소 출처 — T32 `NexusTracedatadump.cmm` 실물
════════════════════════════════════════════════════════════════════
    &TECTRL  = ESB:0xFD000000      TE control   (bit1 = enable)
    &TFCTRL  = ESB:0xFD180000      TF control   (bit1 = enable)
    &ETBBASE = ESB:0xFD180000      ETB (TF 와 같은 base)
      +0x1C  write pointer  (bit0 = wrap 플래그)
      +0x20  read pointer
      +0x24  data           (읽을 때마다 자동 증가)
    버퍼 32KB (0x7FFF)

════════════════════════════════════════════════════════════════════
안전
════════════════════════════════════════════════════════════════════
  * 기본은 **읽기 전용**. 쓰기는 --allow-write 로만.
  * `+0x24`(data) 는 **읽으면 읽기 포인터가 전진**해 트레이스 데이터를 소비한다.
    기본으로 건드리지 않는다. --read-data 로만.
  * halt 를 하지 않는다. 코어를 멈추지 않으므로 SSD 가 hang 하지 않는다.

사용:
    sudo python3 probe_trace_regs.py
    sudo python3 probe_trace_regs.py --device E76
"""

import argparse
import sys

from sfe76_link import (Link, LinkError, AP_MAP, add_common_args,
                        EXIT_OK, EXIT_INSUFFICIENT)

VERSION = "2026-08-10.1"

TECTRL  = 0xFD000000
TFCTRL  = 0xFD180000
ETBBASE = 0xFD180000

# (오프셋, 이름, 안전한가)
ETB_REGS = [
    (0x00, 'TFCTRL/ETB+0x00', True),
    (0x1C, 'write ptr',       True),
    (0x20, 'read ptr',        True),
    (0x24, 'data (소비함!)',  False),
]

# DP/AP 레지스터 인덱스
DP_SELECT = 2
# MEM-AP 레지스터 (뱅크 0): 0=CSW 1=TAR 3=DRW
CSW_CANDIDATES = [0x80000002, 0x23000052, 0x00000002]


def hx(v):
    return "실패" if v is None else f"0x{v & 0xFFFFFFFF:08X}"


def degenerate(vals):
    """전부 같은 값이거나 0/0xFFFFFFFF 면 진짜 읽기가 아니다."""
    v = [x for x in vals if x is not None]
    if not v:
        return True
    if len(set(v)) == 1 and v[0] in (0x00000000, 0xFFFFFFFF):
        return True
    return len(set(v)) == 1


# ── 경로 A: connect 후 J-Link 메모리 읽기 ────────────────────────────
def path_memory(lk, ap_index, addrs):
    try:
        lk.jl.exec_command(f"CORESIGHT_SetIndexBGMemAPToUse = {ap_index}")
    except Exception as e:
        return None, f"BGMemAP 설정 실패: {e}"
    out = []
    for a in addrs:
        try:
            r = lk.jl.memory_read32(a, 1)
            out.append(r[0] & 0xFFFFFFFF if r else None)
        except Exception as e:
            out.append(None)
            if len(out) == 1:
                return out, f"memory_read32 실패: {e}"
    return out, None


# ── 경로 B: CoreSight MEM-AP 직접 (DM 불필요) ────────────────────────
def ap_mem_read(lk, ap_addr, addr, csw):
    """ADIv6: SELECT 에 AP 주소를 쓰고, 뱅크 0 의 CSW/TAR/DRW 를 쓴다.

    DPIDR=0x11013913 → version 필드 3 = **DPv3(ADIv6 / SoC-600)**.
    ADIv6 는 APSEL 이 아니라 **주소**로 AP 를 지정한다.
    """
    try:
        lk.jl.coresight_write(DP_SELECT, ap_addr & 0xFFFFFFF0, ap=False)
        lk.jl.coresight_write(0, csw, ap=True)    # CSW
        lk.jl.coresight_write(1, addr, ap=True)   # TAR
        lk.jl.coresight_read(3, ap=True)          # DRW — 파이프라인, 첫 값 버림
        return lk.jl.coresight_read(3, ap=True) & 0xFFFFFFFF
    except Exception:
        return None


def path_coresight(lk, ap_addr, addrs, csw):
    return [ap_mem_read(lk, ap_addr, a, csw) for a in addrs]


# ══════════════════════════════════════════════════════════════════
def main():
    ap = add_common_args(argparse.ArgumentParser())
    ap.add_argument('--read-data', action='store_true',
                    help='ETB+0x24 도 읽는다 (★ 읽기 포인터가 전진해 데이터를 소비)')
    ap.add_argument('--allow-write', action='store_true',
                    help='TE/TF disable 쓰기까지 시험 (기본 읽기 전용)')
    a = ap.parse_args()

    addrs, names = [TECTRL], ['TECTRL(0xFD000000)']
    for off, nm, safe in ETB_REGS:
        if safe or a.read_data:
            addrs.append(ETBBASE + off)
            names.append(f"{nm} (+0x{off:02X})")

    print(f"\n{'=' * 68}")
    print(f" 트레이스 레지스터 도달 시험 — DM 우회 가능한가  (v{VERSION})")
    print(f"{'=' * 68}")
    print("  목적: 0xFD000000 / 0xFD180000 을 MEM-AP 로 직접 읽을 수 있는가")
    print("        되면 → dmactive 블로커를 우회하고 커버리지 경로가 열린다")
    print("        안되면 → DM 을 먼저 풀어야 함이 확정된다")
    print(f"\n  읽을 주소 {len(addrs)}개:")
    for n, x in zip(names, addrs):
        print(f"    {n:26s} 0x{x:08X}")
    if not a.read_data:
        print("  (+0x24 data 는 읽기 포인터를 전진시키므로 제외. --read-data 로 포함)")

    lk = Link(core_base=a.core_base, hart=a.hart, device=a.device, serial=a.serial)
    good = []
    try:
        with lk:
            print(f"\n{'-' * 68}\n connect (dmactive 로 실패해도 계속 진행)\n{'-' * 68}")
            connected = False
            try:
                lk.connect_checked(tries=a.tries)
                connected = True
                print("  connect 성공")
            except LinkError as e:
                print(f"  connect 실패(예상됨): {e}")

            # ── 경로 A ──────────────────────────────────────────────
            if connected:
                print(f"\n{'-' * 68}\n [A] connect + memory_read32  (BGMemAP 별)\n{'-' * 68}")
                for i, (nm, base, typ) in enumerate(AP_MAP):
                    vals, err = path_memory(lk, i, addrs)
                    if vals is None:
                        print(f"  AP{i} {nm:7s} {typ:7s}: {err}")
                        continue
                    tag = "degenerate" if degenerate(vals) else "★ 실제 데이터로 보임"
                    print(f"  AP{i} {nm:7s} {typ:7s}: {[hx(v) for v in vals]}  {tag}")
                    if not degenerate(vals):
                        good.append(('memory_read32', i, nm, vals))
            else:
                print("\n  [A] 건너뜀 — connect 가 안 돼 memory_read32 를 못 쓴다")

            # ── 경로 B ──────────────────────────────────────────────
            print(f"\n{'-' * 68}\n [B] CoreSight MEM-AP 직접 (ADIv6, DM 불필요)\n{'-' * 68}")
            for i, (nm, base, typ) in enumerate(AP_MAP):
                if typ not in ('AXI-AP', 'AHB-AP', 'APB-AP'):
                    continue
                for csw in CSW_CANDIDATES:
                    vals = path_coresight(lk, base, addrs, csw)
                    if degenerate(vals):
                        continue
                    print(f"  AP{i} {nm:7s} {typ:7s} CSW={hx(csw)}: "
                          f"{[hx(v) for v in vals]}  ★ 실제 데이터로 보임")
                    good.append(('coresight', i, nm, vals))
                    break
                else:
                    print(f"  AP{i} {nm:7s} {typ:7s}: 전부 degenerate")

            # ── 쓰기 시험 (선택) ────────────────────────────────────
            if a.allow_write and good:
                print(f"\n{'-' * 68}\n [W] 쓰기 시험 — TE disable 후 되읽기\n{'-' * 68}")
                print("  (T32 스크립트가 하는 것과 같은 동작이라 안전하다)")
                # 구현은 성공 경로가 확정된 뒤에 붙인다
                print("  성공 경로가 확정되면 이 단계를 구현한다 — 지금은 표시만")
    except Exception as e:
        print(f"\n  예외: {e}")

    print(f"\n{'=' * 68}\n 판정\n{'=' * 68}")
    if good:
        m, i, nm, vals = good[0]
        print(f"  ★★ 트레이스 레지스터에 닿았다 — 경로: {m}, AP{i}({nm})")
        print(f"     값: {[hx(v) for v in vals]}")
        print("\n  → **DM 없이 트레이스 블록 접근 가능.** dmactive 블로커 우회 성립.")
        print("     다음: ETB 포인터 로직을 구현해 raw Nexus 바이트를 덤프한다")
        print("           (T32 NexusTracedatadump.cmm 과 같은 순서)")
        print("\n  ※ 값 검증: TECTRL/TFCTRL 이 그럴듯한 제어값인지, write ptr 이")
        print("     0 이 아니고 bit0(wrap) 이 의미 있어 보이는지 눈으로 확인할 것.")
    else:
        print("  ✗ 어느 AP/경로로도 유효한 값을 못 읽었다.")
        print("\n  → 트레이스 블록이 MEM-AP 로 안 보인다는 뜻이다.")
        print("     T32 가 ESB:(SBA) 로 읽는 이유가 이것일 수 있다 —")
        print("     즉 **SBA 가 유일한 경로**이고, SBA 는 DM 의 일부다.")
        print("     => dmactive 를 먼저 푸는 것이 선행 조건으로 확정된다.")
        print("\n  그 경우 필요한 정보:")
        print("     - T32 의 SYStem.Up 직전 Data.Set 시퀀스 (DM 전원/클럭 가능성)")
        print("     - T32 의 RISC-V 전용 SYStem.CONFIG (DMI/DEBUGMODULE 항목)")
        print("     - 벤더: DMI aperture 정확한 base 와 레지스터 매핑(stride)")
    return EXIT_OK if good else EXIT_INSUFFICIENT


if __name__ == '__main__':
    sys.exit(main())
