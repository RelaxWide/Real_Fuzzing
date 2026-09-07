#@title Overlay Coverage Export
#@category FuzzingTools
#@runtime Jython
"""ghidra_overlay_export.py — 코드 오버레이 구간의 BB/함수 표를 **오버레이별로** 추출.

기존 ghidra_export 계열은 오버레이를 모른다. BM9K1 처럼 여러 코드 본체가 같은
주소를 공유하면(H코어: 0x56000 에 35개) 산출물이 둘 중 하나로 망가진다:
  · 한 오버레이 분량만 나와 나머지가 통째로 분모에서 빠지거나
  · 전부 나와 같은 주소에 겹치는 항목이 쌓이고 bisect 가 아무거나 고른다

Ghidra 는 ELF 의 겹치는 섹션을 **오버레이 주소공간**으로 따로 로드한다.
이 스크립트는 그 공간별로 BB/함수를 뽑아 bank 를 파일명에 박는다.

출력 (OUTPUT_DIR):
    basic_blocks_core<CORE>_ovl<N>.txt    0xSTART 0xEND      (END exclusive)
    functions_core<CORE>_ovl<N>.txt       0xENTRY <size> <name>
주소는 **오버레이 공간 오프셋이 아니라 실제 런타임 주소**로 쓴다(퍼저가 보는 값).

설정: 아래 CORE / OUTPUT_DIR 을 코어마다 바꿔 실행하거나,
      Ghidra 의 script arguments 로 [CORE, OUTPUT_DIR] 을 넘긴다.

bank 번호는 오버레이 공간 이름의 REGION_NN 에서 뽑는다. 이름 규약이 다르면
BANK_FROM_NAME 을 고쳐라 — **추측으로 순서를 매기지 않는다**(순서가 틀리면
표와 런타임 bank 가 어긋나 조용히 잘못된 커버리지가 된다).
"""
import os
import re

from ghidra.program.model.block import BasicBlockModel

CORE = "H"
OUTPUT_DIR = "/home/ssd/ghidra_export"

try:
    _args = getScriptArgs()
    if len(_args) >= 1:
        CORE = _args[0]
    if len(_args) >= 2:
        OUTPUT_DIR = _args[1]
except Exception:
    pass

BANK_FROM_NAME = re.compile(r'REGION[_-]?(\d+)')


def bank_of(space_name):
    m = BANK_FROM_NAME.search(space_name)
    return int(m.group(1)) if m else None


def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    mem = currentProgram.getMemory()
    blocks = [b for b in mem.getBlocks() if b.isOverlay()]
    if not blocks:
        print("[OvlExport] 오버레이 블록이 없다.")
        print("            Ghidra 가 겹치는 섹션을 오버레이로 로드하지 않았거나,")
        print("            이 ELF 에 오버레이가 없다. Memory Map 창에서 'Overlay'")
        print("            열을 확인하라. 로드 옵션에서 켜야 할 수도 있다.")
        return

    # 오버레이 공간별 주소범위
    spaces = {}
    for b in blocks:
        sp = b.getStart().getAddressSpace()
        spaces.setdefault(sp.getName(), []).append(b)

    print("[OvlExport] core=%s  오버레이 공간 %d개" % (CORE, len(spaces)))
    unknown = [n for n in spaces if bank_of(n) is None]
    if unknown:
        print("[OvlExport] ⚠ bank 번호를 못 뽑은 공간: %s" % unknown)
        print("            BANK_FROM_NAME 정규식을 고쳐라. 순서로 추측하지 않는다 —")
        print("            틀리면 표와 런타임 bank 가 어긋나 조용히 잘못된 커버리지가 된다.")

    fm = currentProgram.getFunctionManager()
    bbm = BasicBlockModel(currentProgram)

    for name in sorted(spaces):
        bank = bank_of(name)
        if bank is None:
            continue
        blks = spaces[name]
        lo = min(b.getStart().getOffset() for b in blks)
        hi = max(b.getEnd().getOffset() + 1 for b in blks)

        # ── 함수 ──
        funcs = []
        for b in blks:
            it = fm.getFunctions(b.getStart(), True)
            while it.hasNext():
                f = it.next()
                ent = f.getEntryPoint()
                if ent.getAddressSpace().getName() != name:
                    break                      # 이 공간을 벗어남
                body = f.getBody()
                funcs.append((ent.getOffset(), int(body.getNumAddresses()),
                              f.getName()))
        funcs = sorted(set(funcs))

        # ── BB ──
        bbs = []
        for b in blks:
            it = bbm.getCodeBlocksContaining(b.getStart(), monitor)
            # 블록 전체를 훑으려면 주소집합 기준 반복이 안전하다
        for b in blks:
            it = bbm.getCodeBlocks(monitor)
            while it.hasNext():
                cb = it.next()
                st = cb.getMinAddress()
                if st.getAddressSpace().getName() != name:
                    continue
                bbs.append((st.getOffset(), cb.getMaxAddress().getOffset() + 1))
            break                              # getCodeBlocks 는 전체를 한 번만
        bbs = sorted(set(bbs))

        fp = os.path.join(OUTPUT_DIR, "functions_core%s_ovl%d.txt" % (CORE, bank))
        with open(fp, "w") as f:
            for ent, size, nm in funcs:
                f.write("0x%08x %d %s\n" % (ent, size, nm))
        bp = os.path.join(OUTPUT_DIR, "basic_blocks_core%s_ovl%d.txt" % (CORE, bank))
        with open(bp, "w") as f:
            for s0, e0 in bbs:
                f.write("0x%08x 0x%08x\n" % (s0, e0))

        print("[OvlExport] bank %-2d %-22s 0x%x~0x%x  함수 %5d / BB %6d"
              % (bank, name, lo, hi, len(funcs), len(bbs)))
        if not funcs:
            print("            ⚠ 함수가 0개 — 이 공간에 분석이 안 됐을 수 있다")

    print("[OvlExport] 출력: %s" % OUTPUT_DIR)


main()
