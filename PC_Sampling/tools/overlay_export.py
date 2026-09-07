#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""오버레이별 BB/함수 표 추출 — Ghidra 없이.

두 산출물의 난이도가 완전히 다르다:

  functions_core<X>_ovl<N>.txt  ← **심볼 테이블만으로 정확히 나온다.**
      ELF 심볼은 st_shndx(소속 섹션)를 들고 있으므로 오버레이 섹션 번호로
      거르면 그 오버레이의 함수가 주소·크기·이름까지 그대로 떨어진다.
      디스어셈블이 전혀 필요 없고 추측도 없다.

  basic_blocks_core<X>_ovl<N>.txt ← 디스어셈블이 필요하다. 순서대로 시도:
      ① --objdump 로 준 RISC-V 지원 디스어셈블러(llvm-objdump / riscv*-objdump)
      ② 내장 RV32 스캐너(아래) — 분기/점프만 식별하면 되므로 완전한
         디스어셈블보다 훨씬 작은 문제다.

내장 스캐너가 보는 것만:
  · 명령 길이 — (h & 3) != 3 이면 2바이트(RVC), 아니면 4바이트. GCC 는 48/64비트
    인코딩을 쓰지 않는다.
  · 종결 명령 — 32bit: BRANCH(0x63)/JAL(0x6F)/JALR(0x67)/SYSTEM(0x73 중 ecall·
    ebreak·*ret),  RVC: C.J/C.JAL/C.BEQZ/C.BNEZ/C.JR/C.JALR
  · 리더(BB 시작) — 함수 진입점(심볼) + 직접분기 타겟(계산 가능) + 종결 다음 주소

한계(정직하게): 간접점프(JALR/C.JR) 타겟은 모른다 → 스위치 테이블 진입점이
리더에서 빠져 BB 가 **덜 쪼개진다**. 덜 쪼개지는 건 커버리지 해상도가 거칠어질
뿐 틀린 게 아니다(잘못 쪼개지는 것보다 안전하다). 정확도가 더 필요하면 ①을 쓴다.

사용:
    python3 tools/overlay_export.py --elf FW_FCore.elf --map ovl_F.json --core F \
            --outdir products/BM9K1 [--objdump llvm-objdump]
"""
import argparse
import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import overlay_probe as op          # noqa: E402  (ELF 파서·맵 로더 재사용)

STT_FUNC = 2


# ── 심볼 테이블 ─────────────────────────────
def read_symbols(path):
    """[(name, value, size, shndx, type)] — ELF32-LE symtab."""
    sec, data = op.read_sections(path)
    with open(path, 'rb') as f:
        raw = f.read()
    e_shoff, = struct.unpack_from('<I', raw, 0x20)
    e_shentsize, e_shnum = struct.unpack_from('<HH', raw, 0x2E)
    symtab = None
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        sh_type, = struct.unpack_from('<I', raw, b + 4)
        if sh_type == 2:                       # SHT_SYMTAB
            sh_off, sh_size = struct.unpack_from('<II', raw, b + 16)
            sh_link, = struct.unpack_from('<I', raw, b + 24)
            symtab = (sh_off, sh_size, sh_link)
            break
    if symtab is None:
        raise SystemExit("[ovl] SHT_SYMTAB 이 없다 — strip 된 ELF 로는 함수표를 못 만든다")
    sh_off, sh_size, strndx = symtab
    str_off, str_size = sec[strndx][1], sec[strndx][2]
    strtab = raw[str_off:str_off + str_size]
    out = []
    for o in range(sh_off, sh_off + sh_size, 16):
        st_name, st_value, st_size = struct.unpack_from('<III', raw, o)
        st_info, _st_other, st_shndx = struct.unpack_from('<BBH', raw, o + 12)
        if st_name >= len(strtab):
            continue
        end = strtab.find(b'\0', st_name)
        name = strtab[st_name:end].decode('utf-8', 'replace')
        out.append((name, st_value, st_size, st_shndx, st_info & 0xF))
    return out


def funcs_of_section(syms, shndx):
    """그 섹션에 속한 STT_FUNC 만. 크기 0(별칭/thunk)은 버린다 — 범위가 없으면
    bisect 조회에서 무의미하다."""
    rows = [(v, s, n) for (n, v, s, sh, t) in syms
            if sh == shndx and t == STT_FUNC and s > 0 and n]
    rows.sort()
    return rows


# ── 내장 RV32 BB 스캐너 ──────────────────────
def _ilen(half):
    return 2 if (half & 0x3) != 0x3 else 4


def _term32(w):
    """(종결인가, 직접타겟 offset 또는 None)"""
    op7 = w & 0x7F
    if op7 == 0x63:                                    # BRANCH
        imm = (((w >> 31) & 1) << 12) | (((w >> 7) & 1) << 11) | \
              (((w >> 25) & 0x3F) << 5) | (((w >> 8) & 0xF) << 1)
        if imm & 0x1000:
            imm -= 0x2000
        return True, imm
    if op7 == 0x6F:                                    # JAL
        imm = (((w >> 31) & 1) << 20) | (((w >> 12) & 0xFF) << 12) | \
              (((w >> 20) & 1) << 11) | (((w >> 21) & 0x3FF) << 1)
        if imm & 0x100000:
            imm -= 0x200000
        return True, imm
    if op7 == 0x67:                                    # JALR — 간접
        return True, None
    if op7 == 0x73:                                    # SYSTEM
        funct3 = (w >> 12) & 7
        if funct3 == 0:                                # ecall/ebreak/*ret/wfi
            return True, None
        return False, None
    return False, None


def _term16(h):
    q, f3 = h & 0x3, (h >> 13) & 0x7
    if q == 1:
        if f3 in (1, 5):                               # C.JAL(RV32) / C.J
            imm = (((h >> 12) & 1) << 11) | (((h >> 11) & 1) << 4) | \
                  (((h >> 9) & 3) << 8) | (((h >> 8) & 1) << 10) | \
                  (((h >> 7) & 1) << 6) | (((h >> 6) & 1) << 7) | \
                  (((h >> 3) & 7) << 1) | (((h >> 2) & 1) << 5)
            if imm & 0x800:
                imm -= 0x1000
            return True, imm
        if f3 in (6, 7):                               # C.BEQZ / C.BNEZ
            imm = (((h >> 12) & 1) << 8) | (((h >> 10) & 3) << 3) | \
                  (((h >> 5) & 3) << 6) | (((h >> 3) & 3) << 1) | \
                  (((h >> 2) & 1) << 5)
            if imm & 0x100:
                imm -= 0x200
            return True, imm
    if q == 2 and f3 == 4:                             # C.JR / C.JALR / C.EBREAK
        rs2 = (h >> 2) & 0x1F
        rs1 = (h >> 7) & 0x1F
        if rs2 == 0 and rs1 != 0:
            return True, None
    return False, None


def scan_blocks(body, base, func_entries):
    """섹션 바이트 → [(start, end)]. func_entries 는 리더 시드."""
    n = len(body)
    leaders = {a for a in func_entries if base <= a < base + n}
    leaders.add(base)
    terms = {}                                   # 종결명령 주소 → 다음 주소
    pc = 0
    while pc + 1 < n:
        h = struct.unpack_from('<H', body, pc)[0]
        ln = _ilen(h)
        if pc + ln > n:
            break
        if ln == 4:
            w = struct.unpack_from('<I', body, pc)[0]
            is_t, off = _term32(w)
        else:
            is_t, off = _term16(h)
        if is_t:
            terms[base + pc] = base + pc + ln
            leaders.add(base + pc + ln)          # 종결 다음은 새 BB
            if off is not None:
                tgt = base + pc + off
                if base <= tgt < base + n:
                    leaders.add(tgt)             # 직접 분기 타겟
        pc += ln
    ordered = sorted(a for a in leaders if base <= a < base + n)
    blocks = []
    for i, a in enumerate(ordered):
        end = ordered[i + 1] if i + 1 < len(ordered) else base + n
        if end > a:
            blocks.append((a, end))
    return blocks


def blocks_via_objdump(tool, elf, section, base, size):
    """외부 디스어셈블러 경로. 실패하면 None 을 돌려 내장 스캐너로 넘어간다."""
    for args in ([tool, '-d', '--section', section, elf],
                 [tool, '-d', '-j', section, elf]):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=300)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode != 0 or not r.stdout:
            continue
        addrs = sorted({int(m.group(1), 16)
                        for m in re.finditer(r'^\s*([0-9a-f]+):\s', r.stdout, re.M)})
        addrs = [a for a in addrs if base <= a < base + size]
        if len(addrs) > 4:
            return addrs
    return None


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--elf', required=True)
    p.add_argument('--map', required=True)
    p.add_argument('--core', required=True)
    p.add_argument('--outdir', required=True)
    p.add_argument('--objdump', help='RISC-V 지원 디스어셈블러 (llvm-objdump 등)')
    a = p.parse_args()

    rows = op.load_map(a.map)
    bodies = op.extract(a.elf, rows)
    syms = read_symbols(a.elf)
    os.makedirs(a.outdir, exist_ok=True)

    for bank, (name, idx, base, size) in enumerate(rows):
        fns = funcs_of_section(syms, idx)
        fpath = os.path.join(a.outdir, f"functions_core{a.core}_ovl{bank}.txt")
        with open(fpath, 'w') as f:
            for v, s, nm in fns:
                f.write(f"0x{v:x} {s} {nm}\n")

        blocks = None
        if a.objdump:
            addrs = blocks_via_objdump(a.objdump, a.elf, name, base, size)
            if addrs:
                blocks = [(addrs[i], addrs[i + 1] if i + 1 < len(addrs) else base + size)
                          for i in range(len(addrs))]
                src = f"objdump({a.objdump})"
        if blocks is None:
            blocks = scan_blocks(bodies[idx], base, [v for v, _s, _n in fns])
            src = "내장 RV32 스캐너"
        bpath = os.path.join(a.outdir, f"basic_blocks_core{a.core}_ovl{bank}.txt")
        with open(bpath, 'w') as f:
            for s0, e0 in blocks:
                f.write(f"0x{s0:x} 0x{e0:x}\n")

        print(f"[ovl] bank {bank} ({name}, idx={idx}) — 함수 {len(fns):4} / "
              f"BB {len(blocks):5}  [{src}]")
        if not fns:
            print(f"      ⚠ 이 섹션에 STT_FUNC 심볼이 없다 — 함수표가 비었다",
                  file=sys.stderr)
    print(f"[ovl] 출력: {a.outdir}/{{basic_blocks,functions}}_core{a.core}_ovl*.txt")
    return 0


if __name__ == '__main__':
    sys.exit(main())
