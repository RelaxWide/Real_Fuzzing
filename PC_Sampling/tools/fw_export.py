#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""펌웨어 1회 추출 — ELF 만으로 커버리지 자산 전부. Ghidra headless 대체.

펌웨어가 새로 나올 때마다 Ghidra 를 띄우는 대신 이 명령 하나로 끝낸다.

    python3 tools/fw_export.py --product BM9K1 --outdir products/BM9K1 \
        --core H:FW_HCore.elf --core CM:FW_CMCore.elf \
        --core F:FW_FCore.elf:ovl_F.json --core Q:FW_QCore.elf

산출(코어별):
    basic_blocks_core<X>.txt      functions_core<X>.txt
    callgraph_core<X>.txt         symbols.json (전 코어 합본)
    + 오버레이 맵을 준 코어는 overlay_map_core<X>.json 과
      basic_blocks/functions_core<X>_ovl<N>.txt

왜 ELF 가 Ghidra 보다 나은가(이 제품 한정):
  · 함수 이름·주소·크기 — 심볼 테이블이 **권위 있는 원본**이다. Ghidra 는 추론한다.
  · 오버레이 소속 — st_shndx 로 정확하다. Ghidra 의 overlay space 는 다루기 번거롭다.
  · 재현성·속도 — 수 초, 결정적, 설치 불필요. 프로젝트 상태 관리가 없다.
  · BB 는 **심볼 경계 안에서만** 해독하므로 함수 사이 데이터를 오독하지 않는다.

Ghidra 가 여전히 나은 지점(정직하게):
  · 간접점프(스위치 테이블) 타겟 해석 → BB 가 덜 쪼개진다(해상도만 거칠어짐).
  · 심볼에 없는 코드 탐지. 심볼 있는 ELF 라면 해당 없음.
  → 한 번은 양쪽을 돌려 BB 수를 비교해보고 채택하는 것을 권한다(--compare 로 출력).
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import overlay_export as oe          # noqa: E402
import overlay_probe as op           # noqa: E402

SHF_EXECINSTR = 0x4


def exec_sections(elf):
    """실행 플래그가 선 PROGBITS 섹션 [(idx, addr, off, size)]."""
    import struct
    with open(elf, 'rb') as f:
        raw = f.read()
    e_shoff, = struct.unpack_from('<I', raw, 0x20)
    e_shentsize, e_shnum = struct.unpack_from('<HH', raw, 0x2E)
    out = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        sh_type, sh_flags, sh_addr, sh_off, sh_size = struct.unpack_from('<IIIII', raw, b + 4)
        if sh_type == 1 and (sh_flags & SHF_EXECINSTR) and sh_size:
            out.append((i, sh_addr, sh_off, sh_size))
    return out, raw


def export_core(core, elf, ovl_map, outdir, objdump=None):
    syms = oe.read_symbols(elf)
    secs, raw = exec_sections(elf)
    ovl_idx = set()
    info = {"elf": os.path.abspath(elf),
            "elf_sha256": hashlib.sha256(open(elf, 'rb').read()).hexdigest()}

    if ovl_map:
        rows = op.load_map(ovl_map)
        bodies = op.extract(elf, rows)
        ovl_idx = {idx for _n, idx, _a, _s in rows}
        idx_to_ord = {idx: n for n, (_nm, idx, _a, _s) in enumerate(rows)}
        k, vals = op.find_probe(bodies)
        hdr = op.detect_header(vals) if k is not None else None
        base = rows[0][2]
        end = base + max(r[3] for r in rows)
        doc = {"core": core, "base": base, "window_end": end,
               "probe_offsets": [k] if k is not None else [],
               "probe_to_bank": {f"0x{v:08X}": idx_to_ord[i]
                                 for i, v in (vals or {}).items()},
               "bank_sizes": {str(n): s for n, (_nm, _i, _a, s) in enumerate(rows)}}
        if hdr:
            mask, magic, id_to_idx, _t = hdr
            doc["header"] = {"magic_mask": f"0x{mask:08X}", "magic": f"0x{magic:08X}",
                             "id_mask": f"0x{~mask & 0xFFFFFFFF:08X}",
                             "id_to_section": {str(a): b for a, b in id_to_idx.items()}}
        with open(os.path.join(outdir, f"overlay_map_core{core}.json"), 'w',
                  encoding='utf-8') as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        info["overlay"] = {"base": base, "window_end": end, "banks": len(rows),
                           "probe_offset": k, "header": bool(hdr)}
        for bank, (_name, idx, b0, _sz) in enumerate(rows):
            fns = oe.funcs_of_section(syms, idx)
            _write_funcs(os.path.join(outdir, f"functions_core{core}_ovl{bank}.txt"), fns)
            blk = oe.scan_blocks_bounded(bodies[idx], b0, fns)
            _write_bbs(os.path.join(outdir, f"basic_blocks_core{core}_ovl{bank}.txt"), blk)
            print(f"  [{core}] ovl{bank} (idx={idx}) 함수 {len(fns):5} / BB {len(blk):6}")

    # ── 비오버레이 본체 ──
    all_fns, all_bbs, edges = [], [], {}
    for idx, addr, off, size in secs:
        if idx in ovl_idx:
            continue                     # 오버레이는 위에서 bank 별로 처리했다
        body = raw[off:off + size]
        fns = oe.funcs_of_section(syms, idx)
        all_fns.extend(fns)
        all_bbs.extend(oe.scan_blocks_bounded(body, addr, fns))
        for c, cs in oe.extract_callgraph(body, addr, fns).items():
            edges.setdefault(c, set()).update(cs)
    all_fns.sort()
    all_bbs.sort()
    _write_funcs(os.path.join(outdir, f"functions_core{core}.txt"), all_fns)
    _write_bbs(os.path.join(outdir, f"basic_blocks_core{core}.txt"), all_bbs)
    with open(os.path.join(outdir, f"callgraph_core{core}.txt"), 'w') as f:
        for c in sorted(edges):
            for e in sorted(edges[c]):
                f.write(f"0x{c:x} 0x{e:x}\n")
    info.update({"functions": len(all_fns), "basic_blocks": len(all_bbs),
                 "callgraph_edges": sum(len(v) for v in edges.values()),
                 "exec_sections": len(secs)})
    print(f"  [{core}] 본체 함수 {len(all_fns):5} / BB {len(all_bbs):6} / "
          f"콜그래프 간선 {info['callgraph_edges']:5}")
    # 오버레이에만 함수가 있는 코어도 있으므로, 본체가 비었다고 바로 경고하지 않는다.
    if not all_fns and not info.get("overlay", {}).get("banks"):
        print(f"  ⚠ [{core}] STT_FUNC 심볼이 없다 — strip 된 ELF 면 Ghidra 가 필요하다",
              file=sys.stderr)
    return info


def _write_funcs(path, rows):
    with open(path, 'w') as f:
        for v, s, n in rows:
            f.write(f"0x{v:x} {s} {n}\n")


def _write_bbs(path, rows):
    with open(path, 'w') as f:
        for a, b in rows:
            f.write(f"0x{a:x} 0x{b:x}\n")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--core', action='append', required=True,
                   metavar='NAME:ELF[:OVLMAP]',
                   help='예: F:FW_FCore.elf:ovl_F.json (반복 지정)')
    p.add_argument('--product', default='')
    p.add_argument('--outdir', required=True)
    p.add_argument('--objdump', help='RISC-V 디스어셈블러(선택, 더 정확한 BB)')
    a = p.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    cores = {}
    for spec in a.core:
        parts = spec.split(':')
        if len(parts) < 2:
            raise SystemExit(f"[fw] --core 형식은 NAME:ELF[:OVLMAP] — 받은 값: {spec!r}")
        name, elf = parts[0], parts[1]
        ovl = parts[2] if len(parts) > 2 else None
        if not os.path.exists(elf):
            raise SystemExit(f"[fw] ELF 없음: {elf}")
        if ovl and not os.path.exists(ovl):
            raise SystemExit(f"[fw] 오버레이 맵 없음: {ovl}")
        print(f"[fw] {name} ← {elf}" + (f" (+오버레이 {ovl})" if ovl else ""))
        cores[name] = export_core(name, elf, ovl, a.outdir, a.objdump)

    doc = {"product": a.product, "generated": datetime.now().isoformat(timespec='seconds'),
           "source": "fw_export.py (ELF 직접 추출)", "cores": cores,
           "bb_end_convention": "exclusive"}
    with open(os.path.join(a.outdir, 'symbols.json'), 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    print(f"[fw] symbols.json 포함 {a.outdir} 에 기록 완료")
    return 0


if __name__ == '__main__':
    sys.exit(main())
