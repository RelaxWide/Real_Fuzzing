#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""코드 오버레이 bank 판별 프로브 생성 (BM9K1 F/H 코어).

문제: 오버레이 섹션들이 **같은 주소**를 공유한다(F코어: 4개 전부 0xAE000).
      그래서 그 창 안의 PC 는 "몇 번 오버레이의 코드인가" 가 정해지지 않는다.
      지금은 전부 한 덩어리로 뭉개져 커버리지·함수귀속·분모가 모두 틀린다.

해법: 오버레이들은 VMA 는 같아도 **ELF 파일 안에서는 각자 다른 오프셋**에 저장돼 있다.
      → 오프라인에서 N개 바이트를 전부 꺼내, 값이 서로 다른 워드 오프셋 k 를 찾는다.
      런타임에는 `base+k` 를 **1워드만** SBA 로 읽어 bank 를 확정한다(버스트 경계에서).

산출: overlay_map_core<X>.json — base / probe_offset / {워드값 → bank} / bank별 size.

사용:
    python3 tools/overlay_probe.py --elf FW_FCore.elf --map ovl_F.json --core F \\
            --out products/BM9K1/overlay_map_coreF.json
    # 0단계: 지금 커버리지의 몇 %가 오버레이 창에 떨어지는지
    python3 tools/overlay_probe.py --elf ... --map ... --coverage output/.../coverage.txt
"""
import argparse
import json
import struct
import sys

EI_CLASS, ELFCLASS32 = 4, 1


def read_sections(path):
    """ELF32-LE 섹션 헤더 → {index: (addr, offset, size)}. 최소 파서(의존성 없음)."""
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] != b'\x7fELF':
        raise SystemExit(f"[ovl] ELF 아님: {path}")
    if data[EI_CLASS] != ELFCLASS32:
        raise SystemExit(f"[ovl] ELF32 가 아니다(RV32 예상): {path}")
    e_shoff, = struct.unpack_from('<I', data, 0x20)
    e_shentsize, e_shnum = struct.unpack_from('<HH', data, 0x2E)
    if not e_shoff or not e_shnum:
        raise SystemExit(f"[ovl] 섹션 헤더가 없다: {path}")
    out = {}
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        sh_addr, sh_offset, sh_size = struct.unpack_from('<III', data, b + 12)
        sh_type, = struct.unpack_from('<I', data, b + 4)
        out[i] = (sh_addr, sh_offset, sh_size, sh_type)
    return out, data


def load_map(path):
    """오버레이 맵 JSON → [(name, index, addr, size)] (index 오름차순)."""
    with open(path, encoding='utf-8') as f:
        raw = json.load(f)
    rows = []
    for name, v in raw.items():
        try:
            rows.append((name, int(v['section_index']), int(v['addr']), int(v['size'])))
        except (KeyError, TypeError, ValueError) as e:
            raise SystemExit(f"[ovl] 맵 항목 {name!r} 해석 실패({e}) — "
                             f"section_index/addr/size 필드가 필요하다")
    if not rows:
        raise SystemExit("[ovl] 맵이 비었다")
    rows.sort(key=lambda r: r[1])
    return rows


def extract(elf_path, rows):
    """각 오버레이의 실제 바이트. JSON 과 ELF 가 어긋나면 **크게 실패**한다 —
    조용히 넘어가면 틀린 bank 표가 만들어져 커버리지가 통째로 오염된다."""
    sec, data = read_sections(elf_path)
    bodies = {}
    for name, idx, addr, size in rows:
        if idx not in sec:
            raise SystemExit(f"[ovl] 섹션 index {idx}({name}) 가 ELF 에 없다 "
                             f"(섹션 수={len(sec)})")
        sh_addr, sh_off, sh_size, sh_type = sec[idx]
        if sh_addr != addr:
            raise SystemExit(f"[ovl] {name}: 맵 addr=0x{addr:X} != ELF sh_addr=0x{sh_addr:X}"
                             f" — 맵과 ELF 가 다른 빌드다")
        if sh_size != size:
            raise SystemExit(f"[ovl] {name}: 맵 size={size} != ELF sh_size={sh_size}"
                             f" — 맵과 ELF 가 다른 빌드다")
        if sh_type == 8:          # SHT_NOBITS(.bss) — 파일에 내용이 없다
            raise SystemExit(f"[ovl] {name}: SHT_NOBITS 라 파일에 내용이 없다")
        bodies[idx] = data[sh_off:sh_off + sh_size]
        if len(bodies[idx]) != sh_size:
            raise SystemExit(f"[ovl] {name}: 파일이 잘렸다({len(bodies[idx])}/{sh_size})")
    return bodies


def find_probe(bodies, width=4):
    """모든 오버레이에서 값이 서로 다른 최소 워드 오프셋.

    짧은 오버레이도 커버해야 하므로 min(size) 안에서만 찾는다 — 범위를 넘으면
    그 오버레이가 올라와 있을 때 읽은 값이 인접 데이터라 판별이 무의미해진다.
    """
    limit = min(len(b) for b in bodies.values()) - width
    if limit < 0:
        raise SystemExit("[ovl] 가장 짧은 오버레이가 워드 하나보다 작다")
    for k in range(0, limit + 1, width):
        vals = {idx: struct.unpack_from('<I', b, k)[0] for idx, b in bodies.items()}
        if len(set(vals.values())) == len(vals):
            return k, vals
    return None, None


def find_probe_pair(bodies, width=4):
    """한 워드로 안 갈리면 두 워드 조합으로. (전부 같은 프롤로그로 시작하는 경우)"""
    limit = min(len(b) for b in bodies.values()) - width
    offs = list(range(0, limit + 1, width))
    for i, k1 in enumerate(offs):
        v1 = {idx: struct.unpack_from('<I', b, k1)[0] for idx, b in bodies.items()}
        for k2 in offs[i + 1:]:
            v2 = {idx: struct.unpack_from('<I', b, k2)[0] for idx, b in bodies.items()}
            combo = {idx: (v1[idx], v2[idx]) for idx in bodies}
            if len(set(combo.values())) == len(combo):
                return (k1, k2), combo
    return None, None


def stage0(cov_path, base, end):
    """0단계 — 현재 커버리지의 몇 %가 오버레이 창에 떨어지는가.
    이 숫자가 작으면 오버레이 대응 전체를 안 해도 된다."""
    pcs, inside = 0, 0
    with open(cov_path) as f:
        for line in f:
            t = line.split('#')[0].strip()
            if not t:
                continue
            try:
                v = int(t, 16) if t.lower().startswith('0x') else int(t)
            except ValueError:
                continue
            pcs += 1
            if base <= v < end:
                inside += 1
    return pcs, inside


def detect_header(vals):
    """프로브 워드가 '매직 + 순번 ID' 구조인지 본다.

    F코어 실측: 0x4F564C00/01/02/03 — 상위 3바이트가 'OVL'(0x4F564C) 로 고정이고
    하위 바이트가 오버레이 번호다. 즉 펌웨어가 심어둔 **의도된 헤더**지 우연히
    다른 코드 바이트가 아니다. 이러면 두 가지가 공짜로 생긴다:
      ① 상위 바이트로 읽은 값의 **유효성 검증**(매직 불일치 = 미탑재/복사중/읽기실패)
      ② 하위 바이트가 곧 bank 번호 → 표 없이도 해석 가능
    반환: (mask, magic, {id: section_index}) 또는 None.
    """
    if len(vals) < 2:
        return None
    for shift, mask in ((8, 0xFFFFFF00), (0, 0x00FFFFFF)):
        hi = {v & mask for v in vals.values()}
        if len(hi) != 1:
            continue
        ids = {idx: (v & ~mask) >> (0 if shift else 24) for idx, v in vals.items()}
        if len(set(ids.values())) != len(ids):
            continue
        seq = sorted(ids.values())
        if seq == list(range(seq[0], seq[0] + len(seq))):
            magic = hi.pop()
            txt = bytes((magic >> (8 * i)) & 0xFF for i in range(4))
            txt = b''.join(bytes([c]) for c in txt if 32 <= c < 127).decode() or '?'
            return mask, magic, {i: idx for idx, i in ids.items()}, txt
    return None


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--elf', required=True)
    p.add_argument('--map', required=True, help='오버레이 맵 JSON')
    p.add_argument('--core', default='?', help='코어 이름(H/CM/F/Q)')
    p.add_argument('--out', help='overlay_map_core<X>.json 출력 경로')
    p.add_argument('--coverage', help='0단계 측정용 coverage.txt')
    p.add_argument('--bb-file', dest='bb_file',
                   help='기존 basic_blocks_core<X>.txt — 오버레이 창의 분모 상태 점검')
    a = p.parse_args()

    rows = load_map(a.map)
    bodies = extract(a.elf, rows)
    base = rows[0][2]
    if len({r[2] for r in rows}) != 1:
        print(f"[ovl] 주의: addr 이 서로 다르다 {sorted({r[2] for r in rows})} — "
              f"진짜 오버레이가 아닐 수 있다(단순 섹션 분할).", file=sys.stderr)
    sizes = {r[1]: r[3] for r in rows}
    end = base + max(sizes.values())

    print(f"[ovl] core={a.core}  base=0x{base:X}  창=0x{base:X}~0x{end:X} "
          f"({max(sizes.values()):,}B)  오버레이 {len(rows)}개")
    _MAXL = 8
    for name, idx, _addr, size in rows[:_MAXL]:
        print(f"      idx={idx:<3} {name:<18} size={size:,} "
              f"(끝=0x{base + size:X})")
    if len(rows) > _MAXL:
        _sz = [r[3] for r in rows]
        print(f"      ... {len(rows) - _MAXL}개 더 (크기 {min(_sz):,}~{max(_sz):,}B, "
              f"총 {sum(_sz):,}B = 창의 {sum(_sz) / max(_sz):.1f}배가 같은 자리를 쓴다)")

    # ★ bank 는 **오버레이 순번**(0..3)이다 — 섹션 인덱스가 아니다.
    #   런타임이 헤더에서 뽑는 값(word & 0xFF)이 순번이고, 파일명도 _ovl<순번> 이라
    #   여기서 어긋나면 bank 표가 조용히 로드되지 않는다(실제로 겪음).
    idx_to_ord = {idx: n for n, (_nm, idx, _a, _s) in enumerate(rows)}
    k, vals = find_probe(bodies)
    if k is not None:
        probe = [k]
        table = {f"0x{v:08X}": idx_to_ord[idx] for idx, v in vals.items()}
        print(f"[ovl] 판별 오프셋 = +0x{k:X} (1워드) → 런타임에 0x{base + k:X} 를 읽는다")
    else:
        pair, combo = find_probe_pair(bodies)
        if pair is None:
            raise SystemExit("[ovl] 두 워드로도 판별 불가 — 오버레이 내용이 겹친다")
        probe = list(pair)
        table = {f"0x{v[0]:08X},0x{v[1]:08X}": idx_to_ord[idx] for idx, v in combo.items()}
        print(f"[ovl] 판별 오프셋 = +0x{pair[0]:X},+0x{pair[1]:X} (2워드)")
    _items = sorted(table.items(), key=lambda kv: kv[1])
    for key, idx in _items[:6]:
        print(f"      {key} → bank {idx}")
    if len(_items) > 6:
        print(f"      ... {len(_items) - 6}개 더 (전체는 출력 JSON 의 probe_to_bank)")

    hdr = detect_header(vals) if k is not None else None
    if hdr:
        mask, magic, id_to_idx, txt = hdr
        print(f"[ovl] ★ 구조화된 헤더 감지 — 매직 0x{magic:08X}(\"{txt}\") + 순번 ID")
        print(f"      런타임 검증: (word & 0x{mask:08X}) == 0x{magic:08X} 이어야 유효")
        id_to_bank = {i: idx_to_ord[j] for i, j in id_to_idx.items()}
        _bad = [(i, b) for i, b in sorted(id_to_bank.items()) if i != b]
        if _bad:
            print(f"      헤더 ID = word & 0x{~mask & 0xFFFFFFFF:08X} → bank "
                  f"(ID != bank 인 것 {len(_bad)}개): "
                  + ", ".join(f"ID{i}→bank{b}" for i, b in _bad[:8])
                  + (" ..." if len(_bad) > 8 else ""))
        else:
            print(f"      헤더 ID = word & 0x{~mask & 0xFFFFFFFF:08X} = bank "
                  f"(ID 0~{max(id_to_bank)} 이 bank 와 그대로 일치)")
        if any(i != b for i, b in id_to_bank.items()):
            print("      ⚠ 헤더 ID 가 bank 순번과 다르다 — 런타임은 반드시 probe_to_bank "
                  "표로 변환해야 한다(ID 를 bank 로 그대로 쓰면 표가 로드되지 않는다)",
                  file=sys.stderr)
        doc_hdr = {"magic_mask": f"0x{mask:08X}", "magic": f"0x{magic:08X}",
                   "id_mask": f"0x{~mask & 0xFFFFFFFF:08X}",
                   "id_to_section": {str(i): j for i, j in id_to_idx.items()},
                   # ★ 런타임은 이 표로 ID→bank 변환한다. ID 가 0 부터 시작한다는
                   #   보장이 없다(H코어 실측: ID 4~6, bank 0~2).
                   "id_to_bank": {str(i): b for i, b in id_to_bank.items()}}
    else:
        doc_hdr = None

    doc = {"core": a.core, "base": base, "window_end": end,
           "probe_offsets": probe, "probe_to_bank": table,
           "bank_sizes": {str(idx_to_ord[i]): s for i, s in sizes.items()},
           "header": doc_hdr,
           "note": "런타임: 버스트 경계에서 base+probe 를 읽어 bank 확정. "
                   "버스트 전후 값이 다르면 그 버스트는 폐기. header 가 있으면 "
                   "매직 불일치는 '미탑재/복사중/읽기실패' 로 보고 샘플을 버린다."}
    if a.out:
        with open(a.out, 'w', encoding='utf-8') as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        print(f"[ovl] 저장: {a.out}")

    if a.bb_file:
        # 분모 점검 — 관측(0단계)보다 이쪽이 크다. 35개 코드 본체가 한 주소에
        # 겹쳐 있으면 BB 표는 둘 중 하나다: (a) 한 오버레이 분량만 있고 나머지가
        # 통째로 분모에서 빠졌거나, (b) 전부 있어 같은 주소에 중복 항목이 쌓였고
        # bisect 가 아무거나 고른다. 어느 쪽이든 그 창의 커버리지 %는 틀렸다.
        starts, inwin, dup = [], 0, 0
        seen = set()
        with open(a.bb_file) as f:
            for line in f:
                q = line.split()
                if len(q) < 2:
                    continue
                try:
                    s0 = int(q[0], 16)
                except ValueError:
                    continue
                starts.append(s0)
                if base <= s0 < end:
                    inwin += 1
                    if s0 in seen:
                        dup += 1
                    seen.add(s0)
        print(f"[ovl] ── 분모 점검 ── {os.path.basename(a.bb_file)}: 전체 BB {len(starts):,}개, "
              f"오버레이 창 안 {inwin:,}개 (중복 시작주소 {dup:,}개)")
        n_ovl = len(rows)
        if inwin == 0:
            print("      → 창 안에 BB 가 하나도 없다. 오버레이 코드 전체가 분모에서 빠졌다.")
        elif dup == 0:
            print(f"      → 중복이 없다 = **한 오버레이 분량만** 있다. 나머지 {n_ovl - 1}개"
                  f"({sum(r[3] for r in rows) - max(r[3] for r in rows):,}B)가 분모에서 빠졌다.")
        else:
            print(f"      → 중복이 있다 = 여러 오버레이가 겹쳐 들어갔다. bisect 는 그중"
                  f" 하나만 고르므로 함수 귀속이 틀리고 분모도 부풀어 있다.")
        print("      → fw_export.py 로 bank 별 표를 만들면 양쪽 다 해결된다.")

    if a.coverage:
        tot, ins = stage0(a.coverage, base, end)
        pct = 100.0 * ins / tot if tot else 0.0
        print(f"[ovl] ── 0단계 ── 커버리지 PC {tot:,}개 중 오버레이 창 {ins:,}개 "
              f"({pct:.1f}%)")
        print("      → 이 비율이 작으면 오버레이 대응을 안 해도 된다." if pct < 5 else
              "      → 무시할 수 없는 비율이다. bank 반영이 필요하다.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
