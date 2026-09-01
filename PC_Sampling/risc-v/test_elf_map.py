#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""elf_map 단위테스트.  실행:  python3 -m unittest -v test_elf_map"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import elf_map as em

# 실제 readelf -lW 출력 발췌 — Flg 가 'R E'(공백), 'RW', 'R' 로 제각각인 케이스.
READELF_SAMPLE = """
Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x0002d8 0x0002d8 R   0x8
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x0036a8 0x0036a8 R   0x1000
  LOAD           0x004000 0x0000000000004000 0x0000000000004000 0x013581 0x013581 R E 0x1000
  LOAD           0x021010 0x0000000000022010 0x0000000000022010 0x001258 0x002548 RW  0x1000
  DYNAMIC        0x021c40 0x0000000000022c40 0x0000000000022c40 0x000200 0x000200 RW  0x8
"""


class TestParse(unittest.TestCase):
    def test_exec_only(self):
        """실행(E) 세그먼트만, MemSiz 기준으로 뽑는다."""
        r = em.parse_readelf_l(READELF_SAMPLE)
        self.assertEqual(r, [(0x4000, 0x4000 + 0x13581)])

    def test_rwe_flag(self):
        """'RWE' 처럼 한 토큰으로 붙는 형태도 인식."""
        txt = "  LOAD  0x0 0x1000 0x1000 0x100 0x100 RWE 0x1000\n"
        self.assertEqual(em.parse_readelf_l(txt), [(0x1000, 0x1100)])

    def test_memsz_not_filesz(self):
        """.bss 포함 MemSiz 를 써야 한다(FileSiz 아님)."""
        txt = "  LOAD  0x0 0x2000 0x2000 0x10 0x500 R E 0x1000\n"
        self.assertEqual(em.parse_readelf_l(txt), [(0x2000, 0x2500)])

    def test_junk_ignored(self):
        self.assertEqual(em.parse_readelf_l("garbage\nLOAD nope\n"), [])


class TestRanges(unittest.TestCase):
    def setUp(self):
        self.rr = em.Ranges([(0x1000, 0x2000), (0x5000, 0x5100)])

    def test_boundaries(self):
        self.assertIn(0x1000, self.rr)          # start 포함
        self.assertIn(0x1FFF, self.rr)
        self.assertNotIn(0x2000, self.rr)       # end 제외(exclusive)
        self.assertNotIn(0xFFF, self.rr)
        self.assertIn(0x5000, self.rr)
        self.assertNotIn(0x3000, self.rr)       # 구간 사이 공백

    def test_span(self):
        self.assertEqual(self.rr.span, (0x1000, 0x5100))


class TestValidate(unittest.TestCase):
    def setUp(self):
        self.rr = em.Ranges([(0x1000, 0x2000)])

    def test_all_in(self):
        i = em.validate_pcs([0x1000, 0x1500, 0x1FFE], self.rr)
        self.assertEqual(i["pct"], 100.0)
        self.assertEqual(i["in_range"], 3)

    def test_offset_applied(self):
        """runtime_pc = elf_vaddr + offset → offset 지정 시 통과해야."""
        pcs = [0x41000, 0x41500]
        self.assertEqual(em.validate_pcs(pcs, self.rr, 0)["pct"], 0.0)
        self.assertEqual(em.validate_pcs(pcs, self.rr, 0x40000)["pct"], 100.0)

    def test_partial(self):
        i = em.validate_pcs([0x1000, 0x9999], self.rr)
        self.assertEqual(i["pct"], 50.0)

    def test_empty(self):
        i = em.validate_pcs([], self.rr)
        self.assertEqual(i["total"], 0)
        self.assertEqual(i["pct"], 0.0)
        self.assertIsNone(i["pc_min"])          # 크래시 없이 None

    def test_suggest_offset(self):
        cand, pct = em.suggest_offset([0x41000, 0x41500], self.rr)
        self.assertEqual(cand, 0x40000)
        self.assertEqual(pct, 100.0)

    def test_suggest_no_help(self):
        """흩어진 값이면 offset 으로도 못 살린다 → 낮은 pct 를 정직하게 보고."""
        _, pct = em.suggest_offset([0x10, 0x99999, 0xABCDEF], self.rr)
        self.assertLess(pct, 100.0)


class TestGate(unittest.TestCase):
    """게이트가 '조용히 틀린 심볼화'를 막는지 — 이 모듈의 존재 이유."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.elf = str(Path(self.tmp.name) / "fake.elf")
        Path(self.elf).write_bytes(b"not an elf")

    def tearDown(self):
        self.tmp.cleanup()

    def test_unreadable_elf_blocks(self):
        """실행영역을 못 읽으면 통과시키면 안 된다(검증 불가 = 실패)."""
        ok, info = em.check_gate([0x1000], self.elf, verbose=False)
        self.assertFalse(ok)
        self.assertEqual(info.get("error"), "no-exec-ranges")


@unittest.skipUnless(shutil.which("gcc") and shutil.which("readelf")
                     and shutil.which("addr2line") and shutil.which("objdump"),
                     "binutils/gcc 필요")
class TestRealBinary(unittest.TestCase):
    """실제 ELF 로 end-to-end — 인라인 체인·chunk 분할 회귀 방지."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        src = Path(cls.tmp.name) / "t.c"
        src.write_text(
            '#include <stdio.h>\n'
            'static int helper(int x){ return x*3+1; }\n'
            'static inline int inl(int x){ return helper(x)+2; }\n'
            'int worker(int n){ int s=0; for(int i=0;i<n;i++) s+=inl(i); return s; }\n'
            'int main(void){ printf("%d\\n", worker(5)); return 0; }\n')
        cls.elf = str(Path(cls.tmp.name) / "t")
        subprocess.run(["gcc", "-g", "-O2", "-o", cls.elf, str(src)], check=True)
        import re as _re
        d = subprocess.run(["objdump", "-d", cls.elf],
                           capture_output=True, text=True).stdout
        cls.rr = em.Ranges(em.exec_ranges(cls.elf))
        cls.addrs = sorted({int(m.group(1), 16)
                            for m in _re.finditer(r"^\s+([0-9a-f]+):\t", d, _re.M)})
        cls.addrs = [a for a in cls.addrs if a in cls.rr]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_gate_passes_offset0(self):
        ok, info = em.check_gate(self.addrs, self.elf, 0, verbose=False)
        self.assertTrue(ok)
        self.assertEqual(info["pct"], 100.0)

    def test_gate_fails_and_suggests(self):
        """PC 가 시프트돼 있으면 게이트가 막고 올바른 offset 을 제안해야."""
        shifted = [a + 0x40000 for a in self.addrs]
        ok, info = em.check_gate(shifted, self.elf, 0, verbose=False)
        self.assertFalse(ok)
        self.assertEqual(info["suggested_offset"], 0x40000)
        self.assertEqual(info["suggested_pct"], 100.0)

    def test_symbolize_finds_functions(self):
        sym = em.symbolize(self.elf, self.addrs)
        self.assertLessEqual(set(sym), set(self.addrs))   # 그룹 경계 어긋남 없음
        self.assertIn("worker", em.functions(sym))
        self.assertIn("main", em.functions(sym))

    def test_symbolize_inline_chain(self):
        """-i 인라인 체인(주소당 가변 줄 수)을 정확히 페어링하는지.
        순진한 '2줄씩' 파싱이면 여기서 깨진다."""
        sym = em.symbolize(self.elf, self.addrs)
        multi = [v for v in sym.values() if len(v) > 1]
        self.assertTrue(multi, "인라인 체인 샘플이 없음(컴파일러 차이면 무해)")
        for items in multi:                                # 모든 항목이 (func, loc) 쌍
            for fn, loc in items:
                self.assertTrue(fn and fn != "??")

    def test_chunking_identical(self):
        """chunk 경계에서 결과가 달라지면 안 된다(ARG_MAX 대응 분할)."""
        self.assertEqual(em.symbolize(self.elf, self.addrs, chunk=7),
                         em.symbolize(self.elf, self.addrs))


if __name__ == "__main__":
    unittest.main(verbosity=2)
