#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""overlay_export 단위테스트 — Ghidra 없이 오버레이별 BB/함수 표를 뽑는다.

BB 스캐너는 **인코딩을 손으로 디코드**하므로 여기가 유일한 안전망이다.
잘못 디코드하면 BB 경계가 조용히 틀리고, 그 위의 커버리지가 전부 오염된다.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).with_name('tools')))
import overlay_export as oe          # noqa: E402

BASE = 0xAE000


def jal(rd, off):
    i = off & 0x1FFFFF
    return ((((i >> 20) & 1) << 31) | (((i >> 1) & 0x3FF) << 21) |
            (((i >> 11) & 1) << 20) | (((i >> 12) & 0xFF) << 12) | (rd << 7) | 0x6F)


def beq(rs1, rs2, off):
    i = off & 0x1FFF
    return ((((i >> 12) & 1) << 31) | (((i >> 5) & 0x3F) << 25) | (rs2 << 20) |
            (rs1 << 15) | (((i >> 1) & 0xF) << 8) | (((i >> 11) & 1) << 7) | 0x63)


def cj(off):
    i = off & 0xFFF
    return ((0b101 << 13) | (((i >> 11) & 1) << 12) | (((i >> 4) & 1) << 11) |
            (((i >> 8) & 3) << 9) | (((i >> 10) & 1) << 8) | (((i >> 6) & 1) << 7) |
            (((i >> 7) & 1) << 6) | (((i >> 1) & 7) << 3) | (((i >> 5) & 1) << 2) | 1)


class TestInstLength(unittest.TestCase):
    """길이를 틀리면 그 뒤 스트림 전체가 어긋난다."""

    def test_32bit(self):
        self.assertEqual(oe._ilen(0x0093), 4)      # addi 하위 half

    def test_compressed(self):
        for h in (0x0001, 0x8082, 0x4501):
            self.assertEqual(oe._ilen(h), 2)


class TestTerm32(unittest.TestCase):
    def test_jal_offsets(self):
        for off in (8, -16, 0x7FC, -0x800, 0xFFFFE, -0x100000):
            self.assertEqual(oe._term32(jal(0, off)), (True, off), f"JAL {off}")

    def test_branch_offsets(self):
        for off in (12, -8, 0xFFE, -0x1000):
            self.assertEqual(oe._term32(beq(0, 0, off)), (True, off), f"BEQ {off}")

    def test_indirect_and_system(self):
        self.assertEqual(oe._term32(0x000080E7), (True, None))   # jalr
        self.assertEqual(oe._term32(0x00000073), (True, None))   # ecall
        self.assertEqual(oe._term32(0x30200073), (True, None))   # mret

    def test_csr_is_not_terminator(self):
        """SYSTEM 이지만 funct3!=0 인 CSR 접근은 흐름을 끊지 않는다."""
        self.assertEqual(oe._term32(0x30001073)[0], False)       # csrrw

    def test_plain_alu_not_terminator(self):
        for w in (0x00100093, 0x00208033, 0x00052503):
            self.assertFalse(oe._term32(w)[0])


class TestTerm16(unittest.TestCase):
    def test_cj(self):
        for off in (6, -8, 42, 0x7FE, -0x800):
            self.assertEqual(oe._term16(cj(off)), (True, off), f"C.J {off}")

    def test_cjr_indirect(self):
        self.assertEqual(oe._term16(0x8082), (True, None))       # c.jr ra

    def test_cnop_not_terminator(self):
        self.assertFalse(oe._term16(0x0001)[0])

    def test_cli_not_terminator(self):
        self.assertFalse(oe._term16(0x4501)[0])                  # c.li a0,0


class TestScanBlocks(unittest.TestCase):
    def test_mixed_stream(self):
        """앞으로/뒤로 분기가 모두 리더를 만든다."""
        body = (struct.pack('<I', 0x00100093) +            # +0  addi
                struct.pack('<I', beq(0, 0, 12)) +         # +4  beq → +16
                struct.pack('<I', 0x00200113) +            # +8  addi
                struct.pack('<I', jal(0, -8)) +            # +12 jal → +4
                struct.pack('<I', 0x00300193) +            # +16 addi
                struct.pack('<H', 0x8082))                 # +20 c.jr
        got = oe.scan_blocks(body, BASE, [BASE])
        self.assertEqual(got, [(BASE, BASE + 4),           # jal 이 +4 를 가리킨다
                               (BASE + 4, BASE + 8),
                               (BASE + 8, BASE + 16),
                               (BASE + 16, BASE + 22)])

    def test_function_entries_are_leaders(self):
        body = struct.pack('<I', 0x00100093) * 4
        got = oe.scan_blocks(body, BASE, [BASE, BASE + 8])
        self.assertEqual(got, [(BASE, BASE + 8), (BASE + 8, BASE + 16)])

    def test_blocks_are_contiguous_and_cover_section(self):
        """빈틈이 있으면 그 구간 PC 가 어떤 BB 에도 안 잡혀 조용히 사라진다."""
        body = (struct.pack('<I', beq(0, 0, 8)) + struct.pack('<I', 0x00100093) +
                struct.pack('<H', 0x0001) + struct.pack('<I', jal(0, 4)) +
                struct.pack('<H', 0x0001))
        got = oe.scan_blocks(body, BASE, [BASE])
        self.assertEqual(got[0][0], BASE)
        self.assertEqual(got[-1][1], BASE + len(body))
        for i in range(len(got) - 1):
            self.assertEqual(got[i][1], got[i + 1][0], "BB 사이에 빈틈")

    def test_targets_outside_section_ignored(self):
        """섹션 밖으로 나가는 분기 타겟을 리더로 넣으면 범위 밖 BB 가 생긴다."""
        body = struct.pack('<I', jal(0, 0x1000)) + struct.pack('<I', 0x00100093)
        got = oe.scan_blocks(body, BASE, [BASE])
        for s, e in got:
            self.assertGreaterEqual(s, BASE)
            self.assertLessEqual(e, BASE + len(body))

    def test_truncated_tail_does_not_crash(self):
        body = struct.pack('<I', 0x00100093) + b'\x93'
        oe.scan_blocks(body, BASE, [BASE])

    def test_empty_section(self):
        self.assertEqual(oe.scan_blocks(b'', BASE, []), [])


class TestSymbolFilter(unittest.TestCase):
    """함수표는 심볼 테이블만으로 정확히 나온다 — 추측이 없다."""

    def test_filters_by_section_and_type(self):
        syms = [("f_ovl0", 0xAE000, 32, 15, oe.STT_FUNC),
                ("f_ovl1", 0xAE000, 48, 16, oe.STT_FUNC),
                ("data", 0xAE100, 4, 15, 1),                  # STT_OBJECT
                ("zero_size", 0xAE200, 0, 15, oe.STT_FUNC),   # 크기 0 → 제외
                ("", 0xAE300, 8, 15, oe.STT_FUNC)]            # 이름 없음 → 제외
        self.assertEqual(oe.funcs_of_section(syms, 15), [(0xAE000, 32, "f_ovl0")])
        self.assertEqual(oe.funcs_of_section(syms, 16), [(0xAE000, 48, "f_ovl1")])

    def test_same_address_different_sections(self):
        """오버레이의 핵심 — 같은 주소가 섹션별로 다른 함수다."""
        syms = [("a", 0xAE000, 10, 15, oe.STT_FUNC),
                ("b", 0xAE000, 20, 16, oe.STT_FUNC)]
        self.assertNotEqual(oe.funcs_of_section(syms, 15),
                            oe.funcs_of_section(syms, 16))


if __name__ == '__main__':
    unittest.main(verbosity=2)


class TestBoundedScanAndCallgraph(unittest.TestCase):
    """심볼 경계 스캔 + 직접호출 콜그래프 — Ghidra 대체의 핵심 두 조각."""

    def test_data_between_functions_not_decoded(self):
        """함수 사이 데이터를 명령으로 오독하면 그 뒤 스트림 전체가 어긋난다."""
        body = (struct.pack('<I', 0x00100093) + struct.pack('<I', jal(1, 28)) +
                struct.pack('<I', 0x00100093) * 2 +
                b'\xff\xff\xff\xff' * 4 +                    # 데이터 구간
                struct.pack('<I', 0x00100093) + struct.pack('<H', 0x8082) + b'\x00\x00')
        got = oe.scan_blocks_bounded(body, BASE, [(BASE, 16, 'f0'), (BASE + 32, 8, 'f1')])
        for s, _e in got:
            self.assertFalse(BASE + 16 <= s < BASE + 32, "데이터 구간에 BB 가 생겼다")

    def test_bounded_covers_only_function_bodies(self):
        body = struct.pack('<I', 0x00100093) * 8
        got = oe.scan_blocks_bounded(body, BASE, [(BASE, 8, 'a')])
        self.assertEqual(got, [(BASE, BASE + 8)])

    def test_falls_back_when_no_symbols(self):
        """심볼이 없으면 선형 스캔으로 떨어져야 한다(아무것도 안 내면 안 된다)."""
        body = struct.pack('<I', 0x00100093) * 4
        self.assertTrue(oe.scan_blocks_bounded(body, BASE, []))

    def test_callgraph_direct_call(self):
        body = (struct.pack('<I', 0x00100093) + struct.pack('<I', jal(1, 28)) +
                struct.pack('<I', 0x00100093) * 2 + b'\x00' * 16 +
                struct.pack('<H', 0x8082) + b'\x00' * 6)
        cg = oe.extract_callgraph(body, BASE, [(BASE, 16, 'a'), (BASE + 32, 8, 'b')])
        self.assertEqual(cg.get(BASE), {BASE + 32})

    def test_callgraph_tail_call(self):
        """rd=x0 인 JAL(꼬리호출)도 간선이다."""
        body = (struct.pack('<I', jal(0, 32)) + struct.pack('<I', 0x00100093) * 3 +
                b'\x00' * 16 + struct.pack('<H', 0x8082) + b'\x00' * 6)
        cg = oe.extract_callgraph(body, BASE, [(BASE, 16, 'a'), (BASE + 32, 8, 'b')])
        self.assertEqual(cg.get(BASE), {BASE + 32})

    def test_callgraph_excludes_self_recursion(self):
        body = struct.pack('<I', jal(1, 0)) + struct.pack('<I', 0x00100093) * 3
        self.assertEqual(oe.extract_callgraph(body, BASE, [(BASE, 16, 'a')]), {})

    def test_callgraph_ignores_non_entry_targets(self):
        """함수 내부로 뛰는 것은 호출이 아니라 분기다."""
        body = struct.pack('<I', jal(1, 8)) + struct.pack('<I', 0x00100093) * 3
        self.assertEqual(oe.extract_callgraph(body, BASE, [(BASE, 16, 'a')]), {})
