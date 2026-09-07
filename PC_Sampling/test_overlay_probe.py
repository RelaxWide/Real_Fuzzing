#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""overlay_probe 단위테스트.  실행: python3 -m unittest -v test_overlay_probe"""
import json
import os
import random
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).with_name('tools')))
import overlay_probe as op          # noqa: E402

BASE = 712704                        # 0xAE000 — F코어 실측값
SIZES = {15: 11758, 16: 15970, 17: 10914, 18: 5010}


def build_elf(path, sizes=SIZES, base=BASE, shared_prefix=8, seed=42,
              elfclass=1, bad_size_for=None, bad_addr_for=None, nobits_for=None):
    rnd = random.Random(seed)
    rb = lambda n: bytes(rnd.randrange(256) for _ in range(n))
    bodies = {}
    for i, sz in sizes.items():
        b = bytearray(rb(sz))
        b[0:shared_prefix] = b'\x13\x00\x00\x00' * (shared_prefix // 4)
        bodies[i] = bytes(b)
    nsec = max(sizes) + 1
    hdr, shent, shoff = 52, 40, 52
    data_off = shoff + nsec * shent
    blob, offs = b'', {}
    for i in sorted(bodies):
        offs[i] = data_off + len(blob)
        blob += bodies[i]
    e = bytearray(b'\x7fELF' + bytes([elfclass]) + b'\x01\x01' + b'\x00' * 9)
    e += struct.pack('<HHI', 2, 243, 1)
    e += struct.pack('<III', 0, 0, shoff)
    e += struct.pack('<I', 0)
    e += struct.pack('<HHHHHH', hdr, 0, 0, shent, nsec, 0)
    sh = b''
    for i in range(nsec):
        if i in bodies:
            a = base + (0x1000 if i == bad_addr_for else 0)
            s = sizes[i] + (7 if i == bad_size_for else 0)
            t = 8 if i == nobits_for else 1
            sh += struct.pack('<IIIIIIIIII', 0, t, 6, a, offs[i], s, 0, 0, 4, 0)
        else:
            sh += struct.pack('<IIIIIIIIII', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    Path(path).write_bytes(bytes(e) + sh + blob)
    return bodies


def write_map(path, sizes=SIZES, base=BASE):
    json.dump({f".OVL_REGION_{n:02d}": {"section_index": i, "addr": base, "size": s}
               for n, (i, s) in enumerate(sorted(sizes.items()))},
              open(path, 'w'))


class TestProbe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.elf = os.path.join(self.tmp.name, 'f.elf')
        self.map = os.path.join(self.tmp.name, 'ovl.json')
        write_map(self.map)

    def tearDown(self):
        self.tmp.cleanup()

    def test_skips_shared_prologue(self):
        """오버레이들이 같은 프롤로그로 시작해도 갈리는 오프셋을 찾아야 한다."""
        build_elf(self.elf, shared_prefix=8)
        bodies = op.extract(self.elf, op.load_map(self.map))
        k, vals = op.find_probe(bodies)
        self.assertIsNotNone(k)
        self.assertGreaterEqual(k, 8, "공통 프롤로그 구간은 판별에 못 쓴다")
        self.assertEqual(len(set(vals.values())), len(SIZES))

    def test_probe_within_shortest_overlay(self):
        """가장 짧은 오버레이 범위를 넘으면, 그게 올라와 있을 때 인접 데이터를 읽어
        판별이 무의미해진다."""
        build_elf(self.elf)
        bodies = op.extract(self.elf, op.load_map(self.map))
        k, _ = op.find_probe(bodies)
        self.assertLessEqual(k + 4, min(SIZES.values()))

    def test_probe_is_word_aligned(self):
        build_elf(self.elf)
        k, _ = op.find_probe(op.extract(self.elf, op.load_map(self.map)))
        self.assertEqual(k % 4, 0)

    def test_two_word_fallback(self):
        """한 워드로 못 가르는 경우에도 조합으로 갈라야 한다."""
        bodies = {0: b'\xaa' * 64 + b'\x01\x00\x00\x00',
                  1: b'\xaa' * 64 + b'\x02\x00\x00\x00'}
        # 앞 64바이트가 동일 → 단일 워드로는 갈리는 오프셋이 뒤쪽에만 있다
        k, _ = op.find_probe(bodies)
        self.assertIsNotNone(k)
        pair, combo = op.find_probe_pair(bodies)
        self.assertIsNotNone(pair)
        self.assertEqual(len(set(combo.values())), 2)

    def test_indistinguishable_raises(self):
        """내용이 완전히 같으면 판별 불가를 정직하게 알려야 한다(조용히 아무 bank 금지)."""
        same = {0: b'\x11' * 128, 1: b'\x11' * 128}
        self.assertIsNone(op.find_probe(same)[0])
        self.assertIsNone(op.find_probe_pair(same)[0])


class TestFailLoud(unittest.TestCase):
    """맵과 ELF 가 어긋나면 크게 실패해야 한다 — 조용히 넘어가면 틀린 bank 표가
    만들어져 커버리지가 통째로 오염된다."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.elf = os.path.join(self.tmp.name, 'f.elf')
        self.map = os.path.join(self.tmp.name, 'ovl.json')
        write_map(self.map)

    def tearDown(self):
        self.tmp.cleanup()

    def test_addr_mismatch(self):
        build_elf(self.elf, bad_addr_for=16)
        with self.assertRaises(SystemExit) as c:
            op.extract(self.elf, op.load_map(self.map))
        self.assertIn('다른 빌드', str(c.exception))

    def test_size_mismatch(self):
        build_elf(self.elf, bad_size_for=17)
        with self.assertRaises(SystemExit):
            op.extract(self.elf, op.load_map(self.map))

    def test_missing_section(self):
        # 15/16 은 맵과 일치시키고 17/18 만 없앤다 → '섹션 없음' 이 먼저 걸려야 한다
        build_elf(self.elf, sizes={15: SIZES[15], 16: SIZES[16]})
        with self.assertRaises(SystemExit) as c:
            op.extract(self.elf, op.load_map(self.map))
        self.assertIn('없다', str(c.exception))

    def test_nobits_section(self):
        build_elf(self.elf, nobits_for=15)
        with self.assertRaises(SystemExit):
            op.extract(self.elf, op.load_map(self.map))

    def test_elf64_rejected(self):
        build_elf(self.elf, elfclass=2)
        with self.assertRaises(SystemExit) as c:
            op.read_sections(self.elf)
        self.assertIn('ELF32', str(c.exception))

    def test_not_elf(self):
        Path(self.elf).write_text('nope')
        with self.assertRaises(SystemExit):
            op.read_sections(self.elf)


class TestStage0(unittest.TestCase):
    """0단계 — 이 숫자가 오버레이 대응을 할지 말지를 정한다."""

    def test_counts_window_fraction(self):
        with tempfile.TemporaryDirectory() as d:
            cov = os.path.join(d, 'coverage.txt')
            with open(cov, 'w') as f:
                for _ in range(70):
                    f.write("0x20000\n")
                for _ in range(30):
                    f.write(f"0x{BASE + 16:x}\n")
            tot, ins = op.stage0(cov, BASE, BASE + max(SIZES.values()))
            self.assertEqual((tot, ins), (100, 30))

    def test_window_end_is_exclusive(self):
        with tempfile.TemporaryDirectory() as d:
            cov = os.path.join(d, 'coverage.txt')
            end = BASE + max(SIZES.values())
            Path(cov).write_text(f"0x{end:x}\n0x{end - 1:x}\n")
            tot, ins = op.stage0(cov, BASE, end)
            self.assertEqual((tot, ins), (2, 1))

    def test_ignores_comments_and_junk(self):
        with tempfile.TemporaryDirectory() as d:
            cov = os.path.join(d, 'coverage.txt')
            Path(cov).write_text("# comment\n\n0xAE010\ngarbage\n")
            tot, ins = op.stage0(cov, BASE, BASE + 15970)
            self.assertEqual((tot, ins), (1, 1))


if __name__ == '__main__':
    unittest.main(verbosity=2)
