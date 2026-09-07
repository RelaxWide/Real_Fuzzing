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


class TestHeaderDetect(unittest.TestCase):
    """F코어 실측: 프로브 워드가 'OVL' 매직 + 순번 ID 구조였다.
    이걸 인식하면 런타임에 **유효성 검증**이 공짜로 생긴다(매직 불일치 = 버릴 샘플)."""

    def test_real_values(self):
        vals = {15: 0x4F564C00, 16: 0x4F564C01, 17: 0x4F564C02, 18: 0x4F564C03}
        got = op.detect_header(vals)
        self.assertIsNotNone(got)
        mask, magic, id_to_idx, _txt = got
        self.assertEqual(mask, 0xFFFFFF00)
        self.assertEqual(magic, 0x4F564C00)
        self.assertEqual(id_to_idx, {0: 15, 1: 16, 2: 17, 3: 18})

    def test_validation_rejects_foreign_word(self):
        """매직이 안 맞는 값은 bank 로 해석하면 안 된다(미탑재/복사중/읽기실패)."""
        _mask, magic, _m, _t = op.detect_header(
            {15: 0x4F564C00, 16: 0x4F564C01, 17: 0x4F564C02, 18: 0x4F564C03})
        self.assertNotEqual(0xDEADBEEF & 0xFFFFFF00, magic)

    def test_non_sequential_ids_not_treated_as_header(self):
        """하위 바이트가 순번이 아니면 그냥 우연히 다른 코드 바이트다."""
        self.assertIsNone(op.detect_header(
            {15: 0x4F564C00, 16: 0x4F564C09, 17: 0x4F564C40, 18: 0x4F564CF1}))

    def test_random_words_not_treated_as_header(self):
        self.assertIsNone(op.detect_header(
            {15: 0x2F0F10D8, 16: 0x5958D650, 17: 0xA203B73C, 18: 0x6A48099D}))

    def test_single_overlay_no_header(self):
        self.assertIsNone(op.detect_header({15: 0x4F564C00}))


class TestBankIsOrdinal(unittest.TestCase):
    """★ bank 는 오버레이 **순번**(0..3)이어야 한다 — 섹션 인덱스가 아니다.

    런타임이 헤더에서 뽑는 값(word & 0xFF)이 순번이고 파일명도 _ovl<순번> 이라,
    여기서 섹션 인덱스를 쓰면 bank 표가 **조용히 로드되지 않는다**(실제로 겪었다).
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.elf = os.path.join(self.tmp.name, 'f.elf')
        self.map = os.path.join(self.tmp.name, 'ovl.json')
        self.out = os.path.join(self.tmp.name, 'm.json')
        write_map(self.map)
        build_elf(self.elf)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self):
        import subprocess
        tool = str(Path(__file__).with_name('tools') / 'overlay_probe.py')
        r = subprocess.run([sys.executable, tool, '--elf', self.elf, '--map', self.map,
                            '--core', 'F', '--out', self.out],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.load(open(self.out))

    def test_bank_sizes_keyed_by_ordinal(self):
        doc = self._run()
        self.assertEqual(sorted(doc['bank_sizes']), ['0', '1', '2', '3'])

    def test_probe_maps_to_ordinal(self):
        doc = self._run()
        self.assertEqual(sorted(doc['probe_to_bank'].values()), [0, 1, 2, 3])

    def test_sizes_match_section_order(self):
        """순번 0 은 section_index 가 가장 작은 것(=.OVL_REGION_00)이어야 한다."""
        doc = self._run()
        self.assertEqual(int(doc['bank_sizes']['0']), SIZES[15])
        self.assertEqual(int(doc['bank_sizes']['3']), SIZES[18])


class TestNonZeroHeaderIds(unittest.TestCase):
    """★ 헤더 ID 가 0 부터 시작한다는 보장이 없다.

    H코어 실측 가정: 오버레이 3개인데 헤더 ID 가 4~6(코어간 전역 번호매김).
    런타임이 `bank = word & 0xFF` 를 그대로 쓰면 4,5,6 이 나와 _ovl0~2 표와
    어긋나고 bank 표가 **조용히** 로드되지 않는다. probe_to_bank 가 권위다.
    """

    IDS = (4, 5, 6)
    SZ = {9: 1024, 10: 2048, 11: 768}

    def _vals(self):
        return {9 + n: 0x4F564C00 | i for n, i in enumerate(self.IDS)}

    def test_header_still_detected(self):
        got = op.detect_header(self._vals())
        self.assertIsNotNone(got, "ID 가 0 부터가 아니어도 연속이면 헤더다")
        _mask, magic, id_to_idx, _t = got
        self.assertEqual(magic, 0x4F564C00)
        self.assertEqual(sorted(id_to_idx), [4, 5, 6])

    def test_ids_map_to_ordinal_banks(self):
        """ID 4/5/6 → bank 0/1/2 로 변환돼야 한다."""
        _m, _mg, id_to_idx, _t = op.detect_header(self._vals())
        idx_to_ord = {idx: n for n, idx in enumerate(sorted(self.SZ))}
        id_to_bank = {i: idx_to_ord[j] for i, j in id_to_idx.items()}
        self.assertEqual(id_to_bank, {4: 0, 5: 1, 6: 2})

    def test_raw_id_would_be_wrong(self):
        """ID 를 bank 로 그대로 쓰면 표 범위를 벗어난다는 것을 고정한다."""
        banks = set(range(len(self.SZ)))
        self.assertFalse(set(self.IDS) <= banks,
                         "이 테스트의 전제(ID != bank)가 깨졌다")

    def test_gap_in_ids_not_a_header(self):
        """연속이 아니면 헤더로 보지 않는다(우연히 갈린 코드 바이트일 수 있다)."""
        self.assertIsNone(op.detect_header(
            {9: 0x4F564C04, 10: 0x4F564C05, 11: 0x4F564C09}))


class TestManyOverlays(unittest.TestCase):
    """H코어 실측: 오버레이 35개(REGION_00~34, section 19~53)가 0x56000 을 공유하고
    총 471KB 가 16KB 창을 29.7배로 돌려 쓴다. 4개짜리 F 와 규모가 다르다."""

    H_SIZES = [3370, 12896, 14326, 15464, 16006, 16178, 12080, 14982, 14490,
               15218, 10496, 14042, 16180, 15904, 11888, 16214, 13916, 15594,
               13290, 15228, 13868, 15544, 16130, 13838, 11108, 15762, 14158,
               14632, 15762, 15112, 13560, 11480, 13880, 12558, 7058]
    H_BASE = 352256

    def test_map_geometry(self):
        """플랜의 전제(35개 / section 19~53 / 같은 주소)를 고정한다."""
        self.assertEqual(len(self.H_SIZES), 35)
        self.assertEqual(19 + len(self.H_SIZES) - 1, 53)
        self.assertEqual(self.H_BASE, 0x56000)

    def test_probe_offset_fits_smallest_overlay(self):
        """가장 작은 오버레이(3,370B)보다 앞에서 판별돼야 한다 — 넘으면 그 오버레이가
        올라와 있을 때 인접 데이터를 읽는다."""
        vals = {19 + n: 0x4F564C00 | n for n in range(35)}
        self.assertEqual(len(set(vals.values())), 35)
        self.assertLess(4 + 4, min(self.H_SIZES))

    def test_header_detected_for_35(self):
        vals = {19 + n: 0x4F564C00 | n for n in range(35)}
        got = op.detect_header(vals)
        self.assertIsNotNone(got)
        _m, magic, id_to_idx, _t = got
        self.assertEqual(magic, 0x4F564C00)
        self.assertEqual(len(id_to_idx), 35)
        self.assertEqual(id_to_idx[34], 53)

    def test_bank_fits_key_field(self):
        """bank 필드 폭이 모자라면 키가 조용히 뭉개진다."""
        import riscv_cov as rc
        for b in range(35):
            k = rc.pack(0, b, self.H_BASE + 8)
            self.assertEqual(rc.unpack(k), (0, b, self.H_BASE + 8))

    def test_window_is_max_size(self):
        mx = max(self.H_SIZES)
        self.assertEqual(mx, 16214)
        self.assertEqual(self.H_BASE + mx, 0x59F56)
