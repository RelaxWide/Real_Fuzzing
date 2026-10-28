"""v11.5 제품 파생형 — BM9K1_LENOVO / BM9K1_HP.

PM9M1(_LENOVO/_HP)처럼 --product 로 고르는 파생형이다. BM9K1 전용 동작(PS 추적·timeout PS 배율)과
RISC-V 자산 products/BM9K1/ 은 제품명이 아니라 json products.<제품>.family 로 판정한다.
실제 송신 경로(_send_nvme_command)·PM 경로(_pm_set_state)·자산 로더(_load_riscv_coverage)를 태운다.
"""
import json
import unittest
from unittest.mock import Mock, patch

from fuzzer_target import fuzzer as v
import test_v11_exceptions as integration

CFG = json.loads((v.Path(v.__file__).parent / 'fuzzer_config.json').read_text(encoding='utf-8'))
PRODUCTS = CFG['products']
VARIANTS = ('BM9K1_LENOVO', 'BM9K1_HP')


class ShippedProfiles(unittest.TestCase):
    def test_variants_are_selectable(self):
        for name in VARIANTS:
            self.assertIn(name, v.PRODUCT_CONFIGS, f'--product {name} 를 고를 수 없다')

    def test_variants_match_bm9k1_except_variant_keys(self):
        base = PRODUCTS['BM9K1']
        allowed = {'BM9K1_LENOVO': {'_comment_variant'},
                   'BM9K1_HP': {'_comment_variant', 'state_exclude_lids'}}
        for name in VARIANTS:
            p = PRODUCTS[name]
            diff = {k for k in set(p) | set(base) if p.get(k) != base.get(k)}
            self.assertEqual(diff, allowed[name], f'{name} 가 BM9K1 과 다른 키')
            self.assertEqual(v._profile_family(name, p), 'BM9K1')

    def test_hp_drops_lid_0xdf_like_pm9m1_hp(self):
        self.assertEqual(PRODUCTS['BM9K1_HP']['state_exclude_lids'], PRODUCTS['PM9M1_HP']['state_exclude_lids'])
        lids = {f.get('lid') for f in v.STATE_FIELD_SETS[PRODUCTS['BM9K1_HP']['state_fields']]}
        self.assertIn(223, lids, 'bm9k1 세트에 LID 0xDF 필드가 없으면 제외 설정이 무의미하다')

    def test_bm9k1_kept_for_older_versions(self):
        # v11.4 이하는 BM9K1 전용 동작을 제품명 'BM9K1' 로만 판정하고, import 때 모든 프로필의 interface 를 읽는다.
        self.assertIn('BM9K1', PRODUCTS)
        for name, p in PRODUCTS.items():
            self.assertIn('interface', p, f'{name}: interface 없으면 구버전 import 가 죽는다')


class FamilyResolution(unittest.TestCase):
    def test_missing_family_is_product_name(self):
        self.assertNotIn('family', PRODUCTS['P9'])
        self.assertEqual(v._profile_family('P9', PRODUCTS['P9']), 'P9')
        self.assertEqual(v._profile_family('PM9M1_HP', PRODUCTS['PM9M1_HP']), 'PM9M1')
        self.assertEqual(v._profile_family('', {}), '')

    def test_bad_family_fails_loudly(self):
        for bad in ('', '  ', 3, ['BM9K1']):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                v._profile_family('X', {'family': bad})


class VariantGetsBm9k1Behaviour(unittest.TestCase):
    setUp = integration.RealTransportIntegration.setUp
    send = integration.RealTransportIntegration.send

    def prepare(self, product, family, ps):
        self.f.config.product = product
        self.f.config.product_family = family
        self.f._current_ps = ps
        self.f._exception_controller = None
        self.f._exception_on_spawn = None
        self.f.config.nvme_timeouts['command'] = 8000
        self.proc.returncode = 0

    def test_ps_timeout_factor(self):
        for product in VARIANTS:
            for ps, want in ((0, 8), (1, 80), (2, 80)):
                with self.subTest(product=product, ps=ps):
                    self.prepare(product, 'BM9K1', ps)
                    self.assertEqual(self.send(), 0)
                    self.assertAlmostEqual(self.proc.communicate.call_args.kwargs['timeout'], want)

    def test_other_family_keeps_margin_path(self):
        self.prepare('PM9M1_HP', '', 1)
        self.send()
        self.assertAlmostEqual(self.proc.communicate.call_args.kwargs['timeout'],
                               (8000 + v.PS_ENTRY_EXIT_MARGIN_MS) / 1000 + 2)

    def test_pm_set_state_tracks_ps(self):
        self.prepare('BM9K1_HP', 'BM9K1', 0)
        self.f._pm_nvme_run = Mock(return_value=Mock(returncode=0))
        self.f._pm_timed_out = Mock(return_value=False)
        self.f._op_record = Mock()
        self.assertTrue(v._V101Fuzzer._pm_set_state(self.f, 2))
        self.assertEqual(self.f._current_ps, 2, '파생형인데 PS 추적이 안 된다 → timeout 배율이 틀린다')


class RiscvAssetsAreShared(unittest.TestCase):
    def test_variant_loads_products_bm9k1(self):
        import riscv_cov
        f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
        f.config = v.FuzzConfig(product='BM9K1_HP', product_family='BM9K1', arch='riscv')
        f.cov = None
        with patch.object(riscv_cov.CoverageModel, 'load', side_effect=RuntimeError('stop')) as load:
            f._load_riscv_coverage()
        load.assert_called_once()
        self.assertEqual(v.Path(load.call_args.args[0]).name, 'BM9K1')


if __name__ == '__main__':
    unittest.main()
