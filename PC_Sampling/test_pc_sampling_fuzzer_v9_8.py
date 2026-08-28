"""v9.8 NSID 정책의 장치 비의존 회귀 테스트."""

import ast
from pathlib import Path
import unittest


_SOURCE = Path(__file__).with_name("pc_sampling_fuzzer_v9.8.py")


def _load_helpers():
    """대형 fuzzer 모듈의 HW 의존 import 없이 NSID 순수 함수만 로드한다."""
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    wanted = {"_resolve_nsid", "_parse_active_nsids_json"}
    nodes = [n for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name in wanted]
    # 테스트 namespace에는 annotation 이름과 default 정책만 제공한다.
    namespace = {
        "Optional": __import__("typing").Optional,
        "Tuple": __import__("typing").Tuple,
        "NSID_OVERRIDE_POLICY": "configured_only",
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(_SOURCE), "exec"), namespace)
    return namespace


class ResolveNsidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helpers = _load_helpers()
        cls.resolve = staticmethod(helpers["_resolve_nsid"])
        cls.parse_active = staticmethod(helpers["_parse_active_nsids_json"])

    def test_configured_only_normalizes_namespace_override(self):
        self.assertEqual(self.resolve(1, True, 0xFFFFFFFF), (1, True))

    def test_configured_only_normalizes_non_namespace_override(self):
        self.assertEqual(self.resolve(7, False, 2), (0, True))

    def test_configured_only_keeps_matching_value(self):
        self.assertEqual(self.resolve(3, True, 3), (3, False))
        self.assertEqual(self.resolve(3, False, 0), (0, False))

    def test_configured_only_uses_default_without_override(self):
        self.assertEqual(self.resolve(5, True, None), (5, False))
        self.assertEqual(self.resolve(5, False, None), (0, False))

    def test_fuzz_preserves_override(self):
        self.assertEqual(self.resolve(1, True, 0xFFFFFFFF, "fuzz"),
                         (0xFFFFFFFF, False))
        self.assertEqual(self.resolve(1, False, 2, "fuzz"), (2, False))

    def test_active_only_preserves_any_active_namespace(self):
        active = (1, 2, 5)
        self.assertEqual(self.resolve(1, True, 2, "active_only", active), (2, False))
        self.assertEqual(self.resolve(1, True, 5, "active_only", active), (5, False))

    def test_active_only_filters_inactive_namespace(self):
        self.assertEqual(
            self.resolve(2, True, 0xFFFFFFFF, "active_only", (1, 2, 5)),
            (2, True),
        )

    def test_active_only_uses_first_active_when_configured_is_stale(self):
        self.assertEqual(self.resolve(9, True, None, "active_only", (2, 5)),
                         (2, False))

    def test_active_only_controller_scope_is_zero(self):
        self.assertEqual(self.resolve(1, False, 2, "active_only", (1, 2)),
                         (0, True))

    def test_list_ns_json_integer_shape(self):
        self.assertEqual(self.parse_active({"nsid_list": [5, 1, 2, 2]}), (1, 2, 5))

    def test_list_ns_json_object_shape_and_boundaries(self):
        obj = {"namespaces": [{"nsid": "0x2"}, {"nsid": 5},
                              {"nsid": 0}, {"nsid": 0xFFFFFFFF}]}
        self.assertEqual(self.parse_active(obj), (2, 5))


if __name__ == "__main__":
    unittest.main()
