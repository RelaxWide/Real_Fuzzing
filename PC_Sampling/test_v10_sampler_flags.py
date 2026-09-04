#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v10 샘플러 capability 플래그 계약 테스트.

왜 정적(ast) 검사인가: 퍼저 본체는 import 시 config 로드·로깅 설정 등 부작용이 크고
파일명에 점이 있어 일반 import 가 안 된다. 플래그는 **클래스 속성 리터럴**이라
소스 파싱만으로 정확히 검증된다.

이 테스트가 막는 실제 사고:
  OpenOCDPCSampler 는 NullSampler 를 **상속하지 않는다**(별개 클래스). 플래그를
  NullSampler 에만 선언하면 PM9M1/BM9H1(운영 제품)이 self.sampler.REPORTS_HALT_STATS
  첫 접근에서 AttributeError 로 즉사한다. 실제로 개발 중 발생했다.

실행: python3 -m unittest -v test_v10_sampler_flags
"""
import ast
import json
import unittest
from pathlib import Path

SRC = Path(__file__).parent / "pc_sampling_fuzzer_v10.0.py"
FLAGS = ("INVASIVE", "REPORTS_HALT_STATS", "USES_JLINK_USB",
         "RECONNECT_ON_FW_COMMIT", "SUPPORTS_CONCURRENT_SAMPLING", "LINK_LABEL")
SAMPLERS = ("NullSampler", "OpenOCDPCSampler", "OpenOCDHaltSampler",
            "JLinkHaltSampler", "RiscvPcsrSampler")

# v9.8 이 실제로 하던 동작. 이 표에서 벗어나면 기존 제품(PM9M1/BM9H1/P7/P9) 회귀다.
EXPECTED = {
    "NullSampler":        dict(INVASIVE=False, REPORTS_HALT_STATS=False, USES_JLINK_USB=False,
                               RECONNECT_ON_FW_COMMIT=False, SUPPORTS_CONCURRENT_SAMPLING=False,
                               LINK_LABEL="[OpenOCD]"),
    "OpenOCDPCSampler":   dict(INVASIVE=False, REPORTS_HALT_STATS=False, USES_JLINK_USB=False,
                               RECONNECT_ON_FW_COMMIT=False, SUPPORTS_CONCURRENT_SAMPLING=True,
                               LINK_LABEL="[OpenOCD]"),
    "OpenOCDHaltSampler": dict(INVASIVE=True,  REPORTS_HALT_STATS=False, USES_JLINK_USB=False,
                               RECONNECT_ON_FW_COMMIT=False, SUPPORTS_CONCURRENT_SAMPLING=False,
                               LINK_LABEL="[OpenOCD]"),
    "JLinkHaltSampler":   dict(INVASIVE=True,  REPORTS_HALT_STATS=True,  USES_JLINK_USB=True,
                               RECONNECT_ON_FW_COMMIT=True, SUPPORTS_CONCURRENT_SAMPLING=False,
                               LINK_LABEL="[J-Link]"),
    # BM9K1 — 비침습이라 INVASIVE=False 가 핵심. True 면 펌웨어시간 워치독이 붙어
    # 실제 hang 을 정상으로 오인한다.
    "RiscvPcsrSampler":   dict(INVASIVE=False, REPORTS_HALT_STATS=False, USES_JLINK_USB=True,
                               RECONNECT_ON_FW_COMMIT=True, SUPPORTS_CONCURRENT_SAMPLING=True,
                               LINK_LABEL="[SJTAG/cJTAG]"),
}


def _classes():
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ClassDef) and n.name in SAMPLERS:
            vals = {}
            for st in n.body:
                if isinstance(st, ast.Assign):
                    for t in st.targets:
                        if isinstance(t, ast.Name) and t.id in FLAGS:
                            vals[t.id] = ast.literal_eval(st.value)
            out[n.name] = (vals, [b.id for b in n.bases if isinstance(b, ast.Name)])
    return out


def _effective(name, cls):
    """MRO 를 따라 실제로 해석되는 값(상속 반영)."""
    v = {}
    for b in cls[name][1]:
        if b in cls:
            v.update(_effective(b, cls))
    v.update(cls[name][0])
    return v


class TestFlagContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cls = _classes()

    def test_all_samplers_present(self):
        self.assertEqual(set(self.cls), set(SAMPLERS))

    def test_every_flag_resolvable(self):
        """★ 상속으로도 해결 안 되는 플래그가 있으면 런타임 AttributeError 로 죽는다."""
        for name in SAMPLERS:
            eff = _effective(name, self.cls)
            missing = [f for f in FLAGS if f not in eff]
            self.assertEqual(missing, [], f"{name} 에서 해결 불가: {missing}")

    def test_values_match_v98_behaviour(self):
        """플래그 값이 v9.8 동작을 그대로 재현해야 한다(기존 제품 회귀 방지)."""
        for name, want in EXPECTED.items():
            eff = _effective(name, self.cls)
            for f, v in want.items():
                self.assertEqual(eff[f], v, f"{name}.{f}: 기대={v} 실제={eff[f]}")

    def test_openocd_pc_sampler_declares_own_flags(self):
        """NullSampler 를 상속하지 않으므로 직접 선언해야 한다(과거 실제 버그)."""
        own, bases = self.cls["OpenOCDPCSampler"]
        self.assertNotIn("NullSampler", bases)
        self.assertEqual(set(own), set(FLAGS),
                         "OpenOCDPCSampler 는 6개 플래그를 모두 직접 선언해야 한다")


class TestNoIsinstanceGates(unittest.TestCase):
    """동작을 가르는 게이트가 플래그로 옮겨졌는지. (표시용 분기는 대상 아님)

    assertNotIn 에 소스 전체를 넣지 않는다 — 실패 시 800KB 를 덤프해 읽을 수 없다."""

    @classmethod
    def setUpClass(cls):
        cls.src = SRC.read_text(encoding="utf-8")

    def test_no_isinstance_sampler_checks(self):
        """halt 전용 동작이 isinstance 로 묶여 있으면 새 샘플러가 조용히 잘못 동작한다."""
        n = self.src.count("isinstance(self.sampler, JLinkHaltSampler)")
        self.assertEqual(n, 0, f"isinstance 게이트가 {n}곳 남아 있다")

    def test_behavioural_gates_use_flags(self):
        """동작 분기는 플래그로. 배너 등 **표시용** sampler_type 비교는 남아도 된다."""
        for pat in ("_is_halt = self.config.sampler_type in ('halt', 'jlink_halt')",
                    "_pf_sample = (self.config.sampler_type == 'pcsr')"):
            self.assertEqual(self.src.count(pat), 0, f"동작 분기가 남아 있다: {pat}")
        # _is_halt 는 2곳. v9.8 에서는 이 둘이 **서로 다르게** 판정했다
        #   (한쪽은 isinstance(JLinkHalt), 다른 쪽은 sampler_type in ('halt','jlink_halt'))
        #   → OpenOCDHaltSampler 에서 결과가 엇갈렸다. 같은 플래그로 통일해 해소.
        self.assertEqual(self.src.count("_is_halt = self.sampler.INVASIVE"), 2,
                         "_is_halt 판정 2곳이 모두 INVASIVE 로 통일돼야 한다")
        self.assertEqual(
            self.src.count("_pf_sample = self.sampler.SUPPORTS_CONCURRENT_SAMPLING"), 1,
            "prefill 동시샘플링 분기가 플래그 기반이어야 한다")


class TestRiscvWiring(unittest.TestCase):
    """BM9K1 배선 — 기존 제품 경로를 건드리지 않았는지 포함."""

    @classmethod
    def setUpClass(cls):
        cls.src = SRC.read_text(encoding="utf-8")

    def test_dispatch_branch_exists(self):
        self.assertIn("elif config.sampler_type == 'riscv_pcsr':", self.src)
        self.assertIn("self.sampler = RiscvPcsrSampler(config)", self.src)

    def test_per_core_coverage_branch_is_first(self):
        """per-core 분기가 **기존 분기 앞**이어야 기존 경로가 그대로 남는다."""
        a = self.src.index("getattr(self.sampler, 'PER_CORE_COVERAGE', False)")
        b = self.src.index("elif self._sa_loaded and self._sa_bb_starts:")
        self.assertLess(a, b)

    def test_owns_burst_worker(self):
        """공용 worker 를 고치지 않고 자기 worker 를 갖는다(기존 제품 보호)."""
        i = self.src.index("class RiscvPcsrSampler")
        self.assertIn("def _sampling_worker(self):", self.src[i:i + 12000])

    def test_secrets_not_in_product_config(self):
        """ELF 경로·te_base 등 기밀은 fuzzer_config.json 이 아니라 sjtag_addrs.json 에."""
        cfg = json.loads((SRC.parent / "fuzzer_config.json").read_text(encoding="utf-8"))
        rv = cfg["products"]["BM9K1"]["riscv"]
        self.assertNotIn("cores", rv, "코어/ELF 경로는 config 에 두지 않는다")
        self.assertEqual(cfg["products"]["BM9K1"]["interface"], "cjtag")
        self.assertEqual(cfg["products"]["BM9K1"]["sampler_type"], "riscv_pcsr")


class TestWorkerWindowReset(unittest.TestCase):
    """★ RISC-V worker 가 윈도우마다 누적 필드를 초기화하는지.

    공용 worker 를 override 하면서 이 초기화를 빠뜨리면 _last_raw_pcs/_observations/
    current_trace 가 **영원히 누적**된다. 메모리가 실행 수에 비례해 늘고,
    _account_command 가 매 실행마다 _last_raw_pcs 전체를 재필터링해 2차로 느려진다.
    수천 exec 뒤에야 드러나 놓치기 쉬우므로 소스 수준에서 고정한다.
    (실기서 5000 exec 부근에 호스트가 내려간 실제 원인)"""

    RESET_FIELDS = ("current_trace", "_last_raw_pcs", "_out_of_range_count",
                    "_last_new_at", "_unique_at_intervals", "_stopped_reason")

    @classmethod
    def setUpClass(cls):
        src = SRC.read_text(encoding="utf-8")
        i = src.index("class RiscvPcsrSampler")
        j = src.index("def _track_collapse", i)
        w = src.index("def _sampling_worker(self):", i)
        cls.worker = src[w:j]

    def test_resets_all_accumulators(self):
        for f in self.RESET_FIELDS:
            self.assertIn(f"self.{f} =", self.worker,
                          f"worker 가 self.{f} 를 초기화하지 않는다 — 무한 누적")

    def test_resets_observations(self):
        self.assertIn("_reset_window_extra()", self.worker,
                      "_observations 를 비우지 않으면 account() 가 매번 전체를 재처리한다")

    def test_respects_sample_limit(self):
        """한 윈도우의 샘플 수가 max_samples_per_run 으로 묶여야 한다."""
        self.assertIn("max_samples_per_run", self.worker)


class TestNoPerExecScans(unittest.TestCase):
    """매 실행 경로에 O(커버리지) 스캔이 들어가면 캠페인이 진행될수록 느려지다 멈춘
    것처럼 보인다. 실기서 실제로 겪은 지점."""

    @classmethod
    def setUpClass(cls):
        cls.src = SRC.read_text(encoding="utf-8")

    def test_cov_totals_defaults_to_cheap(self):
        """기본은 by_core=False — len() 만 쓰므로 O(1)."""
        self.assertIn("def _cov_totals(self, by_core=False):", self.src)

    def test_by_core_only_at_periodic_sites(self):
        """by_core=True 는 주기 통계/성장곡선(100 exec 마다)에서만."""
        self.assertEqual(self.src.count("_cov_totals(by_core=True)"), 2)

    def test_riscv_owns_diagnose(self):
        """공용 diagnose 는 샘플마다 _read_all_pcs() → 우리 구현은 매번 4코어 재핀이라
        수백 초가 걸린다. 버스트 기반 override 가 있어야 한다."""
        i = self.src.index("class RiscvPcsrSampler")
        j = self.src.index("class ", i + 10) if "class " in self.src[i + 10:] else len(self.src)
        self.assertIn("def diagnose(self", self.src[i:j])


class TestWorkerCannotSpin(unittest.TestCase):
    """★ 진행 없는 루프 금지. burst 가 빈 리스트를 계속 반환하면(pin 실패) total 이
    안 늘어 while 조건이 영원히 참 → 로그 없이 스레드가 돌며 세션 lock 을 물어
    전체가 멈춘 것처럼 보인다(실기서 실제 발생)."""

    @classmethod
    def setUpClass(cls):
        src = SRC.read_text(encoding="utf-8")
        i = src.index("class RiscvPcsrSampler")
        w = src.index("def _sampling_worker(self):", i)
        cls.worker = src[w:src.index("def _track_collapse", w)]

    def test_empty_burst_has_exit(self):
        self.assertIn("_EMPTY_BURST_LIMIT", self.worker,
                      "빈 버스트 연속 시 탈출 조건이 있어야 한다")

    def test_no_bare_continue_without_counter(self):
        """continue 만 하고 카운터가 없으면 진행 없이 도는 구조가 된다."""
        self.assertIn("empty += 1", self.worker)

    def test_exit_uses_normal_path(self):
        """return 으로 빠지면 total_samples 누적 등 마무리가 건너뛰어진다."""
        self.assertNotIn("            return\n", self.worker)
        self.assertIn("bail = True", self.worker)


class TestInterestingIsGated(unittest.TestCase):
    """★ corpus 가 실행 수만큼 자라면(1000 exec 에 corpus 1000) 커버리지 가이드가
    사실상 없는 것이다. 배경 코드(idle 루프·인터럽트·타 코어 housekeeping)가 매 윈도우
    새 블록을 내놓기 때문 — 두 장치로 막는다."""

    @classmethod
    def setUpClass(cls):
        cls.src = SRC.read_text(encoding="utf-8")
        cls.cfg = json.loads((SRC.parent / "fuzzer_config.json").read_text(encoding="utf-8"))

    def test_credit_cores_is_passed(self):
        """account() 에 credit_cores 를 넘겨야 배경 코어의 신규가 표를 못 던진다."""
        self.assertIn("credit_cores=(self.sampler.credit_cores()", self.src)

    def test_sampler_exposes_credit_cores(self):
        i = self.src.index("class RiscvPcsrSampler")
        self.assertIn("def credit_cores(self)", self.src[i:i + 20000])

    def test_idle_coverage_preseeded(self):
        """diagnose 로 모은 배경 커버리지를 미리 반영해야 '새 커버리지'로 안 잡힌다."""
        self.assertIn("self.cov.update(self.sampler._idle_obs)", self.src)

    def test_config_sets_primary_policy(self):
        rv = self.cfg["products"]["BM9K1"]["riscv"]
        self.assertEqual(rv["interesting_policy"], "primary")
        self.assertIn("primary_core", rv["sample_plan"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
