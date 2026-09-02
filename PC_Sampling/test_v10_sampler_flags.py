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
import unittest
from pathlib import Path

SRC = Path(__file__).parent / "pc_sampling_fuzzer_v10.0.py"
FLAGS = ("INVASIVE", "REPORTS_HALT_STATS", "USES_JLINK_USB",
         "RECONNECT_ON_FW_COMMIT", "SUPPORTS_CONCURRENT_SAMPLING", "LINK_LABEL")
SAMPLERS = ("NullSampler", "OpenOCDPCSampler", "OpenOCDHaltSampler", "JLinkHaltSampler")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
