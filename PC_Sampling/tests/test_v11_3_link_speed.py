"""v11.3 — BM9K1 cJTAG 속도를 제품 프로필 jlink_speed 로 정하고, 준비(pin) 실패 판정 로그에 원인 단서를 남긴다.

예전엔 PcsrSession 이 Link 를 기본 속도(sfe76_link.SPEED_KHZ=10MHz)로만 열어 프로필의 jlink_speed 가 무시됐다.
신호 마진이 작은 프로브는 10MHz 에서 준비 단계(검증이 엄격한 수십 회 AP 접근)가 간헐 실패한다.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

from fuzzer_target import fuzzer as v
import riscv_cov

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'risc-v'))
import sfe76_link  # noqa: E402


class _StopOpen(Exception):
    pass


class _FakeLink:
    made = []

    def __init__(self, **kw):
        self.kw = kw
        self.speed = kw.get('speed')
        _FakeLink.made.append(self)

    def open(self, tap_script=False):
        raise _StopOpen()           # 속도만 확인하고 하드웨어 단계 전에 멈춘다

    def close(self):
        pass


class SessionSpeed(unittest.TestCase):
    def open_with(self, speed):
        _FakeLink.made = []
        s = riscv_cov.PcsrSession(cores={}, verbose=False, speed_khz=speed)
        with mock.patch.object(sfe76_link, 'Link', _FakeLink):
            self.assertFalse(s.open())
        return [m.kw['speed'] for m in _FakeLink.made]

    def test_configured_speed_is_used(self):
        self.assertEqual(self.open_with(4000), [4000])

    def test_default_is_module_speed(self):
        for sp in (None, 0):
            self.assertEqual(self.open_with(sp), [sfe76_link.SPEED_KHZ])


class SamplerPassesProfileSpeed(unittest.TestCase):
    def make(self, cfg):
        o = v.RiscvPcsrSampler.__new__(v.RiscvPcsrSampler)
        o._cores, o.config, o.session = {}, cfg, None
        seen = {}
        new = riscv_cov.PcsrSession(cores={})
        new.open = lambda: True

        def factory(**k):
            seen.update(k)
            return new
        o._rc = type('R', (), {'PcsrSession': staticmethod(factory)})
        self.assertTrue(o._open_session({}))
        return seen

    def test_jlink_speed_reaches_session(self):
        cfg = type('C', (), {'jlink_vtref_mv': None, 'jlink_speed': 2000})()
        self.assertEqual(self.make(cfg)['speed_khz'], 2000)

    def test_missing_jlink_speed_means_default(self):
        cfg = type('C', (), {'jlink_vtref_mv': None})()
        self.assertIsNone(self.make(cfg)['speed_khz'])

    def test_old_riscv_cov_fails_with_clear_log(self):
        o = v.RiscvPcsrSampler.__new__(v.RiscvPcsrSampler)
        o._cores, o.session = {}, None
        o.config = type('C', (), {'jlink_vtref_mv': None, 'jlink_speed': 10000})()

        class OldSession:                       # speed_khz 이전 서명
            def __init__(self, cores, power="both", tap_script=False, auth_wrapper=None,
                         verbose=True, auth_timeout=60.0, word_order=None, vtref_mv=None):
                pass
        o._rc = type('R', (), {'PcsrSession': OldSession, '__file__': '/x/riscv_cov.py'})
        with self.assertLogs(v.log, 'ERROR') as cm:
            self.assertFalse(o._open_session({}))
        self.assertIn("riscv_cov.py 가 이 퍼저와 버전이 다르다", '\n'.join(cm.output))
        self.assertIsNone(o.session)

    def test_riscv_fallback_is_10mhz_not_arm_4000(self):
        src = Path(v.__file__).read_text(encoding='utf-8')
        self.assertIn("jlink_speed=_profile.get('jlink_speed', 10000 if _profile.get('arch') == 'riscv' else 4000)", src)

    def test_bm9k1_profile_keeps_10mhz(self):
        import json
        prof = json.loads((Path(v.__file__).parent / 'fuzzer_config.json').read_text(encoding='utf-8'))
        self.assertEqual(prof['products']['BM9K1']['jlink_speed'], 10000)


class _FakeDap:
    def __init__(self, why=None, stat="CTRL/STAT=0xF0000000 DBGACK 에러비트 없음", boom=False):
        self.last = {'why': why} if why else {}
        self._stat, self._boom = stat, boom

    def sticky(self):
        if self._boom:
            raise RuntimeError("usb gone")
        return self._stat


class LinkDiag(unittest.TestCase):
    def test_reports_last_reason_and_ctrl_stat(self):
        s = riscv_cov.PcsrSession(cores={})
        s.dap = _FakeDap(why="TAR 불일치 쓴값=0x00001040 읽은값=0x00001000")
        d = s.link_diag()
        self.assertIn("TAR 불일치", d)
        self.assertIn("CTRL/STAT=0xF0000000", d)

    def test_no_session(self):
        self.assertEqual(riscv_cov.PcsrSession(cores={}).link_diag(), "세션 없음")

    def test_ctrl_stat_exception_is_contained(self):
        s = riscv_cov.PcsrSession(cores={})
        s.dap = _FakeDap(boom=True)
        self.assertIn("CTRL/STAT 예외", s.link_diag())


class SetupFailLog(unittest.TestCase):
    def make(self, session):
        o = v.RiscvPcsrSampler.__new__(v.RiscvPcsrSampler)
        o.session = session
        o._empty_streak = o._EMPTY_BURST_LIMIT - 1
        o._stopped_reason = None
        o.openocd_error = mock.Mock()
        return o

    def test_limit_log_carries_diag(self):
        s = riscv_cov.PcsrSession(cores={})
        s.dap = _FakeDap(why="TAR 불일치 쓴값=0x1 읽은값=0x0")
        o = self.make(s)
        with self.assertLogs(v.log, 'ERROR') as cm:
            self.assertTrue(o._setup_failed(0))
        out = '\n'.join(cm.output)
        self.assertIn("준비 실패(pin/bank 읽기) 8회 연속", out)
        self.assertIn("TAR 불일치", out)
        o.openocd_error.set.assert_called_once()

    def test_diag_failure_does_not_block_fault(self):
        o = self.make(mock.Mock(link_diag=mock.Mock(side_effect=RuntimeError("x"))))
        with self.assertLogs(v.log, 'ERROR') as cm:
            self.assertTrue(o._setup_failed(0))
        self.assertIn("진단 실패", '\n'.join(cm.output))
        self.assertEqual(o._stopped_reason, 'pin_fail')


if __name__ == '__main__':
    unittest.main()
