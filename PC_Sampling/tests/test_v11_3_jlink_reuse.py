"""v11.3 — pylink.JLink 를 연결마다 새로 만들지 않는다(프로세스당 1개).

pylink 는 DLL 경로에서 버전을 못 읽으면 JLink() 마다 J-Link DLL 을 임시 파일로 복사해 새로 올리고 Linux 에선
내리지 않는다. 재연결·PM 분리·POR 복구마다 새로 만들면 DLL 사본이 쌓여 BM9K1 캠페인이 link_fail_por 복구 중
OOM kill 됐다(2026-10-17, anon-rss 30GB). 마지막 시험은 pylink 의 실제 Library 로 그 누적 자체를 재현한다.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest import mock

from fuzzer_target import fuzzer as v

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'risc-v'))
import sfe76_link  # noqa: E402


class FakeJLink:
    made = 0

    def __init__(self, **kw):
        FakeJLink.made += 1
        self.refs = 0
        self.closes = 0
        self.product_name, self.serial_number = 'J-Link', 1

    def opened(self):
        return self.refs > 0

    def open(self, serial_no=None):
        self.refs += 1           # pylink 처럼: 이미 열려 있으면 참조 수만 오른다

    def close(self):
        if self.refs:
            self.refs -= 1
            self.closes += 1

    def exec_command(self, cmd):
        return 0

    def halted(self):
        return False


class LinkReuse(unittest.TestCase):
    def setUp(self):
        FakeJLink.made = 0
        p = [mock.patch.object(sfe76_link, '_SHARED_JL', None, create=True),
             mock.patch.object(sfe76_link, '_SHARED_OWNER', None, create=True),
             mock.patch.object(sfe76_link, 'JLINK_CREATED', 0, create=True),
             mock.patch.object(sfe76_link.pylink, 'JLink', FakeJLink),
             mock.patch.object(sfe76_link, 'apply_vtref', lambda *a, **k: None),
             mock.patch.object(sfe76_link.time, 'sleep')]
        for x in p:
            x.start()
            self.addCleanup(x.stop)

    def link(self):
        return sfe76_link.Link(verbose=False)

    def test_reconnects_create_one_jlink(self):
        for _ in range(50):
            lk = self.link()
            lk.open(tap_script=False)
            lk.close()
        self.assertEqual(FakeJLink.made, 1)
        self.assertEqual(sfe76_link.JLINK_CREATED, 1)
        self.assertFalse(sfe76_link._SHARED_JL.opened())

    def test_stale_owner_close_leaves_new_session_open(self):
        old = self.link()
        old.open(tap_script=False)
        new = self.link()                        # old 를 닫지 않고 새 세션을 연다
        new.open(tap_script=False)
        jl = sfe76_link._SHARED_JL
        self.assertEqual(jl.refs, 1)             # 낡은 연결을 닫고 새로 열었다(참조 수 2 가 아니다)
        old.close()                              # 늦게 온 이전 세션의 close
        self.assertTrue(jl.opened())             # 새 세션 연결은 그대로
        new.close()
        self.assertFalse(jl.opened())

    def test_same_owner_reopen_does_not_stack_refcount(self):
        lk = self.link()
        lk.open(tap_script=False)
        lk.open(tap_script=False)
        self.assertEqual(sfe76_link._SHARED_JL.refs, 1)


class JLinkHaltReuse(unittest.TestCase):
    def test_arm_reconnects_create_one_jlink(self):
        made = []

        def factory(**kw):
            jl = mock.MagicMock()
            jl.opened.return_value = False
            made.append(jl)
            return jl
        cfg = v.FuzzConfig(sampler_type='jlink_halt')
        s = v.JLinkHaltSampler(cfg)
        fake = NS(JLink=factory, enums=NS(JLinkInterfaces=NS(JTAG=0, SWD=1)))
        with mock.patch.object(v, '_pylink', fake), mock.patch.object(v, '_PYLINK_SHARED', None, create=True), \
                mock.patch.object(s, '_read_all_pcs', return_value=(1,)), self.assertLogs(v.log, 'INFO'):
            for _ in range(20):
                self.assertTrue(s.connect())
        self.assertEqual(len(made), 1)


class FuzzerLogsJLinkCount(unittest.TestCase):
    def test_session_ok_line_reports_jlink_objects_and_rss(self):
        cfg = v.FuzzConfig(sampler_type='riscv_pcsr', riscv={'sample_plan': {'weights': {'0': 1}, 'seed': 1},
                                                             'cores': [{'id': 0}]})
        s = v.RiscvPcsrSampler(cfg)
        s._init_overlay_probe = lambda: None
        s.session = NS(pin=lambda cid: True, auth_count=1, auth_ms=0.0)
        with mock.patch.object(s, '_verify_ranges', return_value=[]), \
                mock.patch.dict(sys.modules, sfe76_link=NS(JLINK_CREATED=1)), self.assertLogs(v.log, 'WARNING') as cm:
            self.assertTrue(s._connect_verify())
        self.assertRegex('\n'.join(cm.output), r'J-Link 객체 1개 · RSS \d+MB')

    def test_old_link_module_is_called_out(self):
        cfg = v.FuzzConfig(sampler_type='riscv_pcsr', riscv={'sample_plan': {'weights': {'0': 1}, 'seed': 1},
                                                             'cores': [{'id': 0}]})
        s = v.RiscvPcsrSampler(cfg)
        s._init_overlay_probe = lambda: None
        s.session = NS(pin=lambda cid: True, auth_count=1, auth_ms=0.0)
        with mock.patch.object(s, '_verify_ranges', return_value=[]), \
                mock.patch.dict(sys.modules, sfe76_link=NS()), self.assertLogs(v.log, 'WARNING') as cm:
            s._connect_verify()
        self.assertIn('구버전 sfe76_link.py', '\n'.join(cm.output))


@unittest.skipUnless(shutil.which('gcc'), 'gcc 없음')
class PylinkCopiesDllPerInstance(unittest.TestCase):
    """원인 재현: 버전 없는 경로의 DLL 은 Library 마다 사본이 올라가 내려가지 않는다(가짜 DLL)."""
    def test_mechanism(self):
        import pylink.library as L
        with tempfile.TemporaryDirectory() as d:
            src, so = Path(d) / 'f.c', Path(d) / 'libjlinkarm.so'
            src.write_text('int JLINKARM_Probe(void){return 1;}\n')
            subprocess.run(['gcc', '-shared', '-fPIC', '-o', str(so), str(src)], check=True)

            def copies():
                with open('/proc/self/maps') as fh:
                    return sum(1 for ln in fh if '(deleted)' in ln and 'r-xp' in ln)
            base = copies()
            libs = [L.Library(dllpath=str(so)) for _ in range(3)]
            for lib in libs:
                lib.unload()                 # pylink 가 하는 정리 — 임시 파일만 지우고 DLL 은 남는다
            self.assertGreaterEqual(copies() - base, 3)


if __name__ == '__main__':
    unittest.main()
