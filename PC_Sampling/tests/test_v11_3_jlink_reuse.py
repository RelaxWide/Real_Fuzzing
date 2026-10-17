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

_REAL_JLINK = sfe76_link.pylink.JLink     # 시험이 pylink.JLink 를 바꿔 끼우기 전의 실제 클래스


class FakeJLink:
    """pylink.JLink 의 열림 규칙을 그대로 흉내 낸다: DLL 상태(opened)와 객체 참조 수(_open_refcount)가 따로다."""
    made = 0

    def __init__(self, **kw):
        FakeJLink.made += 1
        self._open_refcount = 0
        self.dll_open = False
        self.closes = 0
        self._dll = NS(JLINKARM_Close=self._dll_close)
        self.product_name, self.serial_number = 'J-Link', 1

    @property
    def refs(self):
        return self._open_refcount

    def _dll_close(self):
        self.dll_open = False

    def opened(self):
        return self.dll_open

    def open(self, serial_no=None):
        if self._open_refcount > 0:      # pylink: 이미 열려 있으면 DLL 을 열지 않고 참조 수만 올린다
            self._open_refcount += 1
            return
        self.dll_open, self._open_refcount = True, 1

    def close(self):
        if self._open_refcount == 0:     # pylink: 참조 수 0 이면 아무것도 안 한다
            return
        self._open_refcount -= 1
        if self._open_refcount == 0:
            self.dll_open = False
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
            jl._open_refcount = 0
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
        self.assertRegex('\n'.join(cm.output), r'J-Link 객체 1개 · DLL 매핑 \d+ · 스레드 \d+ · RSS \d+MB')

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


FAKE_DLL_C = r"""
#include <string.h>
static int is_open, open_calls, close_calls;
void* JLINKARM_OpenEx(void*a, void*b){ is_open = 1; open_calls++; return 0; }
int  JLINKARM_IsOpen(void){ return is_open; }
void JLINKARM_Close(void){ is_open = 0; close_calls++; }
int  JLINKARM_SelectUSB(int i){ return 0; }
int  JLINKARM_EMU_SelectByUSBSN(int sn){ return 0; }
int  JLINKARM_ExecCommand(const char*c, char*e, int n){ if (e && n) e[0] = 0; return 0; }
void JLINKARM_EMU_GetProductName(char*b, int n){ strncpy(b, "J-Link", n); }
int  JLINKARM_GetSN(void){ return 1; }
const char* JLINKARM_GetCompileDateTime(void){ return "x"; }
const char* JLINKARM_GetRegisterName(int i){ return "x"; }
void JLINKARM_SetErrorOutHandler(void*f){}
void JLINKARM_SetWarnOutHandler(void*f){}
void JLINKARM_SetLogHandler(void*f){}
void JLINKARM_SetDetailedLogHandler(void*f){}
void JLINK_SetHookUnsecureDialog(void*f){}
int  JLINKARM_EMU_IsConnected(void){ return 1; }
int  JLINKARM_EnableLogCom(void){ return 0; }
int  JLINKARM_EnableLog(void){ return 0; }
void FAKE_DropOpen(void){ is_open = 0; }        /* 장애 모의: DLL 쪽만 닫힘(참조 수는 남음) */
int  FAKE_OpenCalls(void){ return open_calls; }
int  FAKE_CloseCalls(void){ return close_calls; }
"""


@unittest.skipUnless(shutil.which('gcc'), 'gcc 없음')
class RealPylinkFaultStates(unittest.TestCase):
    """실제 pylink.JLink + 가짜 DLL — opened()(DLL)와 _open_refcount(객체)가 어긋난 장애 상태."""
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        src, cls.so = Path(cls.tmp.name) / 'f.c', Path(cls.tmp.name) / 'libjlinkarm.so'
        src.write_text(FAKE_DLL_C)
        subprocess.run(['gcc', '-shared', '-fPIC', '-o', str(cls.so), str(src)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        import pylink.library as L
        self.made = []

        def make(**kw):
            jl = _REAL_JLINK(lib=L.Library(dllpath=str(self.so), use_tmpcpy=False), **kw)
            self.made.append(jl)
            return jl
        p = [mock.patch.object(sfe76_link, '_SHARED_JL', None), mock.patch.object(sfe76_link, '_SHARED_OWNER', None),
             mock.patch.object(sfe76_link, 'JLINK_CREATED', 0), mock.patch.object(sfe76_link.pylink, 'JLink', make),
             mock.patch.object(sfe76_link, 'apply_vtref', lambda *a, **k: None),
             mock.patch.object(sfe76_link.time, 'sleep')]
        for x in p:
            x.start()
            self.addCleanup(x.stop)

    def dll(self):
        return self.made[0]._dll

    def test_refcount_left_without_dll_open_still_reopens(self):
        lk = sfe76_link.Link(verbose=False)
        lk.open(tap_script=False)
        self.dll().FAKE_DropOpen()               # DLL 은 닫혔는데 객체 참조 수는 1
        self.assertFalse(self.made[0].opened())
        for k in range(3):
            n = self.dll().FAKE_OpenCalls()
            lk2 = sfe76_link.Link(verbose=False)
            lk2.open(tap_script=False)
            self.assertEqual(self.dll().FAKE_OpenCalls(), n + 1, k)   # 참조 수만 오르지 않고 실제로 연다
            self.assertTrue(self.made[0].opened())
            self.assertEqual(self.made[0]._open_refcount, 1)
            self.dll().FAKE_DropOpen()
        self.assertEqual(len(self.made), 1)

    def test_dll_open_with_zero_refcount_is_closed_first(self):
        lk = sfe76_link.Link(verbose=False)
        lk.open(tap_script=False)
        self.made[0]._open_refcount = 0          # 객체는 닫힘, DLL 은 열림
        c = self.dll().FAKE_CloseCalls()
        sfe76_link.Link(verbose=False).open(tap_script=False)
        self.assertGreater(self.dll().FAKE_CloseCalls(), c)

    def test_close_failure_is_not_reused(self):
        lk = sfe76_link.Link(verbose=False)
        lk.open(tap_script=False)
        with mock.patch.object(self.made[0], 'close', side_effect=RuntimeError('usb')):
            said = []
            jl = sfe76_link._acquire_jlink(object(), said.append)
        self.assertIsNot(jl, self.made[0])                 # 정리 실패한 객체를 그대로 넘기지 않는다
        self.assertEqual(sfe76_link.JLINK_CREATED, 2)
        self.assertIn('새 J-Link 객체로 교체', said[0])

    def test_stale_session_close_does_not_touch_new_owner(self):
        import riscv_cov
        old = riscv_cov.PcsrSession(cores={}, verbose=False)
        old.lk = sfe76_link.Link(verbose=False)
        old.lk.open(tap_script=False)
        old.dap, old._pinned, old._ap, old._cb = mock.MagicMock(), 0, 1, 2
        old._sj = mock.MagicMock()
        new = sfe76_link.Link(verbose=False)
        new.open(tap_script=False)                         # 새 세션이 공유 J-Link 를 가져감
        c = self.dll().FAKE_CloseCalls()
        old.close()
        old._sj.sba_unpin.assert_not_called()               # 낡은 세션의 SBA 접근 없음
        self.assertEqual(self.dll().FAKE_CloseCalls(), c)  # 새 세션 연결도 닫지 않음
        self.assertTrue(self.made[0].opened())
        self.assertIsNone(old.lk)
        new.close()
        self.assertFalse(self.made[0].opened())

    def test_owner_session_close_still_unpins(self):
        import riscv_cov
        s = riscv_cov.PcsrSession(cores={}, verbose=False)
        s.lk = sfe76_link.Link(verbose=False)
        s.lk.open(tap_script=False)
        s.dap, s._pinned, s._ap, s._cb = mock.MagicMock(), 0, 1, 2
        s._sj = mock.MagicMock()
        s.close()
        s._sj.sba_unpin.assert_called_once()
        self.assertFalse(self.made[0].opened())

    def test_arm_stuck_refcount_reopens(self):
        import pylink.library as L
        made = []

        def make(**kw):
            jl = _REAL_JLINK(lib=L.Library(dllpath=str(self.so), use_tmpcpy=False))
            made.append(jl)
            return jl
        with mock.patch.object(v, '_PYLINK_SHARED', None), \
                mock.patch.object(v, '_pylink', NS(JLink=make)):
            jl = v._shared_pylink()
            jl.open()
            jl._dll.FAKE_DropOpen()
            n = jl._dll.FAKE_OpenCalls()
            self.assertIs(v._shared_pylink(), jl)
            jl.open()
            self.assertEqual(jl._dll.FAKE_OpenCalls(), n + 1)
        self.assertEqual(len(made), 1)


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
            base, logged = copies(), v._proc_link_stats()[0]
            libs = [L.Library(dllpath=str(so)) for _ in range(3)]
            for lib in libs:
                lib.unload()                 # pylink 가 하는 정리 — 임시 파일만 지우고 DLL 은 남는다
            self.assertGreaterEqual(copies() - base, 3)
            self.assertGreaterEqual(v._proc_link_stats()[0] - logged, 3)   # 세션 OK 로그의 'DLL 매핑' 이 누적을 보인다


if __name__ == '__main__':
    unittest.main()
