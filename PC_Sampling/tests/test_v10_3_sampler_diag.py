"""v10.3 샘플러 진단 계측 시험. 실제 OpenOCD/JTAG 없이 돈다.

계측이 **관측 대상을 망가뜨리지 않는 것**이 가장 중요한 성질이다 — 이 프로젝트는
진단 도구가 스스로 버그가 된 사례를 두 번 겪었다(faulthandler, 커널 debug 옵션).
그래서 '기록이 남는가' 만큼 '무슨 일이 있어도 읽기 경로를 안 깬다' 를 함께 본다.
"""
import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_v10_2_learning import ROOT, fuzzer      # noqa: F401

sys.path.insert(0, str(ROOT))


def sampler():
    """OpenOCDPCSampler 를 __init__ 없이. 시험 하네스가 흔히 쓰는 형태다."""
    return fuzzer.OpenOCDPCSampler.__new__(fuzzer.OpenOCDPCSampler)


def method_ast(name, cls='OpenOCDPCSampler'):
    """해당 **클래스 안의** 메서드 AST. 샘플러마다 동명 메서드가 있어 모듈 전체를
    walk 하면 기반 클래스의 no-op 을 집는다."""
    tree = ast.parse((ROOT / 'pc_sampling_fuzzer_v10.3.py').read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls)
    return next(n for n in node.body
                if isinstance(n, ast.FunctionDef) and n.name == name)


class OpenOcdOutputIsNotAnUndrainedPipe(unittest.TestCase):
    """아무도 읽지 않는 PIPE 는 64 KiB 에서 OpenOCD 를 write 에 블록시킨다."""

    def test_launch_uses_no_pipe_for_stdout_or_stderr(self):
        fn = method_ast('_launch_openocd')
        popen = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                 and getattr(n.func, 'attr', '') == 'Popen']
        self.assertEqual(len(popen), 1, 'Popen 호출을 찾지 못했다')
        kw = {k.arg: ast.dump(k.value) for k in popen[0].keywords}
        for stream in ('stdout', 'stderr'):
            self.assertIn(stream, kw)
            self.assertNotIn("attr='PIPE'", kw[stream],
                             f'{stream} 가 아직 PIPE 다 — 64KiB 에서 OpenOCD 가 블록된다')

    def test_log_file_is_unbuffered_append(self):
        with tempfile.TemporaryDirectory() as d:
            obj = sampler()
            obj.config = Mock(output_dir=d)
            fh = obj._ocd_log_open()
            self.assertIsNotNone(fh, 'OpenOCD 로그 파일을 못 열었다')
            fh.write(b'Error: something\n')
            self.assertIn('Error: something', obj._ocd_log_tail(5)[0])
            obj._ocd_log_close()

    def test_log_open_failure_falls_back_without_raising(self):
        obj = sampler()
        obj.config = Mock(output_dir='/proc/nonexistent/nope')
        self.assertIsNone(obj._ocd_log_open())       # DEVNULL 로 진행


class ReadFailureRecordsTheDapState(unittest.TestCase):
    """지금까지는 실패 원인이 적힌 레지스터를 읽지도 않고 지워 왔다."""

    def obj(self, d):
        o = sampler()
        o.config = Mock(output_dir=d)
        o._tcl_prefix = 'r8'
        o._sock = object()
        o._telnet_cmd = Mock(side_effect=['0x6ba02477', '0xf0000040'])
        return o

    def test_dpidr_and_ctrlstat_are_read_and_written_to_disk(self):
        with tempfile.TemporaryDirectory() as d:
            o = self.obj(d)
            o._diag_on_read_failure('err-payload')
            regs = [c.args[0] for c in o._telnet_cmd.call_args_list]
            self.assertEqual(regs, ['r8.dap dpreg 0', 'r8.dap dpreg 4'],
                             'DPIDR/CTRL-STAT 을 안 읽었다')
            text = (Path(d) / 'sampler_diag' / 'sampler_events.log').read_text()
            self.assertIn('0x6ba02477', text)
            self.assertIn('0xf0000040', text)
            self.assertIn('err-payload', text)

    def test_it_is_throttled(self):
        with tempfile.TemporaryDirectory() as d:
            o = self.obj(d)
            o._telnet_cmd = Mock(return_value='0x0')
            for _ in range(50):
                o._diag_on_read_failure('x')
            # 1회차만 찍고 이후는 200회마다 — 50회 동안 2회를 넘으면 안 된다
            self.assertLessEqual(o._telnet_cmd.call_count, 4,
                                 'PCSR 은 초당 수십 번이라 매번 찍으면 그 자체가 부하다')

    def test_no_socket_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d:
            o = self.obj(d)
            o._sock = None
            o._diag_on_read_failure('x')
            self.assertIn('소켓 없음',
                          (Path(d) / 'sampler_diag' / 'sampler_events.log').read_text())


class DiagnosticsNeverBreakTheReadPath(unittest.TestCase):
    """계측이 관측 대상을 깨면 안 된다 — 이 프로젝트의 반복된 실패 방식이다."""

    def test_missing_attributes_do_not_raise(self):
        o = sampler()                       # 아무 필드도 없는 상태
        o.config = Mock(output_dir='/proc/nonexistent')
        o._tcl_prefix = 'r8'
        o._diag_on_read_failure('x')        # 예외 없이 지나가야 한다

    def test_telnet_explosion_does_not_raise(self):
        with tempfile.TemporaryDirectory() as d:
            o = sampler()
            o.config = Mock(output_dir=d)
            o._tcl_prefix = 'r8'
            o._sock = object()
            o._telnet_cmd = Mock(side_effect=RuntimeError('link dead'))
            o._diag_on_read_failure('x')    # 예외가 새어 나오면 실패

    def test_read_all_pcs_failure_paths_call_the_diagnostic(self):
        fn = method_ast('_read_all_pcs')
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                 and getattr(n.func, 'attr', '') == '_diag_on_read_failure']
        self.assertGreaterEqual(len(calls), 3,
                                '실패 분기 세 곳(프레임/ERR/파싱) 모두에 걸려 있어야 한다')


class RestartLadderVariesSpeed(unittest.TestCase):
    """같은 설정으로 3번 반복해 봐야 링크가 열화됐으면 3번 다 실패한다."""

    def test_config_declares_a_descending_speed_ladder(self):
        speeds = fuzzer.RECONNECT_SPEEDS_KHZ
        self.assertGreaterEqual(len(speeds), 2, '변주가 없다')
        given = [x for x in speeds if x]
        self.assertEqual(given, sorted(given, reverse=True), '속도가 내려가야 한다')

    def test_launch_accepts_and_applies_speed(self):
        fn = method_ast('_launch_openocd')
        self.assertIn('speed_khz', [a.arg for a in fn.args.args])
        self.assertIn('adapter speed', ast.dump(fn))

    def test_reconnect_picks_a_different_speed_per_attempt(self):
        fn = method_ast('_reconnect')
        body = ast.dump(fn)
        self.assertIn('RECONNECT_SPEEDS_KHZ', body)
        self.assertIn('speed_khz', body)


class CumulativeContextIsRecorded(unittest.TestCase):
    def test_context_reports_uptime_reads_and_recovery_counts(self):
        o = sampler()
        o._session_started = 0.0
        o._total_reads = 19086072
        o._reinit_count = 7
        o._reconnect_count = 2
        o.halt_ok_total = 1
        o.halt_fail_total = 3
        ctx = o._diag_context()
        for token in ('reads=19086072', 'reinit=7', 'reconnect=2'):
            self.assertIn(token, ctx)

    def test_context_works_on_a_bare_object(self):
        self.assertIn('reads=0', sampler()._diag_context())


class ResourceTrendIsSampled(unittest.TestCase):
    def test_sample_reports_this_process(self):
        o = sampler()
        o._proc = None
        line = o._res_sample()
        self.assertIn('fuzzer=rss', line, f'자기 프로세스 RSS 를 못 읽었다: {line}')
        self.assertIn('ocd=-', line)

    def test_monitor_thread_starts_and_stops(self):
        import time as _t
        with tempfile.TemporaryDirectory() as d:
            o = sampler()
            o.config = Mock(output_dir=d)
            o._proc = None
            o._res_thread = None
            o._res_stop = fuzzer.threading.Event()
            o._res_monitor_start(interval=0.05)
            _t.sleep(0.2)
            o._res_monitor_stop()
            text = (Path(d) / 'sampler_diag' / 'sampler_events.log').read_text()
            self.assertIn('[res]', text)

    def test_config_ships_the_knobs(self):
        g = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8'))['globals']
        self.assertTrue(g['sampler_diag']['resource_monitor'])
        self.assertEqual(g['reconnect_speeds_khz'], [None, 1000, 500])


if __name__ == '__main__':
    unittest.main()
