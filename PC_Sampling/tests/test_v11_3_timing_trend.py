"""tools/timing_trend.py — 퍼저가 실제로 찍는 [Timing] 줄(진짜 _timing_line)을 읽어 초반·후반을 가른다."""
import sys
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace as NS

from fuzzer_target import fuzzer as v

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import timing_trend   # noqa: E402


def timing_line(n, send_ms, by_cmd, setup_ms=10.0, read_ms=10.0, stop_ms=2.0, rest_ms=5.0):
    """진짜 _timing_line 으로 한 창의 줄을 만든다."""
    o = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
    ses = NS(t_setup=0.0, t_read=0.0, setup_aborted=0)
    o.sampler = NS(session=ses)
    o._pm_detach_stats = None
    o._bg = True
    o._bg_win = defaultdict(float)
    o._bg_tally = defaultdict(int)
    prev = o._timing_snapshot()
    ses.t_setup, ses.t_read = setup_ms * n / 1000, read_ms * n / 1000
    per = (send_ms + stop_ms + rest_ms) / 1000
    o._tm = dict(n=n, send=send_ms * n / 1000, stop=stop_ms * n / 1000, loop=per * n, nloop=n, last=None,
                 prev=prev, by_cmd={k: [c, ms * c / 1000] for k, (ms, c) in by_cmd.items()})
    return '2026-10-16 12:00:00 WARNING ' + o._timing_line()


class TimingTrend(unittest.TestCase):
    def run_log(self, early, late):
        lines = [timing_line(*early) for _ in range(5)] + [timing_line(*late) for _ in range(5)]
        rows = timing_trend.parse(lines)
        self.assertEqual(len(rows), 10)
        return timing_trend.summarize(rows, 0.2), timing_trend.report(timing_trend.summarize(rows, 0.2))

    def test_same_commands_slower(self):
        s, text = self.run_log((100, 20.0, {'Write': (25.0, 50), 'Read': (15.0, 50)}, 15.0, 10.0),
                               (100, 67.0, {'Write': (80.0, 50), 'Read': (50.0, 50)}, 35.0, 35.0))
        self.assertAlmostEqual(s['phase']['early']['send'], 20.0, places=1)
        self.assertAlmostEqual(s['phase']['late']['send'], 67.0, places=1)
        self.assertAlmostEqual(s['cmds']['Write']['late'][0] / s['cmds']['Write']['early'][0], 3.2, places=2)
        self.assertIn('장치·환경 쪽', text)
        self.assertEqual(s['phase']['late']['exec'], (900, 1000))

    def test_mix_change(self):
        _, text = self.run_log((100, 20.0, {'Read': (15.0, 90), 'Write': (60.0, 10)}),
                               (100, 67.0, {'Read': (15.0, 10), 'Write': (60.0, 90)}))
        self.assertIn('명령 구성', text)

    def test_busy_ratio(self):
        s, text = self.run_log((100, 20.0, {'Read': (20.0, 100)}, 15.0, 10.0),
                               (100, 67.0, {'Read': (67.0, 100)}, 35.0, 35.0))
        self.assertAlmostEqual(s['phase']['early']['busy'], 25 / 27, places=2)
        self.assertIn('SBA 트래픽 세기는 비슷', text)

    def test_cli(self):
        import tempfile
        with tempfile.NamedTemporaryFile('w', suffix='.log', delete=False, encoding='utf-8') as fh:
            fh.write('\n'.join(timing_line(10, 5.0, {'Read': (5.0, 10)}) for _ in range(3)) + '\n')
        self.addCleanup(Path(fh.name).unlink)
        from io import StringIO
        from contextlib import redirect_stdout
        buf = StringIO()
        with redirect_stdout(buf):
            self.assertEqual(timing_trend.main([fh.name]), 0)
        self.assertIn('명령별 전송 평균', buf.getvalue())


if __name__ == '__main__':
    unittest.main()
