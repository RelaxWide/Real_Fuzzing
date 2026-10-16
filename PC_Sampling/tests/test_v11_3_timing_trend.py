"""tools/timing_trend.py — 퍼저가 실제로 찍는 [Timing] 줄(진짜 _timing_line)을 읽어 초반·후반을 가른다."""
import sys
import unittest
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace as NS

from fuzzer_target import fuzzer as v

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import timing_trend   # noqa: E402


def timing_line(n, send_ms, by_cmd, setup_ms=10.0, read_ms=10.0, stop_ms=2.0, rest_ms=5.0, spawn_ms=None):
    """진짜 _timing_line 으로 한 창의 줄을 만든다."""
    o = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
    ses = NS(t_setup=0.0, t_read=0.0, setup_aborted=0)
    o.sampler = NS(session=ses)
    o._pm_detach_stats = None
    o._bg = True
    o._bg_win = defaultdict(float)
    o._bg_tally = defaultdict(int)
    prev = o._timing_snapshot()
    if spawn_ms is not None:
        v._SPAWN_STAT['n'] += n
        v._SPAWN_STAT['s'] += spawn_ms * n / 1000
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

    def test_spawn_share_of_send_growth(self):
        s, text = self.run_log((100, 20.0, {'Read': (20.0, 100)}, 15.0, 10.0, 2.0, 5.0, 2.0),
                               (100, 67.0, {'Read': (67.0, 100)}, 35.0, 35.0, 2.0, 5.0, 50.0))
        self.assertAlmostEqual(s['phase']['early']['spawn'], 2.0, places=1)
        self.assertAlmostEqual(s['phase']['late']['spawn'], 50.0, places=1)
        self.assertIsNotNone(s['phase']['late']['rss'])
        self.assertIn('퍼저 메모리 증가로 nvme-cli 생성이 느려진 것', text)
        self.assertIn('nvme-cli 프로세스 생성(호스트', text)
        self.assertNotIn('장치·환경 쪽', text)

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


class SpawnHook(unittest.TestCase):
    def test_send_path_brackets_popen_with_hook_events(self):
        """_send_nvme_command 가 Popen 바로 앞뒤에 before_popen·spawned 를 낸다 — 생성 시간이 그 사이다."""
        import ast
        from fuzzer_target import FUZZER_FILE
        src = FUZZER_FILE.read_text(encoding='utf-8')
        fn = next(n for c in ast.parse(src).body if isinstance(c, ast.ClassDef) and c.name == '_V101Fuzzer'
                  for n in c.body if isinstance(n, ast.FunctionDef) and n.name == '_send_nvme_command')
        seg = ast.get_source_segment(src, fn)
        a, b, c = seg.index("'nvme.before_popen'"), seg.index('subprocess.Popen('), seg.index("'nvme.spawned'")
        self.assertLess(a, b)
        self.assertLess(b, c)

    def test_hook_accumulates(self):
        n0, s0 = v._SPAWN_STAT['n'], v._SPAWN_STAT['s']
        v._freeze_emit('nvme.before_popen', argv=['nvme'])
        v._freeze_emit('nvme.spawned', child_pid=1)
        v._freeze_emit('nvme.spawned', child_pid=1)      # 짝 없는 spawned 는 세지 않는다
        self.assertEqual(v._SPAWN_STAT['n'], n0 + 1)
        self.assertGreaterEqual(v._SPAWN_STAT['s'], s0)

    def test_rss_readable(self):
        self.assertGreater(v._self_rss_mb(), 1)
