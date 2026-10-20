"""v11.4 응답 시그니처 커버리지 — 디버거 없이(--no-jlink) 쓰는 피드백.

처음 보는 (명령, 완료 status[, latency 구간, DW0 모양, 직전 명령]) 응답이면 새 펌웨어 경로로 보고 corpus 에
넣는다. 실제 NVMeFuzzer(no_jlink → NullSampler)의 회계 경로(_account_command)와 실제 송신 경로를 태운다.
"""
import tempfile
import unittest
from unittest.mock import Mock, patch

from fuzzer_target import fuzzer as v


def make(no_jlink=True):
    d = tempfile.TemporaryDirectory()
    config = v.FuzzConfig(no_jlink=no_jlink, rag_enabled=False, state_enabled=False,
                          output_dir=d.name, vmon_enabled=False)
    with patch.object(v.NVMeFuzzer, '_load_static_analysis'), \
            patch.object(v.NVMeFuzzer, '_load_riscv_coverage'):
        f = v.NVMeFuzzer(config)
    f._d = d
    f._ledger_write = Mock()
    f.sampler.evaluate_coverage = Mock(return_value=(False, 0))
    return f


def run(f, status, ms=1.0, dw0=None, cmd='Read', cdw11=0):
    seed = v.Seed(data=b'', cmd=v._NAME_TO_CMD[cmd])
    seed.cdw11 = cdw11
    f._last_nvme_status, f._last_resp_ms, f._last_resp_dw0 = status, ms, dw0
    f._last_wire = {'opcode': seed.cmd.opcode, 'queue': 'io', 'nsid': 1, 'xfer_len': 0}
    n = len(f.corpus)
    rc = 1 if status is None else (0 if status == 0 else (status & 0xff))
    res = f._account_command(seed, b'', rc, 0)
    return res[0], len(f.corpus) - n, f._ledger_write.call_args


class Config(unittest.TestCase):
    def test_defaults(self):
        c = v._parse_response_coverage({})
        self.assertEqual((c['enabled'], c['dims'], c['max_keys']), ('auto', ('latency', 'dw0'), 4096))

    def test_shipped_json_parses(self):
        import json
        cfg = json.loads((v.Path(v.__file__).parent / 'fuzzer_config.json').read_text(encoding='utf-8'))
        self.assertEqual(v._parse_response_coverage(cfg['strategy']['response_coverage'])['enabled'], 'auto')

    def test_bad_values_fail_loudly(self):
        for bad in ({'enabled': 'yes'}, {'dims': ['pc']}, {'dims': 'latency'},
                    {'latency_edges_ms': [16, 4]}, {'latency_edges_ms': []}, {'latency_edges_ms': [0, 4]},
                    {'max_keys': 0}, {'max_keys': True}, [1]):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                v._parse_response_coverage(bad)


class NoJlinkFeedback(unittest.TestCase):
    def setUp(self):
        self.f = make()
        self.addCleanup(self.f._d.cleanup)

    def test_null_sampler_does_not_collect_coverage(self):
        self.assertFalse(self.f.sampler.COLLECTS_COVERAGE)
        self.assertTrue(v.OpenOCDPCSampler.COLLECTS_COVERAGE)
        self.assertTrue(v.RiscvPcsrSampler.COLLECTS_COVERAGE)
        self.assertTrue(self.f._resp_cov_feedback())

    def test_new_signature_enters_corpus_and_repeat_does_not(self):
        f = self.f
        run(f, 0x4002)                                   # SC-depth 1 첫 도달 — depth 전진으로도 들어간다
        it, added, led = run(f, 0x4002, ms=1.5)          # 같은 status·같은 구간 → 새 아님
        self.assertEqual((it, added), (False, 0))
        it, added, led = run(f, 0x4002, ms=300.0)        # 같은 status, 다른 latency 구간 → 새 시그니처
        self.assertEqual((it, added), (True, 1))
        self.assertTrue(led.args[0]['sig_new'])
        self.assertEqual(led.args[0]['new_pcs'], 0)

    def test_status_alone_beyond_depth_is_new(self):
        f = self.f
        run(f, 0x0002)                                   # depth 1
        it, added, _ = run(f, 0x400b)                    # 같은 depth 1, 다른 status → depth 는 못 잡는다
        self.assertEqual((it, added), (True, 1))
        self.assertFalse(f._last_depth_adv)

    def test_dw0_shapes(self):
        f = self.f
        run(f, 0, dw0=None, cmd='GetFeatures')
        for dw0, cdw11, new in ((0, 0, True), (0, 0, False), (7, 7, True), (0x1234, 0, True), (0x99, 0, True),
                                (0x88, 0, False)):
            with self.subTest(dw0=dw0):
                self.assertEqual(run(f, 0, dw0=dw0, cmd='GetFeatures', cdw11=cdw11)[0], new)

    def test_log_label_and_no_pc_totals(self):
        f = self.f
        run(f, 0x0002)
        with self.assertLogs('pcfuzz', level='INFO') as logs:
            run(f, 0x0002, ms=2000.0)
        text = '\n'.join(logs.output)
        self.assertIn('[+][Resp-Cov] cmd=Read', text)
        self.assertIn('sig=Read 0x0002 lat≥1024ms dw0=-', text)
        self.assertNotIn('total_PC', text)
        self.assertNotIn('New coverage!', text)

    def test_max_keys_caps_signatures(self):
        f = self.f
        with patch.dict(v.RESPONSE_COVERAGE, max_keys=len(f._resp_seen) + 1):
            run(f, 0x0002)                               # 마지막 1칸
            with self.assertLogs('pcfuzz', level='WARNING') as logs:
                it, added, _ = run(f, 0x0002, ms=500.0)
            self.assertEqual((it, added), (False, 0))
            self.assertIn('max_keys', '\n'.join(logs.output))

    def test_prev_dim_separates_paths(self):
        f = self.f
        with patch.dict(v.RESPONSE_COVERAGE, dims=('prev',)):
            run(f, 0, cmd='Write')
            run(f, 0, cmd='Read')                        # prev=Write/3
            run(f, 0, cmd='Read')                        # prev=Read/3 — 다른 경로
            self.assertFalse(run(f, 0, cmd='Read')[0])   # 같은 prev 반복은 새 아님
            self.assertIn(('Read', 0, ('Write', 3)), f._resp_seen)
            self.assertIn(('Read', 0, ('Read', 3)), f._resp_seen)

    def test_errno_and_timeout_make_no_signature(self):
        f = self.f
        before = len(f._resp_seen)
        run(f, None)                                     # 장치 미도달(errno)
        self.assertEqual(len(f._resp_seen), before)

    def test_stats_line_shows_signatures_not_pcs(self):
        f = self.f
        run(f, 0x0002)
        stats = {'executions': 5, 'corpus_size': 1, 'coverage_unique_pcs': 0}
        with self.assertLogs('pcfuzz', level='WARNING') as logs:
            f._print_status(stats, 0, 0.0)
        line = next(l for l in logs.output if '[Stats]' in l)
        self.assertIn('resp_sig: ', line)
        self.assertNotIn('pcs: ', line)


class WithCoverageSampler(unittest.TestCase):
    def setUp(self):
        self.f = make()
        self.addCleanup(self.f._d.cleanup)
        self.f.sampler.COLLECTS_COVERAGE = True          # J-Link 샘플러처럼

    def test_auto_records_but_does_not_feed_back(self):
        f = self.f
        self.assertFalse(f._resp_cov_feedback())
        run(f, 0x0002)
        it, added, led = run(f, 0x0002, ms=500.0)
        self.assertEqual((it, added), (False, 0))
        self.assertTrue(led.args[0]['sig_new'], 'ledger 에는 남아야 한다')

    def test_enabled_true_feeds_back_even_with_coverage(self):
        f = self.f
        with patch.dict(v.RESPONSE_COVERAGE, enabled=True):
            run(f, 0x0002)
            self.assertTrue(run(f, 0x0002, ms=500.0)[0])

    def test_enabled_false_never_feeds_back(self):
        f = self.f
        f.sampler.COLLECTS_COVERAGE = False
        with patch.dict(v.RESPONSE_COVERAGE, enabled=False):
            run(f, 0x0002)
            self.assertFalse(run(f, 0x0002, ms=500.0)[0])


class SendPathCapturesResponse(unittest.TestCase):
    """실제 _send_nvme_command 가 latency·DW0 를 남긴다(nvme-cli 'NVMe command result' 파싱)."""
    import test_v11_exceptions as _i
    setUp = _i.RealTransportIntegration.setUp
    send = _i.RealTransportIntegration.send

    def prep(self, rc, out=b'', err=b''):
        self.f._exception_controller = None
        self.f._exception_on_spawn = None
        self.proc.returncode = rc
        self.proc.communicate.return_value = (out, err)

    def test_dw0_from_stderr_or_stdout(self):
        for out, err, want in ((b'', b'NVMe command result:00000005\n', 5),
                               (b'NVMe command result:0000abcd\n00: 00 01', b'', 0xabcd),
                               (b'', b'', None)):
            with self.subTest(out=out, err=err):
                self.prep(0, out, err)
                self.assertEqual(self.send(), 0)
                self.assertEqual(self.f._last_resp_dw0, want)
                self.assertIsNotNone(self.f._last_resp_ms)

    def test_error_completion_has_no_dw0(self):
        self.prep(2, err=b'NVMe status: INVALID_FIELD: A reserved coded value (0x4002)\n')
        self.send()
        self.assertIsNone(self.f._last_resp_dw0)
        self.assertEqual(self.f._last_nvme_status, 0x4002)


if __name__ == '__main__':
    unittest.main()
