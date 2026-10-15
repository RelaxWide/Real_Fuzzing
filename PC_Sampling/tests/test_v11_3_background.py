"""v11.3 — BM9K1 상시 백그라운드 샘플링(opt-in).

docs/V11_3_BACKGROUND_SAMPLING_PLAN.md §4.2 의 시험 번호를 각 시험 docstring 에 적는다.
장치·J-Link 접근 없음. 샘플러 워커 시험은 진짜 PcsrSession.burst_timed 와 진짜 워커를 돌리고 DAP 읽기만 가짜로 둔다.
퍼저 쪽 시험은 진짜 생성자로 만든 NVMeFuzzer 의 진짜 _account_command 를 쓴다.
"""
import json
import sys
import tempfile
import threading
import time
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

from fuzzer_target import fuzzer as v
import riscv_cov   # noqa: E402 — fuzzer_target 이 경로를 잡은 뒤

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import compare_runs   # noqa: E402

Observation = riscv_cov.Observation


def ob(pc, core=0, valid=True):
    return Observation(core, pc if valid else None, True, valid, 0)


class Clock:
    """호출마다 1 씩 증가하는 가짜 시계 — 읽기 전후 시각을 정확히 예측할 수 있다."""
    def __init__(self, t=100.0):
        self.t = t

    def __call__(self):
        self.t += 1.0
        return self.t


def fake_session(reads, sj_extra=None):
    """reads: 순서대로 돌려줄 raw 값(None = 읽기 실패) 리스트. 진짜 pin/_pin 경로를 탄다."""
    s = riscv_cov.PcsrSession(cores={})
    it = iter(reads)
    s.addr_writes = []

    def read_pinned(_dap):
        return next(it)

    def retarget(dap, ap, cb, addr, abort=None):
        s.addr_writes.append(addr)
        return True

    def pin(dap, ap, cb, addr):
        s.addr_writes.append(addr)
        return True
    sj = NS(sba_read_pinned=read_pinned, sba_retarget=retarget, sba_pin=pin,
            sba_unpin=lambda *a: True, RISCV_ADDRS={})
    for k, val in (sj_extra or {}).items():
        setattr(sj, k, val)
    s._sj = sj
    s.dap = object()
    s._pcsr_addr = lambda core: 0x1000 + core
    return s


# ═════════════════════════════════════════════════════════════════════════════
# 1. 포착 구간 (riscv_cov.PcsrSession.burst_timed)
# ═════════════════════════════════════════════════════════════════════════════
class CaptureSpans(unittest.TestCase):
    def test_address_write_starts_the_trigger_and_each_read_starts_the_next(self):
        """시험 6·11: 첫 값은 [pin 직전, 첫 읽기 직후], 다음 값은 [직전 읽기 직전, 이 읽기 직후]."""
        s, clk = fake_session([3, 5, 7]), Clock()
        obs, spans = s.burst_timed(0, 3, clock=clk)
        # 시계: 101 pin 전, 102 pin 후, 103/104 읽기1, 105/106 읽기2, 107/108 읽기3, 109 끝
        self.assertEqual(spans, [(101.0, 104.0), (103.0, 106.0), (105.0, 108.0)])
        self.assertEqual([o.pc for o in obs], [2, 4, 6])
        self.assertEqual(s.addr_writes, [0x1000])

    def test_same_core_burst_inherits_last_trigger_not_burst_start(self):
        """시험 20: 같은 코어 연속 burst — 주소를 다시 쓰지 않으므로 첫 값은 이전 burst 마지막 읽기가 시작한 것."""
        s, clk = fake_session([3, 5, 7, 9]), Clock()
        s.burst_timed(0, 2, clock=clk)          # 101 pin, 102, 103/104, 105/106, 107
        obs, spans = s.burst_timed(0, 2, clock=clk)
        # 두 번째 burst: 108 pin 전(즉시 반환), 109, 110/111 읽기, 112/113 읽기
        self.assertEqual(s.addr_writes, [0x1000], '같은 코어는 주소를 다시 쓰지 않는다')
        self.assertEqual(spans[0], (105.0, 111.0), '이전 burst 마지막 읽기 직전부터')
        self.assertNotEqual(spans[0][0], 108.0, 'burst 시작 시각을 새 트리거로 쓰면 오귀속')

    def test_core_switch_rewrites_address_and_resets_trigger(self):
        s, clk = fake_session([3, 5, 7, 9]), Clock()
        s.burst_timed(0, 2, clock=clk)
        obs, spans = s.burst_timed(1, 1, clock=clk)
        self.assertEqual(s.addr_writes, [0x1000, 0x1001])
        self.assertEqual(spans[0], (108.0, 111.0))

    def test_unknown_history_excludes_first_sample(self):
        """이어받을 기록이 없다(다른 경로가 핀해 둔 세션) → 첫 값은 알 수 없음(0)."""
        s, clk = fake_session([3, 5]), Clock()
        s._pinned = 0                            # 다른 경로가 이미 핀했다 — 트리거 기록 없음
        obs, spans = s.burst_timed(0, 2, clock=clk)
        self.assertEqual(spans[0][0], riscv_cov.PcsrSession._UNKNOWN_TRIGGER)
        self.assertEqual(spans[1][0], 103.0)

    def test_failed_read_does_not_move_the_trigger(self):
        """읽기 실패는 새 read 를 시작했는지 모른다 → 다음 값의 시작은 마지막 성공 읽기 직전."""
        s, clk = fake_session([3, None, 7]), Clock()
        obs, spans = s.burst_timed(0, 3, clock=clk)
        self.assertEqual(spans[2], (103.0, 108.0))
        self.assertFalse(obs[1].valid)

    def test_existing_burst_is_unchanged(self):
        """기존 burst() 는 손대지 않았다 — v11.2 와 같은 결과."""
        s = fake_session([3, 5])
        obs = s.burst(0, 2)
        self.assertEqual([o.pc for o in obs], [2, 4])
        self.assertIsNone(s._trig)


# ═════════════════════════════════════════════════════════════════════════════
# 퍼저 하네스
# ═════════════════════════════════════════════════════════════════════════════
class AliveThread:
    def is_alive(self):
        return True

    def join(self, timeout=None):
        return None


def coverage_model():
    cov = riscv_cov.CoverageModel()
    cm = riscv_cov.CoreMap(0, 'H')
    cm.bb_starts = [0x100 * i for i in range(1, 400)]
    cm.bb_ends = [0x100 * i + 0x80 for i in range(1, 400)]
    cov.cores[0] = cm
    cov.loaded = True
    return cov


def make_fuzzer(bg=True, **opts):
    tmp = tempfile.TemporaryDirectory()
    config = v.FuzzConfig(no_jlink=True, rag_enabled=False, state_enabled=False,
                          output_dir=tmp.name, vmon_enabled=False)
    with patch.object(v.NVMeFuzzer, '_load_static_analysis'), \
            patch.object(v.NVMeFuzzer, '_load_riscv_coverage'):
        f = v.NVMeFuzzer(config)
    scfg = v.FuzzConfig(sampler_type='riscv_pcsr', output_dir=tmp.name,
                        riscv={'sample_plan': {'weights': {'0': 1}, 'seed': 1, 'jitter_pct': 0}})
    o = dict(v._BG_DEFAULTS, max_lag_sec=1e6, flush_timeout_sec=0.2)
    o.update(opts)
    s = v.RiscvBgSampler(scfg, o)
    s._ranges = {0: range(0, 1 << 24)}
    s._bg_thread = AliveThread()              # 돌고 있는 워커(처리 경계는 시험이 공개하는 묶음으로만 간다)
    f.sampler = s
    f.cov = s.cov = coverage_model()
    f._bg = bg
    f._bg_opts = s.bg_opts
    f._ledger_write = Mock()
    f.learning.options['preserve_setup'] = False
    f._tmp = tmp
    return f


def publish(f, samples=(), processed=None, invalid=(), kind='accept'):
    """워커가 내는 묶음 하나를 흉내 낸다. samples: (t_lo, t_hi, pc[, fresh])."""
    out = []
    for x in samples:
        a, b, pc = x[:3]
        o = ob(pc)
        if len(x) > 3:
            o = o._replace(fresh=x[3])
        out.append((a, b, o))
    f.sampler._bg_out.append({'gen': 0, 'kind': kind, 'invalid': list(invalid), 'processed': processed,
                              'samples': out})


def seed(i, name='Write'):
    return v.Seed(data=bytes([i % 256]) * 4, cmd=v._NAME_TO_CMD[name], cdw10=i)


def bb(i):
    return 0x100 * i + 0x10


def set_send_state(f, i, status=0, submitted=True, parent=None):
    """전송 직후 값 — 명령마다 다르게 둔다(지연 회계가 다른 명령 값을 읽으면 드러나게)."""
    f._last_nvme_status = status
    f._last_cmd_submitted = submitted
    f._last_wire = {'opcode': 1, 'queue': 'io', 'nsid': 1, 'xfer_len': i}
    f._current_mutations = [i % 3]
    f._credit_seed = parent
    f._learning_last_send = None
    f._learning_window_valid = True


def outcome(f):
    return dict(
        corpus=[(s.cmd.name, s.cdw10, s.new_pcs, sorted(s.covered_pcs)) for s in f.corpus],
        executions=f.executions,
        mopt_finds=list(f.mopt_finds), mopt_uses=list(f.mopt_uses),
        rc=sorted((k, dict(c)) for k, c in f.rc_stats.items()),
        cov=sorted(f.cov.covered_bbs),
        csfuzz=list(f._csfuzz_c1_rewards),
        ledger=[(c.args[0]['exec'], c.args[0]['new_pcs'], c.args[0]['sc']) for c in f._ledger_write.call_args_list],
        learning=[(r['command'], r['status'], r['new_coverage']) for r in f.learning.recent],
    )


# 명령 i 가 밟는 BB — 일부는 앞 명령과 겹치고 일부는 새것
PLAN = [[bb(i), bb(i + 1)] if i % 4 else [bb(1)] for i in range(1, 31)]
STATUS = [0 if i % 5 else 0x0002 for i in range(1, 31)]


def run_immediate(f, parents):
    for i, pcs in enumerate(PLAN, 1):
        set_send_state(f, i, status=STATUS[i - 1], parent=parents[i % 2])
        f.sampler.bg_fill_window([ob(pc) for pc in pcs])
        f._account_command(seed(i), seed(i).data, 0, 0, source='c1')


def run_deferred(f, parents, lag_every=3, mutate_after_enqueue=False):
    base = time.monotonic()
    for i, pcs in enumerate(PLAN, 1):
        t0, t1 = base + i, base + i + 0.5
        set_send_state(f, i, status=STATUS[i - 1], parent=parents[i % 2])
        # 이 명령 구간 안에서 포착된 샘플 — 공개는 하되 처리 경계는 lag_every 명령마다만 민다
        publish(f, [(t0 + 0.1 + k * 0.01, t0 + 0.2 + k * 0.01, pc) for k, pc in enumerate(pcs)],
                processed=(t1 if i % lag_every == 0 else None))
        f._bg_main_window = (t0, t1)
        r = f._account_command(seed(i), seed(i).data, 0, 0, source='c1')
        assert r == (False, 0, 'ok'), r
        if mutate_after_enqueue:
            # 다음 명령이 같은 객체를 고치는 상황 — 스냅샷이 복사가 아니면 이 명령 회계가 바뀐다
            f._current_mutations.append(4)
            f._last_wire['xfer_len'] = -1
    publish(f, processed=base + 1000)
    f._bg_drain()


class RecoveryObservation(unittest.TestCase):
    """예외 주입 뒤 복구 관측 창(복구 직후 명령): 측정 → 증거 기록 → 커버리지 보상 제외. 창 방식과 같은 순서."""

    def setUp(self):
        self.f = make_fuzzer()
        self.addCleanup(self.f._tmp.cleanup)
        self.f._exception_controller = Mock()
        self.f._seq_sink = None

    def send(self, i, recovery):
        f = self.f
        base = time.monotonic()
        f.sampler._bg_open_t0 = base - 1.0
        set_send_state(f, i)
        f._exception_interrupted = False
        f._exception_window_truncated = recovery
        f._exception_recovery_window = recovery
        publish(f, [(base - 0.9, base - 0.8, bb(i)), (base - 0.7, base - 0.6, bb(i + 1))],
                processed=base + 100)
        with self.assertLogs(v.log, 'DEBUG'):
            v.log.debug('send')
            _, ok = f._stop_sampling_checked('command:Write')
        self.assertTrue(ok)
        return f._account_command(seed(i), seed(i).data, 0, 0, source='c1')

    def evidence(self):
        return [c.kwargs for c in self.f._exception_controller.emit.call_args_list
                if c.args[0] == 'recovery_observation']

    def test_evidence_has_command_pcs_and_no_reward(self):
        f = self.f
        r = self.send(1, recovery=True)
        self.assertEqual(r, (False, 0, 'continue'))
        ev = self.evidence()
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]['pcs'], [bb(1), bb(2)], '증거는 이 명령 구간의 PC — 회계를 미루면 빈 목록')
        self.assertEqual(f.corpus, [])
        self.assertEqual(sorted(f.cov.covered_bbs), [], '리셋 직후 코드는 보상하지 않는다')
        self.assertEqual(f.stats['coverage_unobserved'], 1)
        self.assertEqual(f._bg_tally['sync'], 1, '같은 구간을 두 번 확정하지 않는다')
        self.assertEqual(f._bg_tally['evidence_samples'], 2)
        self.assertEqual(f._bg_tally['cmd_samples'], 0)
        self.assertEqual(f.sampler.current_trace, set())

    def test_next_command_is_deferred_as_usual(self):
        f = self.f
        self.send(1, recovery=True)
        self.assertEqual(self.send(5, recovery=False), (False, 0, 'ok'))
        self.assertEqual(f._bg_tally['deferred'], 1, '복구 창 다음 명령은 평소처럼 지연 회계 경로')
        f._bg_drain()
        self.assertFalse(f._bg_pending)
        self.assertEqual(sorted(f.cov.covered_bbs), [0x500, 0x600], 'BB 시작 주소')
        self.assertEqual(len(self.evidence()), 1)


class DeferredAccounting(unittest.TestCase):
    def setUp(self):
        self.made = []

    def tearDown(self):
        for f in self.made:
            f._tmp.cleanup()

    def fz(self, **kw):
        f = make_fuzzer(**kw)
        self.made.append(f)
        return f

    def parents(self):
        return [seed(900), seed(901)]

    def test_deferred_accounting_equals_immediate(self):
        """시험 1·17: 처리 경계가 여러 명령 늦게 와도 회계 결과(corpus·MOpt·rc·LLM 학습·ledger·CSFuzz)가 즉시 회계와 같다.
        다음 명령이 같은 리스트·dict 를 고쳐도(스냅샷 불변) 결과가 같다."""
        ref = self.fz(bg=False)
        p_ref = self.parents()
        run_immediate(ref, p_ref)
        for mutate in (False, True):
            got = self.fz(bg=True)
            p_got = self.parents()
            run_deferred(got, p_got, mutate_after_enqueue=mutate)
            self.assertEqual(outcome(got), outcome(ref), f'mutate={mutate}')
            self.assertEqual([p.last_gain_exec for p in p_got], [p.last_gain_exec for p in p_ref])
            self.assertEqual(got._bg_tally['deferred'], len(PLAN))
            self.assertFalse(got._bg_pending)

    def test_commands_wait_until_processed_boundary_passes_their_end(self):
        f = self.fz()
        base = time.monotonic()
        set_send_state(f, 1)
        publish(f, [(base + 1.1, base + 1.2, bb(1))])
        f._bg_main_window = (base + 1, base + 1.5)
        f._account_command(seed(1), b'x', 0, 0)
        self.assertEqual(len(f._bg_pending), 1)
        self.assertEqual(f.corpus, [], '확정 전에는 커버리지 회계를 하지 않는다')
        self.assertEqual(f.executions, 1, '실행 완료 처리는 즉시')
        publish(f, processed=base + 1.5)
        f._bg_drain()
        self.assertEqual(f.executions, 1)
        self.assertEqual(f.corpus[-1].new_pcs, 1)
        self.assertEqual(f.corpus[-1].found_at, 1)

    def test_periodic_work_runs_exactly_once_per_boundary(self):
        """시험 14: 지연 회계가 몰려도·한 번에 여러 명령을 넘어가도 100 경계 작업은 정확히 한 번."""
        f = self.fz()
        f._print_status = Mock()
        f._window_t0, f._window_exec0 = v.datetime.now(), 0
        base = time.monotonic()
        for i in range(1, 206):
            set_send_state(f, i)
            f._bg_main_window = (base + i, base + i + 0.5)
            f._account_command(seed(i), b'x', 0, 0)
            if i in (97, 103, 150, 205):       # 처리 경계가 98→103 처럼 몇 명령씩 건너뛴다
                publish(f, processed=base + i + 0.5)
                f._bg_drain()
        self.assertEqual(f.executions, 205)
        self.assertEqual(f._print_status.call_count, 2)

    def test_sync_command_drains_earlier_pending_first(self):
        """시퀀스 멤버(즉시 판단 필요)는 기다려 확정하되, 앞서 대기 중인 명령을 먼저 회계한다(실행 순서)."""
        f = self.fz()
        base = time.monotonic()
        set_send_state(f, 1)
        publish(f, [(base + 1.1, base + 1.2, bb(1))])
        f._bg_main_window = (base + 1, base + 1.5)
        f._account_command(seed(1), b'a', 0, 0)
        set_send_state(f, 2)
        publish(f, [(base + 2.1, base + 2.2, bb(2))], processed=base + 2.5)
        f._bg_main_window = (base + 2, base + 2.5)
        f._seq_sink = {'commands': [], 'new_pcs': 0, 'covered_pcs': set(), 'interesting': False}
        f._account_command(seed(2), b'b', 0, 0, seq_member=True)
        self.assertEqual([s.cdw10 for s in f.corpus], [1], '대기 명령이 먼저 corpus 에')
        self.assertEqual([s.cdw10 for s in f._seq_sink['commands']], [2])
        self.assertEqual(f._seq_sink['new_pcs'], 1)
        self.assertEqual(f._bg_tally['sync'], 1)

    def test_timeout_is_not_deferred_and_hang_pcs_are_background_only(self):
        """시험 2: timeout 은 기다리지 않고 바로 crash 처리로 간다(지연 회계와 무관). 그 구간 PC 는 백그라운드."""
        f = self.fz()
        base = time.monotonic()
        set_send_state(f, 1, status=None)
        publish(f, [(base + 1.1, base + 1.2, bb(7))], processed=base + 1.5)
        f._bg_main_window = (base + 1, base + 1.5)
        f._handle_timeout_crash = Mock(side_effect=lambda *a: setattr(f, '_timeout_crash', True))
        r = f._account_command(seed(1), b'x', f.RC_TIMEOUT, 0)
        self.assertEqual(r, (False, 0, 'break'))
        f._handle_timeout_crash.assert_called_once()
        self.assertIn(riscv_cov.pack(0, 0, 0x700), f.cov.covered_bbs)
        self.assertNotIn(riscv_cov.pack(0, 0, 0x700), f.cov.judge_bbs)

    def test_straddling_sample_goes_to_background(self):
        """시험 6·11: 이전 호출은 경계 전에 반환됐지만 포착이 경계 뒤일 수 있는 샘플 — 어느 명령에도 안 붙는다."""
        f = self.fz()
        base = time.monotonic()
        # 명령1 [1, 1.5], 명령2 [2, 2.5]. 경계에 걸친 샘플: 트리거 1.4(명령1 안), 회수 2.1(명령2 안)
        set_send_state(f, 1)
        publish(f, [(base + 1.1, base + 1.2, bb(1))])
        f._bg_main_window = (base + 1, base + 1.5)
        f._account_command(seed(1), b'a', 0, 0)
        set_send_state(f, 2)
        publish(f, [(base + 1.4, base + 2.1, bb(9)), (base + 2.1, base + 2.2, bb(2))], processed=base + 2.5)
        f._bg_main_window = (base + 2, base + 2.5)
        f._account_command(seed(2), b'b', 0, 0)
        f._bg_drain()
        self.assertEqual([(s.cdw10, s.new_pcs) for s in f.corpus], [(1, 1), (2, 1)])
        k9 = riscv_cov.pack(0, 0, 0x900)
        self.assertIn(k9, f.cov.covered_bbs, '전체 커버리지에는 들어간다')
        self.assertNotIn(k9, f.cov.judge_bbs)
        self.assertGreaterEqual(f._bg_tally['ambiguous'], 1)

    def test_background_first_bb_still_rewards_the_command_that_reaches_it(self):
        """시험 5·15 (방식 B): 백그라운드가 먼저 본 BB 를 나중에 명령이 밟으면 그 명령의 신규다."""
        f = self.fz()
        base = time.monotonic()
        publish(f, [(base + 0.1, base + 0.2, bb(5))], processed=base + 0.5)   # 명령 사이
        f._bg_drain()
        self.assertIn(riscv_cov.pack(0, 0, 0x500), f.cov.covered_bbs)
        set_send_state(f, 1)
        publish(f, [(base + 1.1, base + 1.2, bb(5))], processed=base + 1.5)
        f._bg_main_window = (base + 1, base + 1.5)
        f._account_command(seed(1), b'a', 0, 0)
        f._bg_drain()
        self.assertEqual(f.corpus[-1].new_pcs, 1)
        self.assertEqual(f._bg_tally['bg_new_bbs'], 1)

    def test_ineligible_command_does_not_steal_discovery(self):
        """시험 15·21: errno 거절(상태 없음)·무효 구간 명령이 본 BB 는 판정 집합에 안 들어간다 — 뒤 정상 명령이 신규로 받는다."""
        for case in ('errno', 'invalid'):
            f = self.fz()
            base = time.monotonic()
            set_send_state(f, 1, status=None if case == 'errno' else 0, submitted=case != 'errno')
            publish(f, [(base + 1.1, base + 1.2, bb(6))],
                    invalid=[(base + 1.15, base + 1.3)] if case == 'invalid' else ())
            f._bg_main_window = (base + 1, base + 1.5)
            f._account_command(seed(1), b'a', 0 if case == 'invalid' else 1, 0)
            set_send_state(f, 2)
            publish(f, [(base + 2.1, base + 2.2, bb(6))], processed=base + 2.5)
            f._bg_main_window = (base + 2, base + 2.5)
            f._account_command(seed(2), b'b', 0, 0)
            f._bg_drain()
            # 명령1 은 SC-depth 전진으로 corpus 에 들어갈 수는 있어도(커버리지 0) BB 를 가져가지 않는다
            self.assertEqual({s.cdw10: s.new_pcs for s in f.corpus}.get(1, 0), 0, case)
            self.assertEqual({s.cdw10: s.new_pcs for s in f.corpus}[2], 1, case)

    def test_swap_drop_across_commands_marks_them_unobserved_and_keeps_draining(self):
        """시험 12·19: 여러 명령을 가로지른 burst 가 정상 스왑으로 폐기 — 그 명령들은 관측 실패, 대기열은 계속 줄고 장애가 아니다."""
        f = self.fz()
        base = time.monotonic()
        for i in (1, 2, 3):
            set_send_state(f, i)
            f._bg_main_window = (base + i, base + i + 0.5)
            f._account_command(seed(i), b'x', 0, 0)
        # 스왑 폐기 묶음 — 1.0~3.6 무효, 처리 경계는 3.6 으로 전진(샘플 없음)
        publish(f, processed=base + 3.6, invalid=[(base + 0.9, base + 3.6)], kind='swap')
        f._bg_drain()
        self.assertFalse(f._bg_pending)
        self.assertEqual(f.executions, 3)
        self.assertEqual(f._bg_tally['unobserved'], 3)
        self.assertEqual(f.stats.get('coverage_unobserved'), 3)
        self.assertFalse(f.sampler.openocd_error.is_set(), '정상 스왑은 장애가 아니다')

    def test_stall_expires_pending_and_late_results_are_never_rewarded(self):
        """시험 7·13: 확정이 멈추면 관측 미확정으로 끝내고 장애 경로로. 늦게 온 샘플은 보상·중복 회계가 없고 참조가 안 남는다."""
        f = self.fz(max_lag_sec=0.05)
        base = time.monotonic() - 1.0            # 명령은 1초 전에 끝났다
        set_send_state(f, 1)
        f._bg_main_window = (base, base + 0.1)
        f._account_command(seed(1), b'a', 0, 0)
        self.assertFalse(f._bg_pending)
        self.assertEqual(f._bg_tally['stall'], 1)
        self.assertTrue(f.sampler.openocd_error.is_set())
        self.assertEqual(f.executions, 1)
        self.assertTrue(all(s.new_pcs == 0 for s in f.corpus))
        n_corpus = len(f.corpus)
        self.assertEqual(f._bg_unconfirmed[0]['command'], 'Write')
        # 늦게 도착한 결과
        publish(f, [(base + 0.02, base + 0.05, bb(3))], processed=base + 0.2)
        f._bg_drain()
        self.assertEqual(f.executions, 1, '중복 회계 없음')
        self.assertEqual(len(f.corpus), n_corpus)
        self.assertFalse(f._bg_pending)
        self.assertNotIn(riscv_cov.pack(0, 0, 0x300), f.cov.judge_bbs)
        self.assertIn(riscv_cov.pack(0, 0, 0x300), f.cov.covered_bbs)

    def test_long_command_is_not_a_stall(self):
        """시험 7: 지연은 명령 완료 뒤부터 잰다 — 처리 경계가 따라오고 있으면 오래된 명령이라도 정체가 아니다."""
        f = self.fz(max_lag_sec=0.05)
        base = time.monotonic() - 10.0          # 10초 전에 끝난 명령(그 뒤 긴 명령이 돌았다)
        set_send_state(f, 1)
        publish(f, processed=base + 9.0)
        f._bg_main_window = (base, base + 0.1)
        f._account_command(seed(1), b'a', 0, 0)
        self.assertEqual(f._bg_tally['stall'], 0)
        self.assertEqual(f.executions, 1)

    def test_pending_max_waits_then_stalls(self):
        """시험 7: 대기 명령 상한 — 짧게 기다리고 그래도 확정이 없으면 정체로 처리."""
        f = self.fz(pending_max=3, max_lag_sec=0.05)
        base = time.monotonic()
        for i in (1, 2, 3):
            set_send_state(f, i)
            f._bg_main_window = (base + i, base + i + 0.5)
            f._account_command(seed(i), b'x', 0, 0)
        self.assertFalse(f._bg_pending)
        self.assertEqual(f._bg_tally['stall'], 1)
        self.assertEqual(f._bg_tally['expired'], 3)

    def test_quiescent_worker_lets_pending_settle(self):
        """일시정지·장애 대기 중이면 앞으로 올 샘플은 재개 뒤 것 — 기다리지 않고 확정한다."""
        f = self.fz()
        base = time.monotonic() - 1.0
        set_send_state(f, 1)
        publish(f, [(base + 0.1, base + 0.2, bb(4))])
        f._bg_main_window = (base, base + 0.5)
        f.sampler._bg_parked = True
        f._account_command(seed(1), b'a', 0, 0)
        self.assertEqual(f.executions, 1)
        self.assertEqual(f.corpus[-1].new_pcs, 1)

    def test_finish_flushes_pending_and_writes_crash_list(self):
        """시험 8: 종료·crash flush 는 제한 시간 안에서 확정하고 나머지는 미확정 목록으로 남긴다."""
        f = self.fz(flush_timeout_sec=0.05)
        base = time.monotonic() + 100            # 처리 경계가 영영 안 오는 구간
        set_send_state(f, 1)
        f._bg_main_window = (base, base + 0.5)
        f._account_command(seed(1), b'a', 0, 0)
        t = time.monotonic()
        f._sampling_finish()
        self.assertLess(time.monotonic() - t, 2.0)
        self.assertEqual(f.executions, 1)
        self.assertEqual(f._bg_unconfirmed[0]['reason'], 'exit')
        with tempfile.TemporaryDirectory() as d, \
                patch.object(v._V101Fuzzer, '_snapshot_crash_context'):
            f._snapshot_crash_context(Path(d), None)
            saved = json.loads((Path(d) / 'bg_unconfirmed.json').read_text())
        self.assertEqual(saved[0]['command'], 'Write')

    def test_completion_count_and_sc_are_immediate(self):
        """리뷰 P2: 샘플 확정 전에도 실행 수·rc·SC 가 바로 반영되고, 100 경계 주기 작업도 그 명령 직후에 돈다."""
        f = self.fz()
        f._print_status = Mock()
        f._window_t0, f._window_exec0 = v.datetime.now(), 0
        base = time.monotonic()
        for i in range(1, 104):
            set_send_state(f, i, status=0x0002 if i == 50 else 0)
            f._bg_main_window = (base + i, base + i + 0.5)
            f._account_command(seed(i), b'x', 0, 0)
            if i == 99:
                self.assertEqual(f._print_status.call_count, 0)
            if i == 100:
                self.assertEqual(f._print_status.call_count, 1, '100번째 명령 직후')
        self.assertEqual(f.executions, 103)
        self.assertEqual(len(f._bg_pending), 103, '커버리지 회계는 아직')
        self.assertEqual(sum(f.rc_stats['Write'].values()), 103)
        self.assertIn(('Write', 0x0002), f._sc_seen)
        self.assertEqual(f.corpus, [])

    def test_timeout_with_pending_reaches_crash_without_device_access(self):
        """리뷰 P1: 대기 명령이 있는 채 timeout — crash 처리 전에 장치 명령(state capture 등)을 보내지 않고, 기다리지도 않는다."""
        f = self.fz(flush_timeout_sec=5.0)
        f.config.state_enabled = True
        order = []
        f.state_monitor = NS(capture=Mock(side_effect=lambda: order.append('capture')))
        f._print_status = Mock()
        f._window_t0, f._window_exec0 = v.datetime.now(), 0
        f.executions = 98
        base = time.monotonic() + 100            # 처리 경계가 오지 않는 구간 — 기다리면 5초가 걸린다
        for i in (1, 2):                         # 두 번째 명령이 100번째 — 주기 작업은 그 직후(timeout 전)
            set_send_state(f, i)
            f._bg_main_window = (base + i, base + i + 0.5)
            f._account_command(seed(i), b'x', 0, 0)
        self.assertEqual(order, ['capture'])
        self.assertEqual(len(f._bg_pending), 2)
        order.append('timeout')
        f._send_nvme_command = Mock(side_effect=lambda *a, **k: order.append('send'))
        f._handle_timeout_crash = Mock(side_effect=lambda *a: (order.append('crash'),
                                                               setattr(f, '_timeout_crash', True)))
        set_send_state(f, 3, status=None)
        f._bg_main_window = (base + 3, base + 3.5)
        t = time.monotonic()
        self.assertEqual(f._account_command(seed(3), b'x', f.RC_TIMEOUT, 0), (False, 0, 'break'))
        self.assertLess(time.monotonic() - t, 1.0, 'timeout 은 확정을 기다리지 않는다')
        self.assertEqual(order, ['capture', 'timeout', 'crash'])
        self.assertEqual([u['reason'] for u in f._bg_unconfirmed], ['sync:command:Write'] * 2)
        self.assertFalse(f._bg_pending)

    def test_pending_coverage_accounting_never_touches_the_device(self):
        """지연 회계(커버리지)는 장치 접근·복구·LLM 적용을 하지 않는다."""
        f = self.fz()
        f._print_status = Mock()
        f._window_t0, f._window_exec0 = v.datetime.now(), 0
        f.config.state_enabled = True
        f.executions = 99
        base = time.monotonic()
        set_send_state(f, 1)
        publish(f, [(base + 1.1, base + 1.2, bb(1))])
        f._bg_main_window = (base + 1, base + 1.5)
        f.state_monitor = NS(capture=Mock(return_value=None))
        f._account_command(seed(1), b'x', 0, 0)          # 100번째 — 주기 작업은 여기서
        boom = Mock(side_effect=AssertionError('device access during deferred accounting'))
        with patch.object(f, '_send_nvme_command', boom), \
                patch.object(f, '_account_periodic', boom), \
                patch.object(f, '_llm_drain_and_apply', boom), \
                patch.object(f.sampler, '_reconnect', boom), \
                patch.object(f, '_reconnect_after_fw_commit', boom):
            f.state_monitor.capture = boom
            publish(f, processed=base + 2)
            f._bg_drain()
        self.assertEqual(f.corpus[-1].new_pcs, 1)

    def test_state_replay_send_failure_does_not_enter_judge_set(self):
        """리뷰 P1: 실제 호출 문맥(state-replay:…)에서도 전송 실패 창은 판정 집합을 갱신하지 않는다."""
        f = self.fz()
        base = time.monotonic()
        k = riscv_cov.pack(0, 0, 0x600)
        for ctx in ('state-replay:Write', 'calibration:Write:1', 'io-workload:read', 'fw-preload:slot1',
                    'startup:FormatNVM'):
            f._last_cmd_submitted, f._last_nvme_status = False, None
            publish(f, [(base + 0.1, base + 0.2, bb(6))], processed=base + 0.5)
            f.sampler.bg_last_window = (base, base + 0.5)
            with patch.object(v._V101Fuzzer, '_stop_sampling_checked', return_value=(0, True)):
                f._stop_sampling_checked(ctx)
            self.assertEqual(f.sampler.current_trace, set(), ctx)
            self.assertNotIn(k, f.cov.judge_bbs or set(), ctx)
            base += 1
        # PM 창은 NVMe 명령이 아니다 — 전송 확인 없이 받는다
        publish(f, [(base + 0.1, base + 0.2, bb(6))], processed=base + 0.5)
        f.sampler.bg_last_window = (base, base + 0.5)
        with patch.object(v._V101Fuzzer, '_stop_sampling_checked', return_value=(0, True)):
            f._stop_sampling_checked('pm:clkreq')
        self.assertEqual(len(f.sampler.current_trace), 1)
        # 뒤 정상 명령은 같은 BB 를 신규로 받는다
        f2 = self.fz()
        b2 = time.monotonic()
        f2._last_cmd_submitted, f2._last_nvme_status = False, None
        publish(f2, [(b2 + 0.1, b2 + 0.2, bb(6))], processed=b2 + 0.5)
        f2.sampler.bg_last_window = (b2, b2 + 0.5)
        with patch.object(v._V101Fuzzer, '_stop_sampling_checked', return_value=(0, True)):
            f2._stop_sampling_checked('state-replay:Write')
        set_send_state(f2, 1)
        publish(f2, [(b2 + 1.1, b2 + 1.2, bb(6))], processed=b2 + 1.5)
        f2._bg_main_window = (b2 + 1, b2 + 1.5)
        f2._account_command(seed(1), b'x', 0, 0)
        f2._bg_drain()
        self.assertEqual(f2.corpus[-1].new_pcs, 1)

    def test_every_sampling_context_is_classified(self):
        """소스의 모든 _stop_sampling_checked 문맥 접두사가 명령 창/PM 창 중 의도한 쪽으로 분류된다."""
        import re
        from fuzzer_target import FUZZER_FILE
        src = FUZZER_FILE.read_text(encoding='utf-8')
        found = set(re.findall(r'_stop_sampling_checked\(\s*f?["\']([a-z-]+):', src))
        self.assertTrue({'command', 'calibration', 'state-replay', 'io-workload', 'startup', 'pm',
                         'fw-preload'} <= found, found)
        for p in found:
            is_cmd = not (p + ':').startswith(v.BackgroundSamplingMixin._BG_NON_COMMAND_CONTEXTS)
            self.assertEqual(is_cmd, p != 'pm', p)

    def test_seed_changed_after_enqueue_keeps_sent_values(self):
        """리뷰 P2: 대기 중 원본 seed 를 바꿔도 corpus·학습에는 보낸 값이 남는다."""
        f = self.fz()
        base = time.monotonic()
        sd = seed(1)
        sd.learning_meta = {'k': [1]}
        set_send_state(f, 1)
        f._learning_last_send = (sd, 0.25)
        publish(f, [(base + 1.1, base + 1.2, bb(1))])
        f._bg_main_window = (base + 1, base + 1.5)
        f._account_command(sd, sd.data, 0, 0)
        sd.cdw10 = 99
        sd.learning_meta['k'].append(2)
        publish(f, processed=base + 2)
        f._bg_drain()
        self.assertEqual(f.corpus[-1].cdw10, 1)
        self.assertEqual(f.corpus[-1].learning_meta, {'k': [1]})
        self.assertEqual(f.learning.recent[-1]['device_seconds'], 0.25)

    def test_same_pc_across_the_boundary_is_still_the_commands_first_find(self):
        """리뷰 P1: burst 안에서 백그라운드 → 명령으로 같은 PC 가 이어져 fresh=False 로 표시돼도 명령의 첫 발견이다."""
        f = self.fz()
        base = time.monotonic()
        publish(f, [(base + 0.1, base + 0.2, bb(8))], processed=base + 0.5)      # 백그라운드: A (fresh)
        f._bg_drain()
        set_send_state(f, 1)
        publish(f, [(base + 1.1, base + 1.2, bb(8), False)], processed=base + 1.5)  # 같은 burst 다음 값: A (stale 표시)
        f._bg_main_window = (base + 1, base + 1.5)
        f._account_command(seed(1), b'a', 0, 0)
        f._bg_drain()
        self.assertEqual(f.corpus[-1].new_pcs, 1)
        self.assertIn(riscv_cov.pack(0, 0, 0x800), f.cov.judge_bbs)

    def test_commands_sharing_one_burst_each_get_their_observations(self):
        """리뷰: 같은 burst 안의 두 명령 — 뒤 명령의 첫 샘플이 앞 명령 마지막과 같은 PC 여도 뒤 명령 관측에 든다."""
        f = self.fz()
        base = time.monotonic()
        set_send_state(f, 1)
        publish(f, [(base + 1.1, base + 1.2, bb(1)), (base + 1.2, base + 1.3, bb(2))])
        f._bg_main_window = (base + 1, base + 1.5)
        f._account_command(seed(1, 'Write'), b'a', 0, 0)
        set_send_state(f, 2)
        publish(f, [(base + 2.1, base + 2.2, bb(2), False), (base + 2.2, base + 2.3, bb(2), False)],
                processed=base + 2.5)
        f._bg_main_window = (base + 2, base + 2.5)
        f._account_command(seed(2, 'Read'), b'b', 0, 0)
        f._bg_drain()
        self.assertEqual(f.cmd_cov_keys['Write'], {riscv_cov.pack(0, 0, 0x100), riscv_cov.pack(0, 0, 0x200)})
        self.assertEqual(f.cmd_cov_keys['Read'], {riscv_cov.pack(0, 0, 0x200)})

    def test_bg_refresh_fresh(self):
        obs = [ob(5)._replace(fresh=False), ob(5)._replace(fresh=False), ob(None, valid=False), ob(5),
               ob(6, core=1)._replace(fresh=False)]
        got = [o.fresh for o in v.bg_refresh_fresh(obs)]
        self.assertEqual([got[i] for i in (0, 1, 3, 4)], [True, False, True, True])   # 무효 샘플 뒤 같은 PC 는 새 값

    def overlay_cov(self, f):
        """core0 에 오버레이 bank 1·2 표를 단다 — 같은 주소 0x5010 이 bank 마다 다른 BB."""
        cm = f.cov.cores[0]
        cm.overlay = {'base': 0x5000, 'window_end': 0x6000}
        for b in (1, 2):
            cm.banks[b] = {'bb_starts': [0x5000], 'bb_ends': [0x5080], 'fn_entries': [], 'fn_ends': [], 'fn_names': []}
        return {riscv_cov.pack(0, 1, 0x5000), riscv_cov.pack(0, 2, 0x5000)}

    def test_refresh_compares_bank_and_pc(self):
        """리뷰 P1: 같은 코어·같은 PC·다른 bank 는 반복이 아니다. 같은 bank 면 반복이다."""
        a = Observation(0, 0x5010, False, True, 1)
        b = Observation(0, 0x5010, False, True, 2)
        self.assertEqual([o.fresh for o in v.bg_refresh_fresh([a, b, b, a])], [True, True, False, True])

    def test_same_pc_different_banks_both_count_in_command_window(self):
        """리뷰 P1(명령 창): bank 1·2 의 같은 주소가 이어져도 BB 키 2개가 모두 그 명령의 신규."""
        f = self.fz()
        want = self.overlay_cov(f)
        base = time.monotonic()
        set_send_state(f, 1)
        f.sampler._bg_out.append({'gen': 0, 'kind': 'accept', 'invalid': [], 'processed': base + 1.5, 'samples': [
            (base + 1.1, base + 1.2, Observation(0, 0x5010, True, True, 1)),
            (base + 1.2, base + 1.3, Observation(0, 0x5010, False, True, 2)),
            (base + 1.3, base + 1.4, Observation(0, 0x5010, False, True, 2))]})
        f._bg_main_window = (base + 1, base + 1.5)
        f._account_command(seed(1), b'a', 0, 0)
        f._bg_drain()
        self.assertEqual(f.corpus[-1].new_pcs, 2)
        self.assertEqual(set(f.corpus[-1].covered_pcs), want)

    def test_same_pc_different_banks_both_count_in_background(self):
        """리뷰 P1(백그라운드): 명령 사이 관측도 bank 별 BB 키를 모두 전체 커버리지에 넣는다."""
        f = self.fz()
        want = self.overlay_cov(f)
        base = time.monotonic()
        f.sampler._bg_out.append({'gen': 0, 'kind': 'accept', 'invalid': [], 'processed': base + 0.5, 'samples': [
            (base + 0.1, base + 0.2, Observation(0, 0x5010, True, True, 1)),
            (base + 0.2, base + 0.3, Observation(0, 0x5010, False, True, 2))]})
        f._bg_drain()
        self.assertEqual(want & f.cov.covered_bbs, want)
        self.assertEqual(f._bg_tally['bg_new_bbs'], 2)

    def test_window_mode_is_untouched(self):
        """시험 10: 창 방식(_bg False)에서는 대기열·판정 집합을 쓰지 않는다."""
        f = self.fz(bg=False)
        set_send_state(f, 1)
        f.sampler.bg_fill_window([ob(bb(1))])
        f._account_command(seed(1), b'a', 0, 0)
        self.assertEqual(f.executions, 1)
        self.assertIsNone(f.cov.judge_bbs)
        self.assertFalse(f._bg_pending)


# ═════════════════════════════════════════════════════════════════════════════
# 3. 워커 (진짜 스레드, 가짜 DAP)
# ═════════════════════════════════════════════════════════════════════════════
def worker_sampler(read, overlay_words=None, **opts):
    """read(n) → raw (n = 누적 읽기 횟수). overlay_words: 프로브 읽기마다 돌려줄 값의 iterator(None = 오버레이 없음)."""
    scfg = v.FuzzConfig(sampler_type='riscv_pcsr',
                        riscv={'sample_plan': {'weights': {'0': 1}, 'seed': 1, 'jitter_pct': 0,
                                               'burst_len': 8}})
    o = dict(v._BG_DEFAULTS, overlay_burst_len=8, pause_timeout_sec=2.0)
    o.update(opts)
    s = v.RiscvBgSampler(scfg, o)
    s._ranges = {0: range(0, 1 << 24)}
    count = {'n': 0}

    def raw(_dap):
        count['n'] += 1
        return read(count['n'])
    sess = fake_session([])
    sess._sj.sba_read_pinned = raw
    sess.lk = NS(jl=object())
    sess.close = Mock()
    if overlay_words is not None:
        s._ovl_probe = {0: 0x40}
        sess.read_word = Mock(side_effect=lambda *a, **k: next(overlay_words))
        s._resolve_bank = lambda c, w: w
    s.session = sess
    s.count = count
    s._sj_mod = lambda: NS(PCSR_COLLAPSE_MIN_ALL_CORE_CYCLES=10 ** 9, PCSR_COLLAPSE_MIN_SECONDS=1e9)
    return s


def wait_for(cond, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.005)
    return False


class Worker(unittest.TestCase):
    def test_pause_ack_means_no_more_dap_access(self):
        """시험 3: 일시정지 확인 뒤에는 DAP 읽기가 없다. 재개하면 다시 읽고 세대가 바뀐다."""
        s = worker_sampler(lambda n: 0x2001)
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.count['n'] > 50))
        self.assertTrue(s.bg_pause())
        self.assertTrue(s.bg_quiescent())
        n = s.count['n']
        time.sleep(0.05)
        self.assertEqual(s.count['n'], n)
        kinds = [b['kind'] for b in s.bg_take()]
        self.assertEqual(kinds[-1], 'pause')
        gen = s.bg_gen
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.count['n'] > n + 20))
        self.assertEqual(s.bg_gen, gen + 1)
        self.assertIn('gap', [b['kind'] for b in s.bg_take()])
        s.bg_shutdown()

    def test_unresponsive_worker_is_never_closed_or_replaced(self):
        """시험 3: J-Link 호출 안에서 멈춘 워커 — 일시정지 실패 → 세션 close·새 워커·복구 재연결을 하지 않는다."""
        hang = threading.Event()

        def read(n):
            if n == 30:
                hang.wait(5.0)
            return 0x2001
        s = worker_sampler(read)
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.count['n'] >= 30))
        self.assertFalse(s.bg_pause(timeout=0.1))
        self.assertTrue(s.bg_unresponsive)
        self.assertTrue(s.openocd_error.is_set())
        s.close()
        s.session.close.assert_not_called()
        t, gen = s._bg_thread, s.bg_gen
        s.start_sampling()
        self.assertIs(s._bg_thread, t, '새 워커를 만들면 같은 핸들을 두 스레드가 쓴다')
        self.assertEqual(s.bg_gen, gen, '응답 없는 워커를 재개하지 않는다')
        self.assertTrue(s._bg_pause_req)
        self.assertFalse(s.connect())
        # 퍼저 쪽: 복구(close·재연결)를 부르지 않고 캠페인을 멈춘다 — 종료 정리도 막힌 close 를 다시 부르지 않는다
        f = make_fuzzer()
        f.sampler = s
        with patch.object(v._V101Fuzzer, '_stop_sampling_checked') as base_stop:
            self.assertEqual(f._stop_sampling_checked('command:Write'), (0, False))
        base_stop.assert_not_called()
        self.assertTrue(f._sampler_recovery_failed)
        f._sampling_finish()
        s.session.close.assert_not_called()
        self.assertIsNone(f._read_bm9k1_monitor_pc())
        hang.set()
        f._tmp.cleanup()

    def test_consecutive_bank_swaps_are_not_faults(self):
        """시험 19: 정상 bank 불일치가 연달아 나도 장애·재연결로 가지 않고 처리 경계는 계속 간다."""
        words = iter([1, 2] * 1000)              # 앞 1, 뒤 2 — 매번 스왑
        s = worker_sampler(lambda n: 0x2001, overlay_words=words)
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.bg_counts['swap_drop'] >= 5))
        s.bg_pause()
        batches = s.bg_take()
        swaps = [b for b in batches if b['kind'] == 'swap']
        self.assertGreaterEqual(len(swaps), 5)
        self.assertTrue(all(b['invalid'] and b['processed'] and not b['samples'] for b in swaps))
        procs = [b['processed'] for b in swaps]
        self.assertEqual(procs, sorted(procs))
        self.assertFalse(s.openocd_error.is_set())
        self.assertEqual(s.bg_counts['faults'], 0)
        s.bg_shutdown()

    def test_kept_overlay_burst_is_tagged_and_accepted(self):
        words = iter([3] * 10000)
        s = worker_sampler(lambda n: 0x2001, overlay_words=words)
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.bg_counts['accepted'] >= 2))
        s.bg_pause()
        acc = [b for b in s.bg_take() if b['kind'] == 'accept']
        self.assertTrue(acc and all(o.bank == 3 for b in acc for _, _, o in b['samples']))
        s.bg_shutdown()

    def test_transport_failure_is_a_fault_and_worker_parks(self):
        """시험 4: 전송 실패 — 직전 정상 검증 경계부터 무효로 공개, 장애 표시, 세션에 손대지 않고 대기."""
        s = worker_sampler(lambda n: 0x2001 if n <= 16 else None)
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.openocd_error.is_set()))
        self.assertTrue(wait_for(s.bg_quiescent))
        n = s.count['n']
        time.sleep(0.05)
        self.assertEqual(s.count['n'], n, '장애 대기 중에는 읽지 않는다')
        batches = s.bg_take()
        acc = [b for b in batches if b['kind'] == 'accept']
        fault = [b for b in batches if b['kind'].startswith('fault')]
        self.assertTrue(acc and fault)
        self.assertEqual(fault[0]['invalid'][0][0], acc[-1]['processed'], '무효 구간은 마지막 정상 검증 경계부터')
        self.assertTrue(s.bg_pause())
        s.bg_shutdown()

    def test_worker_exception_publishes_invalid_span_before_parking(self):
        """리뷰 P2: burst 도중 예외 — 직전 정상 검증 경계부터 무효를 공개한 뒤 장애 대기."""
        def read(n):
            if n == 30:
                raise RuntimeError('DLL 예외 흉내')
            return 0x2001
        s = worker_sampler(read)
        s.start_sampling()
        self.assertTrue(wait_for(s.bg_quiescent))
        batches = s.bg_take()
        acc = [b for b in batches if b['kind'] == 'accept']
        fault = [b for b in batches if b['kind'].startswith('fault')]
        self.assertTrue(acc and fault)
        self.assertEqual(fault[0]['kind'], 'fault:exception')
        self.assertEqual(fault[0]['invalid'][0][0], acc[-1]['processed'])
        self.assertTrue(s.openocd_error.is_set())
        self.assertEqual(len(fault), 1, '예외에서 이미 공개했으면 장애 대기에서 또 내지 않는다')
        self.assertTrue(s.bg_pause())
        s.bg_shutdown()

    def test_error_flag_without_fault_publishes_one_before_parking(self):
        """붕괴·스케줄 없음·메인 정체 판정처럼 장애 표시만 세운 경로도 장애 대기 전에 무효 구간을 공개한다."""
        s = worker_sampler(lambda n: 0x2001)
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.bg_counts['accepted'] >= 2))
        s.openocd_error.set()
        self.assertTrue(wait_for(s.bg_quiescent))
        kinds = [b['kind'] for b in s.bg_take()]
        self.assertIn('fault:error', kinds)
        self.assertTrue(s.bg_pause())
        s.bg_shutdown()

    def test_fault_after_resume_is_published_again(self):
        """재개 뒤 첫 사건이 장애여도 공개한다(이전 세대의 장애 공개를 이번 것으로 치지 않는다)."""
        s = worker_sampler(lambda n: 0x2001)
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.bg_counts['accepted'] >= 2))
        s.openocd_error.set()
        self.assertTrue(wait_for(s.bg_quiescent))
        s.stop_sampling()
        self.assertTrue(s.bg_pause())
        s.bg_take()
        s.start_sampling()                          # 장애 표시가 남은 채 재개 — 바로 장애 대기로
        self.assertTrue(wait_for(lambda: s._bg_error_parked))
        self.assertIn('fault:error', [b['kind'] for b in s.bg_take()])
        self.assertTrue(s.bg_pause())
        s.bg_shutdown()

    def test_exception_mid_command_marks_pending_command_unobserved(self):
        """리뷰 P2: 예외에 걸친 대기 명령은 보상·학습 근거에서 빠진다(처리 경계가 '지금'으로 가도)."""
        f = make_fuzzer()
        self.addCleanup(f._tmp.cleanup)
        boom = {'at': None}

        def read(n):
            if boom['at'] is not None and n >= boom['at']:
                raise RuntimeError('DLL 예외 흉내')
            return bb(7) | 1
        w = worker_sampler(read)
        w.cov, w._ranges = f.cov, f.sampler._ranges
        f.sampler, f._bg_opts = w, w.bg_opts
        w.start_sampling()                          # 명령 구간 열림
        self.assertTrue(wait_for(lambda: w.bg_counts['accepted'] >= 3))
        boom['at'] = w.count['n'] + 5
        self.assertTrue(wait_for(w.bg_quiescent))
        set_send_state(f, 1)
        w._reinit_target = Mock(return_value=True)  # 장애 표시 → 복구 경로는 모의(실제 세션을 열지 않는다)
        f._prepare_sjtag_reauth = Mock()
        f._stop_sampling_checked('command:Write')
        f._account_command(seed(1), b'a', 0, 0)
        f._bg_drain()
        self.assertEqual(f.executions, 1)
        self.assertFalse(f._bg_pending)
        self.assertEqual([s.new_pcs for s in f.corpus if s.new_pcs], [])
        self.assertNotIn(riscv_cov.pack(0, 0, 0x700), f.cov.judge_bbs or set())
        self.assertEqual(f._bg_tally['unobserved'], 1)
        self.assertFalse(f.learning.recent[-1]['observable'])
        w.bg_pause()
        w.bg_shutdown()

    def test_first_sample_after_resume_on_same_core_is_not_attributed_to_new_window(self):
        """시험 20: 일시정지 뒤 재개 — 같은 코어면 주소를 다시 쓰지 않으므로 첫 값의 구간은 일시정지 전부터다."""
        s = worker_sampler(lambda n: 0x2001)
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.count['n'] > 20))
        s.stop_sampling()                        # 앞 명령 구간을 닫는다(실제 퍼저는 늘 start/stop 짝)
        s.bg_pause()
        s.bg_take()
        time.sleep(0.02)
        acc0 = s.bg_counts['accepted']
        s.start_sampling()                       # 재개 + 명령 구간 시작
        t0 = s.bg_open_t0()
        self.assertTrue(wait_for(lambda: s.bg_counts['accepted'] >= acc0 + 2))
        s.bg_pause()
        first = next(b for b in s.bg_take() if b['kind'] == 'accept' and b['samples'])
        lo, hi, _ = first['samples'][0]
        self.assertLess(lo, t0, '첫 값은 일시정지 전 트리거 — 새 구간에 완전히 들 수 없다')
        s.bg_shutdown()

    def test_result_queue_memory_is_bounded_without_a_consumer(self):
        """리뷰 P2: 메인이 결과를 가져가지 않아도 큐 항목 수·무효 구간 수가 늘지 않는다."""
        s = worker_sampler(lambda n: 0x2001, queue_max_samples=2)
        sizes = []
        for k in range(300):
            s._bg_put([(1.0 + k, 1.5 + k, ob(bb(1)))])
            s._bg_put([], [(2.0 + k, 2.1 + k)], kind='swap')
            q = list(s._bg_out)
            sizes.append((len(q), sum(len(b['invalid']) for b in q), sum(len(b['samples']) for b in q)))
        self.assertEqual(sizes[-1], sizes[10], '넘친 뒤에는 묶음·무효 구간·샘플이 늘지 않는다')
        self.assertLessEqual(sizes[-1][2], 2)
        over = s._bg_out[-1]
        self.assertEqual(over['kind'], 'overflow')
        self.assertEqual(over['invalid'][0][1], over['processed'], '넘침 구간은 마지막 공개까지 덮는다')
        s2 = worker_sampler(lambda n: 0x2001)
        s2._BG_MAX_BATCHES = 10
        for k in range(300):
            s2._bg_put([], kind='skip')
        self.assertLessEqual(len(s2._bg_out), 11)

    def test_overflow_drops_samples_but_publishes_invalid_span(self):
        """§3.10: 결과 큐 상한 — 샘플을 버리되 그 구간을 무효로 공개하고 넘침을 센다."""
        s = worker_sampler(lambda n: 0x2001, queue_max_samples=10)
        s.start_sampling()
        self.assertTrue(wait_for(lambda: s.bg_counts['overflow_samples'] > 0))
        s.bg_pause()
        over = [b for b in s.bg_take() if b['kind'] == 'overflow']
        self.assertTrue(over and all(not b['samples'] and len(b['invalid']) == 1 for b in over))
        s.bg_shutdown()


class EndToEnd(unittest.TestCase):
    """진짜 워커 스레드(가짜 DAP) + 진짜 퍼저 회계. 명령마다 펌웨어가 다른 BB 를 돈다고 두고,
    각 명령이 **자기 BB 만** 받는지, 명령 사이 PC 가 백그라운드로만 가는지 본다."""

    IDLE = 350

    def test_commands_get_only_their_own_code(self):
        f = make_fuzzer(flush_timeout_sec=2.0, max_lag_sec=5.0)
        self.addCleanup(f._tmp.cleanup)
        state = {'bb': self.IDLE}
        w = worker_sampler(lambda n: bb(state['bb']) | 1)
        w.cov, w._ranges = f.cov, f.sampler._ranges
        f.sampler = w
        f._bg_opts = w.bg_opts
        f._window_t0, f._window_exec0 = v.datetime.now(), 0

        def send(i, sleep=0.005):
            # 펌웨어가 명령 구간 전체(시작 전 ~ 끝난 뒤)에 걸쳐 BB i 를 돈다 — 구간 안의 읽기는 전부 BB i
            state['bb'] = i
            w.start_sampling()
            time.sleep(sleep)
            set_send_state(f, i)

        def stop(i):
            f._stop_sampling_checked(f'command:{i}')
            state['bb'] = self.IDLE              # 구간이 닫힌 뒤 idle 로 — 명령 사이 PC

        seq_hits = 0
        for i in range(1, 41):
            send(i)
            if i == 20:
                # 세션을 쓰는 다른 경로(예: PM 분리) — 워커를 멈췄다가 다음 명령에서 재개
                w._stop_worker()
                self.assertTrue(w.bg_quiescent())
            if i % 10 == 5:
                # 시퀀스 멤버 — 기다려 확정(앞 대기 명령 먼저)
                f._seq_sink = {'commands': [], 'new_pcs': 0, 'covered_pcs': set(), 'interesting': False}
                stop(i)
                f._account_command(seed(i), b'x', 0, 0, seq_member=True)
                self.assertLessEqual(f._seq_sink['covered_pcs'], {riscv_cov.pack(0, 0, 0x100 * i)}, i)
                seq_hits += bool(f._seq_sink['new_pcs'])
                f._seq_sink = None
                continue
            stop(i)
            f._account_command(seed(i), b'x', 0, 0)
            time.sleep(0.001)                     # 명령 사이(idle)
        f._sampling_finish()

        self.assertEqual(f.executions, 40)
        self.assertFalse(f._bg_pending)
        got = {s.cdw10: set(s.covered_pcs) for s in f.corpus}
        for i, keys in got.items():
            # 엄격: 다른 명령·idle 의 BB 는 절대 섞이지 않는다
            self.assertEqual(keys, {riscv_cov.pack(0, 0, 0x100 * i)}, f'명령 {i} 에 다른 명령/idle BB 가 섞였다')
        # 느슨: 워커 스레드 스케줄에 따라 짧은 명령 하나가 샘플 0개일 수는 있다(오귀속은 아니다)
        plain = [i for i in range(1, 41) if i % 10 != 5]
        self.assertGreaterEqual(sum(i in got for i in plain), int(0.75 * len(plain)))
        self.assertGreaterEqual(seq_hits, 2)
        idle = riscv_cov.pack(0, 0, 0x100 * self.IDLE)
        self.assertIn(idle, f.cov.covered_bbs, '명령 사이 PC 는 전체 커버리지에')
        self.assertFalse(any(idle in s.covered_pcs for s in f.corpus), 'idle PC 가 명령 성과로 잡혔다')
        self.assertEqual(f._bg_tally['stall'], 0)
        self.assertGreater(f._bg_tally['ambiguous'], 0)
        self.assertFalse(w._bg_thread.is_alive(), '종료 때 워커를 끝낸다')


# ═════════════════════════════════════════════════════════════════════════════
# 4. 설정·기동·비교 도구
# ═════════════════════════════════════════════════════════════════════════════
def cfg(bg):
    return NS(riscv={'sample_plan': {'background': bg}})


class Startup(unittest.TestCase):
    def test_options(self):
        """시험 10: 키가 없으면 꺼짐. 켜면 기본값, 모르는 키·잘못된 값은 거부."""
        self.assertIsNone(v.riscv_background_options(NS(riscv={})))
        self.assertIsNone(v.riscv_background_options(cfg(False)))
        self.assertIsNone(v.riscv_background_options(cfg({'enabled': False, 'pending_max': 9})))
        self.assertEqual(v.riscv_background_options(cfg(True)), v._BG_DEFAULTS)
        self.assertEqual(v.riscv_background_options(cfg({'enabled': True, 'pending_max': 9}))['pending_max'], 9)
        for bad in ({'enabled': 'yes'}, {'enabled': True, 'pendng_max': 1},
                    {'enabled': True, 'max_lag_sec': 0}, {'enabled': True, 'pending_max': True}, 'on'):
            with self.assertRaises(ValueError, msg=bad):
                v.riscv_background_options(cfg(bad))

    def test_shipped_config_turns_background_on(self):
        data = json.loads((ROOT / 'fuzzer_config.json').read_text(encoding='utf-8'))
        plan = data['products']['BM9K1']['riscv']['sample_plan']
        self.assertIs(plan['background']['enabled'], True)
        self.assertIsNotNone(v.riscv_background_options(NS(riscv=data['products']['BM9K1']['riscv'])))

    def _construct(self, bg, exceptions=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = v.FuzzConfig(rag_enabled=False, state_enabled=False, output_dir=tmp.name,
                              vmon_enabled=False, sampler_type='riscv_pcsr',
                              riscv={'sample_plan': {'weights': {'0': 1}, 'background': bg}})
        exc_cfg = dict(v._CFG, exceptions=dict(v._CFG.get('exceptions') or {}, enabled=exceptions))
        with patch.object(v.NVMeFuzzer, '_load_static_analysis'), \
                patch.object(v.NVMeFuzzer, '_load_riscv_coverage'), \
                patch.object(v.NVMeFuzzer, 'exception_config', exc_cfg), \
                patch.object(v, 'compile_profiles'), \
                patch('subprocess.run', side_effect=AssertionError('device access')):
            return v.NVMeFuzzer(config)

    def test_factory_selects_sampler_by_option(self):
        """시험 10: background 꺼짐 → v11.2.1 RiscvPcsrSampler 그대로, 켜짐 → RiscvBgSampler."""
        off = self._construct(False)
        self.assertIs(type(off.sampler), v.RiscvPcsrSampler)
        self.assertFalse(off._bg)
        on = self._construct({'enabled': True})
        self.assertIs(type(on.sampler), v.RiscvBgSampler)
        self.assertTrue(on._bg)
        self.assertEqual(on._run_record_conditions()['sampling_mode'], 'background')
        self.assertEqual(off._run_record_conditions()['sampling_mode'], 'window')

    def test_background_with_exception_injection_is_allowed(self):
        """시험 16: 예외 주입과 함께 켤 수 있다(복구 관측 창은 RecoveryObservation 시험)."""
        on = self._construct({'enabled': True}, exceptions=True)
        self.assertIs(type(on.sampler), v.RiscvBgSampler)
        self.assertTrue(on._bg)
        self._construct(False, exceptions=True)

    def test_run_settles_pending_before_final_reports(self):
        """시험 8: 메인 루프가 어떻게 끝나든(break·예외·Ctrl+C) finally 첫머리에서 대기 명령을 확정한다."""
        import ast
        from fuzzer_target import FUZZER_FILE
        tree = ast.parse(FUZZER_FILE.read_text(encoding='utf-8'))
        base = next(c for c in tree.body if isinstance(c, ast.ClassDef) and c.name == '_V101Fuzzer')
        run = next(n for n in base.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
        finals = [t.finalbody for t in ast.walk(run) if isinstance(t, ast.Try) and t.finalbody
                  and any(getattr(getattr(c, 'func', None), 'attr', '') == '_learning_save'
                          for s in t.finalbody for c in ast.walk(s) if isinstance(c, ast.Call))]
        self.assertEqual(len(finals), 1)
        order = [c.func.attr for s in finals[0] for c in ast.walk(s)
                 if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)]
        self.assertLess(order.index('_sampling_finish'), order.index('_learning_save'))

    def test_bad_option_stops_startup(self):
        with self.assertRaises(SystemExit):
            self._construct({'enabled': True, 'pending_max': -1})

    def test_other_products_are_unaffected(self):
        """시험 10: 다른 제품(샘플러 종류)은 백그라운드 설정과 무관."""
        f = make_fuzzer(bg=False)
        self.addCleanup(f._tmp.cleanup)
        self.assertFalse(getattr(v.NullSampler, 'BACKGROUND', False))
        self.assertFalse(getattr(v.RiscvPcsrSampler, 'BACKGROUND', False))


def record(rid, mode=None, bb=10.0):
    cond = {'product': 'BM9K1', 'commands': ['Read'], 'llm': False, 'version': '11.3.0'}
    if mode is not None:
        cond['sampling_mode'] = mode
    return {'schema': compare_runs.SCHEMA, 'run_id': rid, 'conditions': cond, 'coverage_unit': 'bb',
            'totals': {'bb_total': 100}, 'series': [{'t': 0, 'exec': 0, 'bb_pct': 0.0},
                                                   {'t': 10, 'exec': 10, 'bb_pct': bb}]}


class CompareTool(unittest.TestCase):
    def test_mixed_sampling_modes_are_refused_without_strict(self):
        """시험 9: v11.2(키 없음 = window) 와 v11.3 background 를 한 그룹으로 섞지 않는다."""
        runs = [record('a'), record('b', 'background')]
        with self.assertRaises(SystemExit) as cm:
            compare_runs.check_comparable(runs, 'llm', strict=False)
        self.assertIn('--group sampling_mode', str(cm.exception))

    def test_missing_key_means_window(self):
        problems = compare_runs.check_comparable([record('a'), record('b', 'window')], 'llm', strict=False)
        self.assertFalse([p for p in problems if 'sampling_mode' in p])

    def test_grouping_by_sampling_mode_is_allowed(self):
        runs = [record('a'), record('b', 'background')]
        compare_runs.check_comparable(runs, 'sampling_mode', strict=False)
        self.assertEqual(compare_runs.group_label('sampling_mode', compare_runs.cond(runs[0], 'sampling_mode')),
                         'sampling_mode=window')



if __name__ == '__main__':
    unittest.main()
