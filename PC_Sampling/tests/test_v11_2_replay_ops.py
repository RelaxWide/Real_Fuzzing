"""v11.2.1 — replay 가 PM 동작을 preflight 와 같게 재생.

예전 replay 는 'pcie_state' 요약 항목에서 setpci 를 따로 다시 만들어 EP/RP 순서, Clock PM 조건,
CLKREQ# assert, ASPM 정책 쓰기, 검증 명령(get-feature·lspci·PMU 전류), 대기 시간이 실제와 달랐다.
지금은 실제로 실행한 저수준 동작(op)을 이력에 순서·시각과 함께 남기고 replay 가 그대로 재생한다.
"""
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fuzzer_target import fuzzer as v

BDF, RP = '0000:01:00.0', '0000:00:01.1'


def engine():
    f = v.NVMeFuzzer.__new__(v.NVMeFuzzer)
    f._cmd_history = v._CmdHistory()
    f._pm_unresponsive = None
    f._orig_aspm_policy = 'default'
    f._pcie_bdf, f._pcie_cap_offset, f._pcie_lnkcap = BDF, 0x70, 0x2 << 10
    f._pcie_root_bdf, f._pcie_root_cap_offset = RP, 0x40
    f._pcie_l1ss_offset = f._pcie_root_l1ss_offset = None
    f._pcie_l1ss_cap = f._pcie_root_l1ss_cap = None
    f._pcie_pm_cap_offset = 0x50
    f.config = SimpleNamespace(nvme_device='/dev/nvme0', nvme_kernel_timeout_sec=2592000,
                               pmu_script='/bin/true', clkreq_assert_pin=1, clkreq_deassert_pin=2,
                               clkreq_voltage_mv=3300, l1_settle_s=0.0, l1_2_settle_s=0.0)
    return f


def fake_run(calls):
    def run(argv, timeout=None, **kw):
        calls.append(list(argv))
        out = '0040' if argv[0] == 'setpci' and '=' not in argv[-1] else ''
        return subprocess.CompletedProcess(argv, 0, stdout=out if kw.get('text') else out.encode(),
                                           stderr='' if kw.get('text') else b'')
    return run


def replay_lines(f):
    folder = Path(tempfile.mkdtemp())
    f._generate_replay_sh(folder, 't')
    text = (folder / 'replay_t.sh').read_text()
    subprocess.run(['bash', '-n', str(folder / 'replay_t.sh')], check=True)   # 문법
    return text.splitlines()


def replayed_argv(lines):
    """replay 에서 실제로 실행되는 setpci·python3 줄 → argv (sudo 제외)."""
    out = []
    for line in lines:
        if line.startswith('sudo setpci') or line.startswith('sudo python3'):
            out.append(shlex.split(line)[1:])
    return out


@patch('fuzzer_active_test.time.sleep')
class SameOperations(unittest.TestCase):
    def test_l1_enter_and_l0_restore_replay_exactly_what_ran(self, _):
        f, calls = engine(), []
        with patch('fuzzer_active_test.subprocess.run', side_effect=fake_run(calls)), \
                patch.object(v.Path, 'write_text', return_value=None):
            self.assertTrue(f._set_pcie_l_state(v.PCIeLState.L1))
            self.assertTrue(f._set_pcie_l_state(v.PCIeLState.L0))
        lines = replay_lines(f)
        ran = [c for c in calls if c[0] in ('setpci', 'python3')]
        self.assertGreater(len(ran), 10)
        self.assertEqual(replayed_argv(lines), ran)            # 같은 명령, 같은 순서
        # 예전 재구성과 갈리던 지점들이 실제 순서대로 들어 있다
        text = '\n'.join(lines)
        self.assertIn("echo powersave | sudo tee /sys/module/pcie_aspm/parameters/policy", text)
        self.assertIn("echo default | sudo tee /sys/module/pcie_aspm/parameters/policy", text)
        ep_aspm = text.index(f'sudo setpci -s {BDF} 0x80.w=0002:0003')
        rp_aspm = text.index(f'sudo setpci -s {RP} 0x50.w=0002:0003')
        self.assertLess(ep_aspm, rp_aspm)                       # L1 enable: EP 먼저(preflight 순서)

    def test_verify_and_ps_commands_are_replayed(self, _):
        f, calls = engine(), []
        with patch('fuzzer_active_test.subprocess.run', side_effect=fake_run(calls)), \
                patch('fuzzer_active_test._run_nvme_state_cmd',
                      return_value=v._StateProc(0, b'Current value:0x00000004', b'')):
            f._pm_set_state(4)
            f._pm_verify_combo(v.POWER_COMBOS[4])
        text = '\n'.join(replay_lines(f))
        self.assertIn('--cdw11=0x4', text)                      # PS SetFeatures
        self.assertIn('sudo nvme get-feature /dev/nvme0 -f 0x02', text)   # 검증용 get-feature
        self.assertIn('sudo python3 /bin/true 3 1', text)       # PMU 전류 측정
        self.assertIn('sudo lspci -vv -s', text)

    def test_summary_entries_are_not_rebuilt(self, _):
        f, calls = engine(), []
        with patch('fuzzer_active_test.subprocess.run', side_effect=fake_run(calls)):
            f._setpci_write(BDF, 0x80, 0x2, 0x3, 'w')
        f._record_pcie_state_history(v.POWER_COMBOS[0], True, 'restore')
        text = '\n'.join(replay_lines(f))
        self.assertEqual(text.count('sudo setpci'), 1)          # 요약 항목에서 다시 만들지 않는다
        self.assertIn('실제 동작은 앞뒤 op 줄로 재생', text)


class Timing(unittest.TestCase):
    def test_recorded_gaps_are_slept(self):
        f = engine()
        f._cmd_history.append({'kind': 'op', 'label': 'op a', 'argv': ['setpci', '-s', BDF, '0x80.w'],
                               'rc': 0, 't0': 10.0, 't1': 10.01})
        f._cmd_history.append({'kind': 'op', 'label': 'op b', 'argv': ['setpci', '-s', BDF, '0x82.w'],
                               'rc': 0, 't0': 12.01, 't1': 12.02})
        f._cmd_history.append({'kind': 'op', 'label': 'op c', 'argv': ['setpci', '-s', BDF, '0x84.w'],
                               'rc': 0, 't0': 112.02, 't1': 112.03})
        text = '\n'.join(replay_lines(f))
        self.assertIn('sleep 2.000', text)
        self.assertIn('sleep 30.000  # 원래 100.0s', text)       # 긴 공백은 상한

    def test_untimed_commands_keep_fixed_sleep(self):
        f = engine()
        f._cmd_history.append(dict(kind='nvme', label='Read', passthru_type='io-passthru',
                                   device='/dev/nvme0n1', opcode=2, nsid=1, cdw2=0, cdw3=0,
                                   cdw10=0, cdw11=0, cdw12=0, cdw13=0, cdw14=0, cdw15=0,
                                   data=None, data_len=0, is_write=False))
        self.assertIn('sleep 0.1', replay_lines(f))
        self.assertNotIn('pcie_aspm', '\n'.join(replay_lines(f)))   # op 없으면 정책 줄 없음


class History(unittest.TestCase):
    def test_keeps_last_100_commands_with_ops_between(self):
        h = v._CmdHistory()
        for i in range(150):
            h.append({'kind': 'nvme', 'i': i})
            h.append({'kind': 'op', 'i': i})
        cmds = [x for x in h if x['kind'] != 'op']
        self.assertEqual(len(cmds), 100)
        self.assertEqual(cmds[0]['i'], 50)
        # 밀려난 명령(49) 바로 뒤의 op 는 남은 첫 명령(50) 직전에 실제로 일어난 동작이라 남긴다
        self.assertEqual((h[0]['kind'], h[0]['i']), ('op', 49))
        self.assertEqual(sum(1 for x in h if x['kind'] == 'op'), 101)

    def test_total_cap(self):
        h = v._CmdHistory()
        for i in range(v._CmdHistory.MAX_TOTAL + 50):
            h.append({'kind': 'op', 'i': i})
        self.assertEqual(len(h), v._CmdHistory.MAX_TOTAL)

    def test_state_corpus_snapshot_excludes_ops(self):
        src = v.__file__ and Path(v.__file__).read_text(encoding='utf-8')
        self.assertIn("sequence = [h for h in self._cmd_history if h.get('kind') != 'op'],", src)

    def test_relative_pmu_script_becomes_absolute(self):
        # replay 는 crash 폴더로 cd 해서 돈다 — 상대 경로면 PMU 줄이 엉뚱한 파일을 찾는다
        import os
        f, calls = engine(), []
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'pmu.py').write_text('')
            old = os.getcwd()
            os.chdir(d)
            try:
                f.config.pmu_script = 'pmu.py'
                with patch('fuzzer_active_test.subprocess.run', side_effect=fake_run(calls)):
                    f._pmu_clkreq_assert()
            finally:
                os.chdir(old)
            self.assertEqual(f._cmd_history[-1]['argv'][1], str(Path(d, 'pmu.py').resolve()))

    def test_op_run_records_even_on_exception(self):
        f = engine()
        with patch('fuzzer_active_test.subprocess.run', side_effect=subprocess.TimeoutExpired('x', 3)):
            with self.assertRaises(subprocess.TimeoutExpired):
                f._op_run(['setpci', '-s', BDF, '0x80.w'], 3)
        self.assertEqual((f._cmd_history[-1]['kind'], f._cmd_history[-1]['rc']), ('op', None))


if __name__ == '__main__':
    unittest.main()
