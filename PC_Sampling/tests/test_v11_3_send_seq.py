"""송신 번호(send#) — [NVMe]·[NVMe RET]·exec= 줄을 같은 번호로 잇는다.

백그라운드 샘플링은 exec= 커버리지 회계를 미뤄, exec= 줄이 RET 와 떨어져 몰려 찍힌다. exec 번호는 보조 송신
(상태 재현·format 등)을 세지 않아 송신과 1:1 이 아니므로 송신은 따로 번호를 매기고 exec= 줄에 그 명령의
송신 번호를 찍는다.
"""
import re
import time
import unittest
from unittest.mock import patch

from fuzzer_target import fuzzer as v
import test_v11_3_background as bgt
import test_v11_exceptions as ex


class DeferredExecLineKeepsItsSendNumber(unittest.TestCase):
    def test_burst_of_exec_lines_each_name_their_own_send(self):
        f = bgt.make_fuzzer(bg=True)
        self.addCleanup(f._tmp.cleanup)
        base = time.monotonic()
        with self.assertLogs('pcfuzz', level='INFO') as logs:
            for i in range(1, 4):
                t0, t1 = base + i, base + i + 0.5
                bgt.set_send_state(f, i)
                f._last_send_seq = 100 + i               # 이 명령을 보낸 송신 번호
                bgt.publish(f, [(t0 + 0.1, t0 + 0.2, bgt.bb(i))])
                f._bg_main_window = (t0, t1)
                f._account_command(bgt.seed(i), b'x', 0, 0, source='c1')
            self.assertEqual(len(f._bg_pending), 3, '처리 경계 전 — 셋 다 대기')
            f._last_send_seq = 999                       # 다음 송신이 이미 나간 상태에서 drain
            bgt.publish(f, processed=base + 100)
            f._bg_drain()
        lines = [l for l in logs.output if re.search(r'\bexec=\d+ ', l)]
        got = [re.search(r'exec=(\d+) send#(\S+)', l).groups() for l in lines]
        self.assertEqual(got, [('1', '101'), ('2', '102'), ('3', '103')])
        self.assertEqual(f._last_send_seq, 999, '회계 뒤 현재 값으로 돌아온다')


class SendPathNumbersEachSend(unittest.TestCase):
    setUp = ex.RealTransportIntegration.setUp
    send = ex.RealTransportIntegration.send

    def prep(self, rc, err=b''):
        self.f._exception_controller = None
        self.f._exception_on_spawn = None
        self.proc.returncode = rc
        self.proc.communicate.return_value = (b'', err)

    def test_send_and_ret_share_a_number_that_advances(self):
        nums = []
        for rc, err in ((0, b''), (2, b'NVMe status: INVALID_FIELD: x (0x4002)\n')):
            self.prep(rc, err)
            with self.assertLogs('pcfuzz', level='INFO') as logs:
                self.send()
            text = '\n'.join(logs.output)
            sent = re.search(r'\[NVMe\] send#(\d+) ', text).group(1)
            ret = re.search(r'\[NVMe RET\] send#(\d+) Identify rc=', text).group(1)
            self.assertEqual(sent, ret)
            self.assertEqual(int(sent), self.f._last_send_seq)
            nums.append(int(sent))
        self.assertEqual(nums[1], nums[0] + 1)

    def test_blocked_send_has_no_number(self):
        self.prep(0)
        self.send()
        self.assertIsNotNone(self.f._last_send_seq)
        blocked = v.Seed(data=b'', cmd=v._NAME_TO_CMD['SetFeatures'], cdw10=0x0C)  # APST — json 차단
        with patch.object(v.subprocess, 'Popen') as popen:
            rc = self.f._send_nvme_command(b'', blocked)
        popen.assert_not_called()
        self.assertEqual(rc, self.f.RC_SKIP)
        self.assertIsNone(self.f._last_send_seq, '보내지 않은 호출이 앞 송신 번호를 물려받지 않는다')


if __name__ == '__main__':
    unittest.main()
