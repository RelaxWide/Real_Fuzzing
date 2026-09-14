"""Legacy OpenOCD PCSR protocol regression tests; no SSD/debug probe needed."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_v10_2_learning import fuzzer


class PcsrResponseTests(unittest.TestCase):
    def sampler(self, n=3):
        obj = fuzzer.OpenOCDPCSampler.__new__(fuzzer.OpenOCDPCSampler)
        obj._pcsr_addrs = [0x80030084 + i * 0x2000 for i in range(n)]
        obj._invalid_pc_mask = frozenset([0x6ba02476] + obj._pcsr_addrs)
        obj._drain_socket = Mock()
        return obj

    def test_dpidr_noise_is_not_a_fourth_core(self):
        obj = self.sampler()
        obj._telnet_cmd = Mock(return_value=(
            'Info : SWD DPIDR 0x6ba02477\r\nread_all_pcs r1\r\n'
            'PCFUZZ_PCSR:r1:0x1001 0x2000 0x3001:END\r\n'))
        self.assertEqual(obj._read_all_pcs(), (0x1000, 0x2000, 0x3000))
        obj._telnet_cmd.assert_called_once_with('read_all_pcs r1')
        obj._drain_socket.assert_not_called()

    def test_errors_echo_stale_malformed_and_ambiguous_frames_rejected(self):
        good = 'PCFUZZ_PCSR:r1:0x1000 0x2000 0x3000:END'
        cases = [
            '0x6ba02477 0x1000 0x2000 0x3000',
            'proc read_all_pcs {token} { return "PCFUZZ_PCSR:${token}:$pc0 $pc1 $pc2:END" }',
            good.replace('r1:', 'r0:'), good + '\n' + good,
            good.replace('0x3000', '0x3000 0x4000'),
            good.replace('0x3000', 'bad'), good[:-4],
            'PCFUZZ_PCSR:r1:ERR:read failed 0x80030084 0x80032084 0x80034084:END',
        ]
        for response in cases:
            with self.subTest(response=response):
                obj = self.sampler()
                obj._telnet_cmd = Mock(return_value=response)
                self.assertIsNone(obj._read_all_pcs())
                obj._drain_socket.assert_called_once()

    def test_invalid_values_inside_real_frame_still_rejected(self):
        for payload in ['0x1000 0x6ba02477 0x3000', '0x0 0x0 0xffffffff',
                        '0x1000 0x80030084 0x3000']:
            obj = self.sampler()
            obj._telnet_cmd = Mock(return_value='PCFUZZ_PCSR:r1:' + payload + ':END')
            self.assertIsNone(obj._read_all_pcs())

    def test_fragmented_socket_response_and_next_request(self):
        obj = self.sampler()
        obj._sock_buf = b''
        obj._sock = Mock()
        obj._sock.recv.side_effect = [
            b'Info : 0x6ba02477\r\nread_all_pcs r1\r\nPCFU',
            b'ZZ_PCSR:r1:0x1001 0x2000 ', b'0x3000:END\r\n>', b' ',
            b'read_all_pcs r2\r\nPCFUZZ_PCSR:r2:0x4000 0x5000 0x6000:END\r\n> ',
        ]
        self.assertEqual(obj._read_all_pcs(), (0x1000, 0x2000, 0x3000))
        self.assertEqual(obj._read_all_pcs(), (0x4000, 0x5000, 0x6000))
        self.assertEqual([c.args[0] for c in obj._sock.sendall.call_args_list],
                         [b'read_all_pcs r1\n', b'read_all_pcs r2\n'])

    def test_core_count_comes_from_product(self):
        obj = self.sampler(n=1)
        obj._telnet_cmd = Mock(return_value='PCFUZZ_PCSR:r1:0x1001:END')
        self.assertEqual(obj._read_all_pcs(), (0x1000,))

    def test_startup_frames_both_swd_and_jtag_without_changing_addresses(self):
        for interface in ['swd', 'jtag']:
            obj = self.sampler()
            obj.config = SimpleNamespace(interface=interface, power_addr=None, power_mask=None)
            obj._tcl_prefix = 'r8'
            obj._telnet_cmd = Mock()
            with patch.object(fuzzer.time, 'sleep'):
                obj._send_startup_tcl()
            body = obj._telnet_cmd.call_args.args[0]
            self.assertIn('proc read_all_pcs {token}', body)
            self.assertIn('return "PCFUZZ_PCSR:${token}:$pc0 $pc1 $pc2:END"', body)
            self.assertIn('PCFUZZ_PCSR:${token}:ERR:$_err:END', body)
            for addr in obj._pcsr_addrs:
                self.assertIn('r8.abp read_memory ' + hex(addr) + ' 32 1', body)
