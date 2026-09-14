"""FWCommit output routing; no device access."""
import io
import logging
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_v10_2_learning import fuzzer


class CommitLoggingTests(unittest.TestCase):
    def test_details_to_file_and_one_terminal_summary(self):
        for outcome in (True, False, RuntimeError('reconnect failed')):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                terminal, direct = io.StringIO(), io.StringIO()
                path = Path(tmp) / 'fuzzer.log'
                logger = logging.Logger('commit-test', logging.DEBUG)
                fh = logging.FileHandler(str(path), encoding='utf-8')
                fh.setLevel(logging.INFO)
                ch = logging.StreamHandler(terminal)
                ch.setLevel(logging.WARNING)
                ch.addFilter(fuzzer._FuzzingTerminalFilter())
                logger.addHandler(fh)
                logger.addHandler(ch)
                inst = fuzzer.NVMeFuzzer.__new__(fuzzer.NVMeFuzzer)

                def reconnect():
                    print('[pcsr] 인증 완료')
                    print('DM 활성화', file=sys.stderr)
                    logger.warning('[cJTAG/SBA] 세션 OK')
                    print('x' * 20000, end='')
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                inst.sampler = Mock()
                inst.sampler._reconnect.side_effect = reconnect
                try:
                    with patch.object(fuzzer, 'log', logger), patch('sys.stdout', direct), patch('sys.stderr', direct):
                        result = inst._reconnect_after_fw_commit()
                        self.assertIs(sys.stdout, direct)
                        self.assertIs(sys.stderr, direct)
                    fh.flush()
                    content = path.read_text()
                    self.assertIn('[pcsr] 인증 완료', content)
                    self.assertIn('DM 활성화', content)
                    self.assertIn('세션 OK', content)
                    self.assertEqual(sum(len(line.split('] ', 1)[1]) for line in content.splitlines()
                                         if line.startswith('[FWCommit/detail] x')), 20000)
                    self.assertEqual(direct.getvalue(), '')
                    self.assertEqual(len(terminal.getvalue().splitlines()), 1)
                    self.assertIn('성공' if outcome is True else '실패', terminal.getvalue())
                    self.assertEqual(result, outcome is True)
                    if isinstance(outcome, Exception):
                        self.assertIn('Traceback', content)
                    inst.sampler._reconnect.assert_called_once_with()
                    self.assertEqual(len(ch.filters), 1)
                finally:
                    fh.close()

    def test_other_threads_keep_their_output(self):
        terminal = io.StringIO()
        logger = logging.Logger('thread-test', logging.DEBUG)
        logger.addHandler(logging.StreamHandler(terminal))
        direct = io.StringIO()
        with patch.object(fuzzer, 'log', logger), patch('sys.stdout', direct):
            with fuzzer._fw_commit_detail_logging():
                def background():
                    print('background output')
                    logger.error('background error')
                worker = threading.Thread(target=background)
                worker.start()
                worker.join()
        self.assertIn('background output', direct.getvalue())
        self.assertIn('background error', terminal.getvalue())
