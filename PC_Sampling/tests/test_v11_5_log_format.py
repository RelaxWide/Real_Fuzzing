"""v11.5 로그 파일 형식 — 이름 fuzzer_<ts>_log.txt, 첫 줄 TEST LOCATION, 타임스탬프 [] 감싸기.

실제 setup_logging 을 임시 폴더에 태운다(로거 핸들러는 끝나면 되돌린다).
"""
import logging
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fuzzer_target import fuzzer as v


class LogFile(unittest.TestCase):
    def setUp(self):
        logger = logging.getLogger('pcfuzz')
        saved = (logger.handlers[:], logger.level, logger.propagate, v._early_buffer.records[:])

        def restore():
            for h in logger.handlers:
                if h not in saved[0]:
                    h.close()
            logger.handlers, logger.level, logger.propagate = saved[0], saved[1], saved[2]
            v._early_buffer.records[:] = saved[3]
        self.addCleanup(restore)
        v._early_buffer.records.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def setup(self):
        with patch.object(v, '_detect_nvme_cli_version'), patch.object(v, '_nvme_cli_warn'):
            logger, path = v.setup_logging(self.tmp.name)
        logger.warning('[Stats] marker')
        for h in logger.handlers:
            h.flush()
        return Path(path)

    def test_name_first_line_and_bracketed_timestamp(self):
        path = self.setup()
        self.assertRegex(path.name, r'^fuzzer_\d{8}_\d{6}_log\.txt$')
        lines = path.read_text(encoding='utf-8').splitlines()
        self.assertEqual(lines[0], '[ TEST LOCATION : { TESTER:TestPC01, BOARD:NA, SLOT:NA, PORT:NA } ]')
        for line in lines[1:]:
            self.assertRegex(line, r'^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\] \[[A-Z]+\] ', line)
        self.assertTrue(any(l.endswith('[WARNING] [Stats] marker') for l in lines))
        self.assertEqual(list(Path(self.tmp.name).glob('fuzzer_*.log')), [])

    def test_location_from_json(self):
        with patch.dict(v.QTMGR, tester='TestPC07', board='B2', slot='3', port='1'):
            path = self.setup()
        self.assertEqual(path.read_text(encoding='utf-8').splitlines()[0],
                         '[ TEST LOCATION : { TESTER:TestPC07, BOARD:B2, SLOT:3, PORT:1 } ]')

    def test_llm_log_and_terminal_use_same_timestamp_format(self):
        rec = logging.LogRecord('pcfuzz', logging.WARNING, __file__, 1, '[LLM] x', None, None)
        for fmt_cls in (v._MsFormatter, v._ColorFormatter):
            text = re.sub(r'\x1b\[[0-9;]*m', '', fmt_cls(v.LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S').format(rec))
            self.assertRegex(text, r'^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\] \[WARNING\] \[LLM\] x$')
        self.setup()
        llm = next((Path(self.tmp.name) / 'llm').glob('*.log'))
        logging.getLogger('pcfuzz').warning('[LLM] y')
        for h in logging.getLogger('pcfuzz').handlers:
            h.flush()
        self.assertRegex(llm.read_text(encoding='utf-8'), r'(?m)^\[\d{4}-\d\d-\d\d [^\]]+\] \[WARNING\] \[LLM\] y$')


if __name__ == '__main__':
    unittest.main()
