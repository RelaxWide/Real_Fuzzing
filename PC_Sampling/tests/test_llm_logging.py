"""Regression for backend logs and early activation disappearing from llm files."""
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_v10_2_learning import fuzzer
from rag import rag_retrieval, vllm_client


class LlmLoggingTests(unittest.TestCase):
    def test_backend_and_early_records_reach_both_files(self):
        logger = fuzzer.log
        handlers, level, propagate = logger.handlers[:], logger.level, logger.propagate
        early = fuzzer._early_buffer.records[:]
        try:
            logger.handlers = [fuzzer._early_buffer]
            logger.propagate = False
            fuzzer._early_buffer.records.clear()
            logger.warning('[LLM] early activation marker')
            logger.warning('unrelated early marker')
            with tempfile.TemporaryDirectory() as tmp:
                with patch.object(fuzzer, '_detect_nvme_cli_version'), patch.object(fuzzer, '_nvme_cli_warn'):
                    fuzzer.setup_logging(tmp)
                rag_retrieval._log.warning('[LLM/rag] retrieval marker')
                vllm_client._log.warning('[LLM/vllm] backend marker')
                for h in logger.handlers:
                    h.flush()
                main = next(Path(tmp).glob('fuzzer_*.log')).read_text()
                llm = next((Path(tmp)/'llm').glob('*.log')).read_text()
                for marker in ['early activation marker', 'retrieval marker', 'backend marker']:
                    self.assertEqual(main.count(marker), 1)
                    self.assertEqual(llm.count(marker), 1)
                self.assertNotIn('unrelated early marker', llm)
        finally:
            for h in logger.handlers:
                if h not in handlers:
                    h.close()
            logger.handlers = handlers
            logger.setLevel(level)
            logger.propagate = propagate
            fuzzer._early_buffer.records[:] = early
