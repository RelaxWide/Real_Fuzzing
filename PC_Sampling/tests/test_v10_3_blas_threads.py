"""BLAS 스레드 제한 시험 — RAG 검색이 sched_yield 스핀을 만들지 않게.

OpenBLAS 워커는 연산이 끝난 뒤에도 sched_yield() 로 busy-wait 한다. 퍼저는 샘플러·
LLM 워커·메인 루프가 함께 도는 멀티스레드 프로세스라, 코어 수만큼의 스핀 스레드가
다른 스레드를 굶겨 hang 처럼 보인다. rag_retrieval 의 top-k 행렬곱에서 실제로 관측됐다.

핵심은 **numpy import 보다 먼저** 환경변수가 잡히는가다. 순서가 틀리면 무효다.
"""
import ast
import subprocess
import sys
import unittest
from pathlib import Path

from test_v10_2_learning import ROOT      # noqa: F401

VARS = ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")


def first_numpy_import_line(path):
    """해당 파일에서 numpy 를 처음 import 하는 줄 번호(지연 import 포함)."""
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    best = None
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or '']
        if any(n.split('.')[0] == 'numpy' for n in names):
            best = node.lineno if best is None else min(best, node.lineno)
    return best


def env_setdefault_line(path):
    """BLAS 환경변수를 세우는 가장 이른 줄 번호."""
    src = Path(path).read_text(encoding='utf-8').splitlines()
    for i, line in enumerate(src, 1):
        if 'OPENBLAS_NUM_THREADS' in line:
            return i
    return None


class LimitIsSetBeforeNumpy(unittest.TestCase):
    FILES = ('pc_sampling_fuzzer_v10.3.py', 'rag/rag_retrieval.py', 'tools/rag_ingest.py')

    def test_every_numpy_user_sets_the_limit_first(self):
        for rel in self.FILES:
            path = ROOT / rel
            with self.subTest(file=rel):
                setline = env_setdefault_line(path)
                self.assertIsNotNone(setline, f'{rel}: BLAS 제한이 없다')
                npline = first_numpy_import_line(path)
                if npline is not None:
                    self.assertLess(setline, npline,
                                    f'{rel}: numpy import(L{npline}) 보다 늦게 세운다(L{setline})')

    def test_all_relevant_vars_are_covered(self):
        src = (ROOT / 'rag/rag_retrieval.py').read_text(encoding='utf-8')
        for v in VARS:
            self.assertIn(v, src, f'{v} 가 빠졌다')

    def test_user_setting_is_respected(self):
        """setdefault 여야 한다 — 사용자가 명시한 값을 덮어쓰면 안 된다.

        주석에 'setdefault' 라는 **단어**가 있는 것으로는 안 된다. 실제 호출을 본다.
        """
        for rel in self.FILES:
            src = (ROOT / rel).read_text(encoding='utf-8')
            with self.subTest(file=rel):
                self.assertIn('.environ.setdefault(', src,
                              f'{rel}: environ.setdefault 호출이 없다')
                self.assertNotIn('_os_blas.environ[_v] =', src,
                                 f'{rel}: 사용자 설정을 덮어쓴다')


class ImportingTheFuzzerLimitsBlas(unittest.TestCase):
    def test_env_is_one_after_import_and_numpy_untouched_before(self):
        code = (
            "import sys, os;"
            "assert 'numpy' not in sys.modules;"
            "sys.path.insert(0, %r);"
            "import importlib.util;"
            "from unittest.mock import patch;"
            "spec = importlib.util.spec_from_file_location('fz', %r);"
            "m = importlib.util.module_from_spec(spec); sys.modules['fz'] = m;"
            "patcher = patch.object(sys, 'argv', ['x']); patcher.start();"
            "spec.loader.exec_module(m); patcher.stop();"
            "print(os.environ.get('OPENBLAS_NUM_THREADS'), 'numpy' in sys.modules)"
        ) % (str(ROOT), str(ROOT / 'pc_sampling_fuzzer_v10.3.py'))
        out = subprocess.run([sys.executable, '-c', code], capture_output=True,
                             text=True, timeout=180, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual(out.returncode, 0, out.stderr[-800:])
        self.assertEqual(out.stdout.strip().split()[0], '1',
                         'import 후 OPENBLAS_NUM_THREADS 가 1 이 아니다')


class RetrievalModuleLimitsBlasOnImport(unittest.TestCase):
    """소스 위치가 아니라 **실제 동작**을 본다 — import 만으로 제한이 걸려야 한다."""

    def test_importing_rag_retrieval_sets_the_limit_before_numpy(self):
        code = (
            "import sys, os;"
            "assert 'numpy' not in sys.modules;"
            "sys.path.insert(0, %r);"
            "import rag.rag_retrieval;"
            "print(os.environ.get('OPENBLAS_NUM_THREADS'), 'numpy' in sys.modules)"
        ) % str(ROOT)
        out = subprocess.run([sys.executable, '-c', code], capture_output=True,
                             text=True, timeout=120, env={'PATH': '/usr/bin:/bin'})
        self.assertEqual(out.returncode, 0, out.stderr[-600:])
        val, np_loaded = out.stdout.strip().split()
        self.assertEqual(val, '1', 'import 후 제한이 안 걸렸다')
        self.assertEqual(np_loaded, 'False', 'numpy 가 제한보다 먼저 로드됐다')

    def test_a_preexisting_user_value_survives(self):
        code = (
            "import sys, os;"
            "sys.path.insert(0, %r);"
            "import rag.rag_retrieval;"
            "print(os.environ.get('OPENBLAS_NUM_THREADS'))"
        ) % str(ROOT)
        out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                             timeout=120,
                             env={'PATH': '/usr/bin:/bin', 'OPENBLAS_NUM_THREADS': '4'})
        self.assertEqual(out.stdout.strip(), '4', '사용자가 지정한 값을 덮어썼다')


class RetrievalDoesNotCopyTheIndexPerQuery(unittest.TestCase):
    """질의마다 인덱스 전체를 float32 로 복사하면 인덱스 크기에 비례해 낭비가 커진다."""

    def test_matmul_uses_the_cached_matrix(self):
        src = (ROOT / 'rag/rag_retrieval.py').read_text(encoding='utf-8')
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == 'retrieve')
        seg = ast.get_source_segment(src, fn) or ''
        self.assertNotIn('vectors.astype', seg,
                         '질의 경로에서 여전히 인덱스를 통째로 변환한다')
        self.assertIn('vectors @', seg)

    def test_load_caches_float32(self):
        src = (ROOT / 'rag/rag_retrieval.py').read_text(encoding='utf-8')
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == '_load')
        seg = ast.get_source_segment(src, fn) or ''
        self.assertIn('astype(np.float32)', seg, '_load 가 float32 로 캐시하지 않는다')


if __name__ == '__main__':
    unittest.main()
