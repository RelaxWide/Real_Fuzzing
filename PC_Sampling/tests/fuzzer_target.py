"""테스트 대상 퍼저의 단일 출처 — 파일 **경로**로 한 번만 불러온다.

퍼저 파일 이름에는 버전이 들어가고(pc_sampling_fuzzer_v11.1.py 처럼 점이 들어갈 수도 있다) 모듈
이름으로는 import 할 수 없다. 그래서 테스트는 파일 이름을 직접 쓰지 않고 여기서 불러온
`fuzzer`(모듈 이름 'fuzzer_active_test')를 쓴다. 버전업 때는 FUZZER_FILE 한 줄만 바꾼다.

    from fuzzer_target import fuzzer as v, FUZZER_FILE
    from fuzzer_active_test import ExceptionController      # fuzzer_target 을 먼저 import 한 뒤
    patch('fuzzer_active_test.time.sleep')                   # 문자열 patch 대상도 같은 이름
"""
import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FUZZER_FILE = ROOT / 'pc_sampling_fuzzer_v11.2.py'
MODULE = 'fuzzer_active_test'

if MODULE in sys.modules:
    fuzzer = sys.modules[MODULE]
else:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    _spec = importlib.util.spec_from_file_location(MODULE, FUZZER_FILE)
    fuzzer = importlib.util.module_from_spec(_spec)
    sys.modules[MODULE] = fuzzer
    # CLI argv 를 격리한다 — __main__ 블록은 실행되지 않는다
    with patch.object(sys, 'argv', [str(FUZZER_FILE)]):
        _spec.loader.exec_module(fuzzer)
