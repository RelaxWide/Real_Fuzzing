#!/usr/bin/env python3
"""v11 entrypoint: v10.3 command/LLM engine + optional exception profiles.

All original CLI flags are preserved. Configure exceptions in the same JSON.
The v10.3 entrypoint does not enable this mixin even if that JSON section exists.
"""
from pathlib import Path
import runpy
from exception_control import make_fuzzer

if __name__ == '__main__':
    runpy.run_path(str(Path(__file__).with_name('pc_sampling_fuzzer_v10.3.py')),
                  run_name='__main__',
                  init_globals={'_ENTRY_VERSION': '11.0.0', '_FUZZER_FACTORY': make_fuzzer})
