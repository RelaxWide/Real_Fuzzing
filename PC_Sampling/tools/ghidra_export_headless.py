#@runtime Jython
# -*- coding: utf-8 -*-
r"""펌웨어 커버리지 추출 — BIN / ELF 공통 진입점 (호스트 Python 3).

필요한 tools 파일
----------------
  BIN만 사용: ghidra_export_headless.py
  ELF도 사용: ghidra_export_headless.py + GhidraExportMaps.java (같은 폴더)
  fw2export.sh, run_ghidra_export.sh, 기존 ghidra_export.py는 필요 없다.
  BIN/ELF, overlay JSON, PC seed, 출력 결과는 tools 밖에 두어도 된다.

외부 준비
---------
  Ghidra와 해당 버전이 요구하는 JDK를 별도로 설치한다.
  --ghidra는 support/ 폴더를 포함하는 Ghidra 설치 루트다.
  필요하면 --java-home /path/to/jdk 또는 JAVA_HOME을 지정한다.
  BIN: Ghidra 안에서 이 .py를 실행할 Python/Jython 스크립트 환경 필요.
  ELF: readelf 필요. Java 스크립트가 Ghidra에서 컴파일되어 실행된다.
  아래 CPU/주소/경로는 예시다. 실제 펌웨어에 맞게 지정해야 한다.

1) BIN -> basic_blocks.txt / functions.txt
-----------------------------------------
  python3 tools/ghidra_export_headless.py analyze /fw/FW.bin /out/bin \
    --ghidra /opt/ghidra --processor ARM:LE:32:v7 \
    --cut 0xA4000

  --cut N: 앞 N바이트를 제거한 임시 파일을 분석한다. 원본은 변경하지 않는다.
           dd bs=1M iflag=skip_bytes skip=N과 같은 바이트 절단이다.
           N은 10진수 또는 0x 접두사의 16진수. 파일 전체를 자르는 값은 거부한다.
  위 예는 앞 0xA4000바이트를 제거하고, 남은 첫 바이트를 주소 0에 배치한다.
  base가 0이면 --base는 생략한다(BASE 환경변수도 미설정일 때 기본값 0).
  다른 주소가 필요할 때만 --base A를 지정한다. 이 옵션은 파일을 자르지 않는다.
  헤더 제거가 없으면 --cut 0을 사용한다.
  OUTDIR 생략 시 현재 폴더 아래 BIN 파일명(확장자 제외)을 사용한다.
  출력: basic_blocks.txt (시작/끝 주소, 끝 주소 exclusive),
        functions.txt (진입 주소/10진수 크기/함수 이름).
  추가 옵션: --loader, --analysis-timeout (초, 기본 7200), --java-home.
  --match-gui는 별도 match_gui.py가 있을 때만 사용(--script-dir로 위치 지정).
  기본값 환경변수: GHIDRA, JAVA_HOME, PROC, BASE, CUT, LOADER, MATCH_GUI.

2) ELF 파일들 -> 코어별 전체 자료
---------------------------------
  MAXMEM=16G OVL_MAP='/maps/FW*{label}Core_overlay_map.json' \
    python3 tools/ghidra_export_headless.py symbols /fw/elfs all /out/elf

  위 환경변수 대신 옵션으로도 지정할 수 있다:
  python3 tools/ghidra_export_headless.py symbols /fw/elfs all /out/elf \
    --ghidra /opt/ghidra --maxmem 16G \
    --overlay-map '/maps/FW*{label}Core_overlay_map.json'

  all: ELF 폴더의 FW_*Core.elf를 순회한다(FW_HCore.elf -> label H).
  단일 코어: symbols /fw/FW_HCore.elf H /out/elf
  overlay 진단만: symbols /fw/FW_HCore.elf ovlinfo /out/elf
  PC seed 선택: 출력 경로 뒤에 PC_DIR(all) 또는 PC_LIST(단일 코어)를 추가.
                PC_DIR에서는 pcsr_coreH.txt처럼 코어별 파일을 찾는다.

  입력은 로드 가능한 ELF다. 텍스트 심볼 목록만으로는 사용할 수 없다.
  ELF 섹션 주소를 사용하므로 --cut/--base는 적용하지 않는다.
  CPU 기본값은 RISCV:LE:32:default. 자동 판별은 --processor ''로 지정한다.
  overlay가 없으면 --overlay-map/OVL_MAP을 생략한다.
  패턴을 따옴표로 감싸면 코어마다 {label} 치환 후 *를 확장한다.
  여러 map은 쉼표로 구분한다. 공백이 든 경로는 지원하며 쉼표는 구분자다.
  없는 map은 경고 후 건너뛰고, 잘못된 JSON/상충하는 section 매핑은 중단한다.
  OVL_MAP은 ELF section_index로 filemap을 분리한다. ELF 자체를 재배치하지 않는다.

  출력: basic_blocks_core<LABEL>.txt, functions_core<LABEL>.txt,
        callgraph_core<LABEL>.txt, filemap_core<LABEL>.txt,
        overlay별 *_core<LABEL>_ovl<N>.txt,
        symbols_core<LABEL>.json, 통합 symbols.json.
  추가 옵션: --maxcpu, --no-dwarf 0|1, --aggressive 0|1, --script-dir.
  기본값 환경변수: GHIDRA_HOME(GHIDRA도 대체값), JAVA_HOME, PROCESSOR,
                  MAXMEM(8G), MAXCPU, NO_DWARF(1), AGGRESSIVE(1), OVL_MAP.
  명시한 옵션이 환경변수보다 우선한다. JAVA_HOME 미지정 시 Ghidra가 Java를 선택한다.
  heap을 적용하기 위해 ELF 방식은 Ghidra support/launch.sh를 직접 호출한다.

기존 Ghidra 분석에서 BIN 형식의 목록만 추출
-------------------------------------------
  -scriptPath /path/to/tools
  -postScript ghidra_export_headless.py export /out/bin
  이는 Ghidra 내부 전용 모드다. 일반 Python에서 export만 실행할 수는 없다.

실패 처리
---------
  임시 프로젝트와 새 출력으로 검증한 뒤 결과를 저장한다. 분석 실패 시 기존
  결과를 성공으로 오인하지 않고 유지한다. ELF는 선택된 모든 코어가 완료된 뒤
  저장하며, 갱신 코어의 오래된 overlay 파일을 정리하고 다른 코어의 심볼은 유지한다.
  각 파일 교체는 원자적이지만 여러 파일 전체가 단일 트랜잭션인 것은 아니다.

이 파일은 Ghidra Jython에서도 읽으므로 Python 2.7 호환 문법을 유지한다.
호스트 전용 Python 3 모듈은 호스트 함수 안에서만 import한다.
"""
from __future__ import print_function

import os


def export_program(program, output_dir):
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    currentProgram = program
    OUTPUT_DIR = output_dir
    if not os.path.isdir(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    listing   = currentProgram.getListing()
    func_mgr  = currentProgram.getFunctionManager()
    prog_name = currentProgram.getName()
    print('[GhidraExport] start: ' + prog_name)
    print('[GhidraExport] output: ' + OUTPUT_DIR)

    bb_path  = os.path.join(OUTPUT_DIR, 'basic_blocks.txt')
    bb_model = BasicBlockModel(currentProgram)
    monitor  = ConsoleTaskMonitor()
    blocks   = bb_model.getCodeBlocks(monitor)
    bb_count = 0
    bb_skipped = 0
    f = open(bb_path, 'w')
    try:
        while blocks.hasNext():
            bb = blocks.next()
            bb_start = bb.getMinAddress()
            if listing.getInstructionAt(bb_start) is None:
                bb_skipped += 1
                continue
            start = bb_start.getOffset()
            end   = bb.getMaxAddress().getOffset() + 1
            f.write('0x{:08x} 0x{:08x}\n'.format(start, end))
            bb_count += 1
            if bb_count % 50000 == 0:
                print('  [1] basic blocks: {:,} ...'.format(bb_count))
    finally:
        f.close()
    print('[1] basic blocks: {:,} (skipped {:,} non-code) -> {}'.format(bb_count, bb_skipped, bb_path))

    func_path = os.path.join(OUTPUT_DIR, 'functions.txt')
    func_count = 0
    func_skipped = 0
    f = open(func_path, 'w')
    try:
        for fn in func_mgr.getFunctions(True):
            size = fn.getBody().getNumAddresses()
            if fn.isExternal() or size == 0:
                func_skipped += 1
                continue
            entry = fn.getEntryPoint().getOffset()
            name  = fn.getName()
            f.write('0x{:08x} {} {}\n'.format(entry, size, name))
            func_count += 1
    finally:
        f.close()
    print('[2] functions: {:,} (skipped {:,} external/empty) -> {}'.format(func_count, func_skipped, func_path))
    print('[GhidraExport] done.')


def export_args(args):
    args = list(args)
    if args and args[0] == 'export':
        args = args[1:]
    if len(args) > 1:
        raise ValueError('Ghidra usage: export OUTDIR (or legacy OUTDIR)')
    return args[0] if args else '/home/ssd/ghidra_export'


def overlay_sections(spec, label):
    """Merge section -> overlay mappings; accept JSON keys or named region objects."""
    import glob
    import json
    import re
    from pathlib import Path
    sections = {}
    def walk(obj, region=None):
        if isinstance(obj, list):
            for item in obj:
                walk(item, region)
        elif isinstance(obj, dict):
            # A list entry may name its region in 'name', 'region', etc.
            names = [v for v in obj.values() if isinstance(v, str)
                     and re.match(r'^\.?OVL_REGION_[0-9]+$', v)]
            if names:
                region = int(names[0].rsplit('_', 1)[1])
            if region is not None and 'section_index' in obj:
                si = int(obj['section_index'])
                if si in sections and sections[si] != region:
                    raise ValueError('conflicting overlay regions for section {}'.format(si))
                sections[si] = region
            for key, value in obj.items():
                match = re.match(r'^\.?OVL_REGION_([0-9]+)$', key)
                walk(value, int(match.group(1)) if match else region)
    for pattern in (spec or '').replace('{label}', label).split(','):
        if not pattern.strip():
            continue
        matches = sorted(glob.glob(pattern.strip()))
        if not matches:
            print('Overlay map not found for core {} (skipped): {}'.format(label, pattern))
            continue
        for name in matches:
            with Path(name).open() as src:
                walk(json.load(src))
    return sections


def export_filemap(elf, label, out, sections, env):
    import subprocess
    # ELF FILE symbols only scope subsequent LOCAL functions, never GLOBAL ones.
    result = subprocess.run(['readelf', '-sW', str(elf)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode:
        raise ValueError('readelf failed: ' + result.stderr.strip())
    rows = {'': []}
    source = ''
    for line in result.stdout.splitlines():
        if line.lstrip().startswith('Symbol table '):
            source = ''
        cols = line.split(None, 7)
        if len(cols) < 8:
            continue
        _, value, size, kind, bind, vis, ndx, name = cols
        if kind == 'FILE':
            source = name
        elif kind == 'FUNC' and bind == 'LOCAL' and source:
            region = sections.get(int(ndx)) if ndx.isdigit() else None
            suffix = '_ovl{}'.format(region) if region is not None else ''
            rows.setdefault(suffix, []).append('0x{} {}\n'.format(value, source))
    for suffix, lines in rows.items():
        (out / ('filemap_core' + label + suffix + '.txt')).write_text(''.join(lines))
    for region in set(sections.values()):
        for prefix in ('basic_blocks', 'functions'):
            path = out / ('{}_core{}_ovl{}.txt'.format(prefix, label, region))
            if not path.exists():
                path.write_text('')


def analyze_symbols(args):
    """Host-only ELF launcher. Java retains Ghidra analysis/overlay export logic."""
    import re
    import json
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path
    src = Path(args.source).resolve()
    out = Path(args.outdir).resolve()
    scripts = Path(args.script_dir).resolve() if args.script_dir else Path(__file__).resolve().parent
    java_script = scripts / 'GhidraExportMaps.java'
    launcher = Path(args.ghidra).resolve() / 'support' / 'launch.sh'
    if not java_script.is_file():
        raise ValueError('GhidraExportMaps.java missing: ' + str(scripts))
    if not launcher.is_file() or not os.access(str(launcher), os.X_OK):
        raise ValueError('Ghidra launch.sh not executable: ' + str(launcher))
    if not re.match(r'^[1-9][0-9]*[kKmMgG]?$', args.maxmem):
        raise ValueError('--maxmem must be a positive heap size such as 16G')
    if args.maxcpu is not None and args.maxcpu <= 0:
        raise ValueError('--maxcpu must be positive')
    if args.core == 'all':
        if not src.is_dir():
            raise ValueError('all requires an ELF directory')
        jobs = [(p, p.name[3:-8]) for p in sorted(src.glob('FW_*Core.elf'))]
        if not jobs:
            raise ValueError('no FW_*Core.elf in ' + str(src))
    else:
        jobs = [(src, args.core)]
    env = os.environ.copy()
    if args.java_home:
        env['JAVA_HOME'] = args.java_home
        env['PATH'] = str(Path(args.java_home) / 'bin') + os.pathsep + env.get('PATH', '')
    prepared = []
    for elf, label in jobs:
        if not re.match(r'^[A-Za-z0-9_-]+$', label):
            raise ValueError('invalid core label: ' + label)
        if not elf.is_file():
            raise ValueError('ELF not found: ' + str(elf))
        pc = None
        if args.pc_list:
            pc = Path(args.pc_list).resolve()
            if args.core == 'all':
                pc = pc / ('pcsr_core' + label + '.txt')
                if not pc.is_file():
                    print('No PC seed for core {}: {}'.format(label, pc))
                    pc = None
            elif not pc.is_file():
                raise ValueError('PC seed not found: ' + str(pc))
        sections = overlay_sections(args.overlay_map, label) if args.core != 'ovlinfo' else {}
        prepared.append((elf, label, pc, sections))
    with tempfile.TemporaryDirectory(prefix='fw2export-symbols-') as tmp:
        stage = Path(tmp) / 'export'
        stage.mkdir()
        # Preserve fragments for other cores when refreshing one or a subset of cores.
        labels = {label for _, label, _, _ in prepared}
        if out.is_dir():
            for frag in out.glob('symbols_core*.json'):
                if frag.name[len('symbols_core'):-len('.json')] not in labels:
                    shutil.copyfile(str(frag), str(stage / frag.name))
        for index, (elf, label, pc, sections) in enumerate(prepared):
            project = Path(tmp) / ('project-' + str(index))
            project.mkdir()
            # Invoke launch.sh directly: analyzeHeadless can override MAXMEM to 2G.
            cmd = [str(launcher), 'fg', 'jdk', 'Ghidra-Headless', args.maxmem,
                   '-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djava.awt.headless=true',
                   'ghidra.app.util.headless.AnalyzeHeadless', str(project), 'cov',
                   '-import', str(elf), '-scriptPath', str(scripts),
                   '-preScript', 'GhidraExportMaps.java', 'pre']
            if args.no_dwarf == '1':
                cmd.append('nodwarf')
            if args.aggressive == '1':
                cmd.append('aggressive')
            cmd += ['-postScript', 'GhidraExportMaps.java', label]
            if label != 'ovlinfo':
                cmd.append(str(stage))
                if pc:
                    cmd.append(str(pc))
            cmd.append('-deleteProject')
            if args.processor:
                cmd += ['-processor', args.processor]
            if args.maxcpu is not None:
                cmd += ['-max-cpu', str(args.maxcpu)]
            print('ELF: {} | core: {} | heap: {}'.format(elf, label, args.maxmem))
            result = subprocess.run(cmd, env=env)
            if result.returncode:
                return result.returncode if result.returncode > 0 else 1
            if label == 'ovlinfo':
                continue
            required = ['callgraph_core' + label + '.txt', 'symbols_core' + label + '.json', 'symbols.json']
            for name in required:
                if not (stage / name).is_file():
                    raise ValueError('fresh export missing: ' + name)
            with (stage / ('symbols_core' + label + '.json')).open() as inp:
                fragment = json.load(inp)
            for prefix, count in (('basic_blocks', 'basic_blocks_resident'), ('functions', 'functions_resident')):
                path = stage / (prefix + '_core' + label + '.txt')
                if not path.exists():
                    if fragment.get('counts', {}).get(count) != 0:
                        raise ValueError('resident export missing: ' + path.name)
                    path.write_text('')  # Java omits empty buckets, including overlay-only images.
            export_filemap(elf, label, stage, sections, env)
        if args.core == 'ovlinfo':
            return 0
        out.mkdir(parents=True, exist_ok=True)
        # All selected cores completed before old overlay files are removed/published.
        for label in labels:
            for prefix in ('basic_blocks', 'functions', 'filemap'):
                for old in out.glob(prefix + '_core' + label + '_ovl*.txt'):
                    if not (stage / old.name).exists():
                        old.unlink()
        for fresh in sorted(stage.iterdir()):
            fd, temp = tempfile.mkstemp(prefix='.' + fresh.name, dir=str(out))
            try:
                with os.fdopen(fd, 'wb') as dst, fresh.open('rb') as inp:
                    shutil.copyfileobj(inp, dst)
                os.replace(temp, str(out / fresh.name))
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
        print('DONE: {} core(s) -> {}'.format(len(jobs), out))
    return 0


def main(argv=None):
    import argparse
    import shutil
    import subprocess
    import sys
    import tempfile
    from pathlib import Path

    def number(value):
        try:
            n = int(value, 16 if value.lower().startswith('0x') else 10)
        except ValueError:
            raise argparse.ArgumentTypeError('expected a decimal or hexadecimal integer')
        if n < 0:
            raise argparse.ArgumentTypeError('must be non-negative')
        return n

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    modes = ap.add_subparsers(dest='mode')
    run = modes.add_parser('analyze', help='import firmware, analyze and export coverage')
    run.add_argument('firmware')
    run.add_argument('outdir', nargs='?')
    run.add_argument('--ghidra', default=os.environ.get('GHIDRA', '/home/ssd/ghidra_12.0.1_PUBLIC'))
    run.add_argument('--java-home', default=os.environ.get('JAVA_HOME'))
    run.add_argument('--processor', default=os.environ.get('PROC', 'ARM:LE:32:v7'))
    run.add_argument('--base', type=number, default=os.environ.get('BASE', '0x0'))
    run.add_argument('--cut', type=number, default=os.environ.get('CUT', '0x0'))
    run.add_argument('--loader', default=os.environ.get('LOADER', 'BinaryLoader'))
    run.add_argument('--analysis-timeout', type=number, default=7200)
    run.add_argument('--match-gui', action='store_true', default=os.environ.get('MATCH_GUI') == '1')
    run.add_argument('--script-dir', help='directory containing optional match_gui.py')
    modes.add_parser('export', help='Ghidra-only mode: use as a postScript').add_argument('outdir', nargs='?')
    symbols = modes.add_parser('symbols', help='ELF symbols, per-core coverage and overlays')
    symbols.add_argument('source', help='ELF file, or directory for all')
    symbols.add_argument('core', help='core label, all, or ovlinfo')
    symbols.add_argument('outdir')
    symbols.add_argument('pc_list', nargs='?', help='PC seed file, or directory for all')
    symbols.add_argument('--ghidra', default=os.environ.get('GHIDRA_HOME', os.environ.get('GHIDRA', '/home/ssd/ghidra_12.0.1_PUBLIC')))
    symbols.add_argument('--java-home', default=os.environ.get('JAVA_HOME'))
    symbols.add_argument('--processor', default=os.environ.get('PROCESSOR', 'RISCV:LE:32:default'))
    symbols.add_argument('--maxmem', default=os.environ.get('MAXMEM', '8G'))
    symbols.add_argument('--maxcpu', type=number, default=os.environ.get('MAXCPU') or None)
    symbols.add_argument('--no-dwarf', choices=('0', '1'), default=os.environ.get('NO_DWARF', '1'))
    symbols.add_argument('--aggressive', choices=('0', '1'), default=os.environ.get('AGGRESSIVE', '1'))
    symbols.add_argument('--overlay-map', default=os.environ.get('OVL_MAP', ''))
    symbols.add_argument('--script-dir', help='directory containing GhidraExportMaps.java')
    args = ap.parse_args(argv)
    if args.mode == 'symbols':
        try:
            return analyze_symbols(args)
        except KeyboardInterrupt:
            print('Interrupted', file=sys.stderr)
            return 130
        except (OSError, ValueError) as exc:
            print('Symbol export failed: ' + str(exc), file=sys.stderr)
            return 1
    if args.mode != 'analyze':
        ap.error('use analyze or symbols on Python 3; export requires a loaded program inside Ghidra')
    firmware = Path(args.firmware).resolve()
    if not firmware.is_file():
        ap.error('firmware not found: ' + str(firmware))
    if args.cut >= firmware.stat().st_size:
        ap.error('--cut must leave at least one byte of firmware')
    if args.analysis_timeout <= 0:
        ap.error('--analysis-timeout must be positive')
    headless = Path(args.ghidra).resolve() / 'support' / 'analyzeHeadless'
    if not headless.is_file() or not os.access(str(headless), os.X_OK):
        ap.error('analyzeHeadless is not executable: ' + str(headless))
    script = Path(__file__).resolve()
    extra = Path(args.script_dir).resolve() if args.script_dir else script.parent
    if args.match_gui and not (extra / 'match_gui.py').is_file():
        ap.error('--match-gui requires match_gui.py in --script-dir or beside this script')
    out = Path(args.outdir or ('./' + firmware.stem)).resolve()
    env = os.environ.copy()
    if args.java_home:
        env['JAVA_HOME'] = args.java_home
        env['PATH'] = str(Path(args.java_home) / 'bin') + os.pathsep + env.get('PATH', '')
    try:
        # Project and fresh output staging are cleaned even on failure or Ctrl+C.
        # Old output must never make a failed export look successful.
        with tempfile.TemporaryDirectory(prefix='fw2export-') as scratch:
            project = Path(scratch) / 'project'
            project.mkdir()
            staged = Path(scratch) / 'export'
            staged.mkdir()
            imported = firmware
            if args.cut:
                imported = Path(scratch) / (firmware.name + '.cut')
                with firmware.open('rb') as src, imported.open('wb') as dst:
                    src.seek(args.cut)
                    shutil.copyfileobj(src, dst)
            script_path = str(script.parent)
            if extra != script.parent:
                script_path += ';' + str(extra)
            cmd = [str(headless), str(project), 'fwproj', '-import', str(imported),
                   '-loader', args.loader, '-loader-baseAddr', hex(args.base),
                   '-processor', args.processor, '-scriptPath', script_path]
            if args.match_gui:
                cmd += ['-preScript', 'match_gui.py']
            cmd += ['-postScript', script.name, 'export', str(staged), '-deleteProject',
                    '-analysisTimeoutPerFile', str(args.analysis_timeout)]
            print('FW: {} | processor: {} | base: {} | cut: {}'.format(
                firmware, args.processor, hex(args.base), args.cut))
            result = subprocess.run(cmd, env=env)
            if result.returncode:
                print('Analysis failed (rc={})'.format(result.returncode), file=sys.stderr)
                return result.returncode if result.returncode > 0 else 1
            bb = staged / 'basic_blocks.txt'
            funcs = staged / 'functions.txt'
            if not bb.is_file() or bb.stat().st_size == 0 or not funcs.is_file():
                print('Export failed: fresh basic_blocks.txt/functions.txt missing or no code blocks', file=sys.stderr)
                return 1
            out.mkdir(parents=True, exist_ok=True)
            for src in (bb, funcs):
                # Replace on the destination filesystem (out may be a different mount).
                fd, tmp = tempfile.mkstemp(prefix='.' + src.name, dir=str(out))
                try:
                    with os.fdopen(fd, 'wb') as dst, src.open('rb') as inp:
                        shutil.copyfileobj(inp, dst)
                    os.replace(tmp, str(out / src.name))
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
            print('DONE: ' + str(out))
            return 0
    except KeyboardInterrupt:
        print('Interrupted', file=sys.stderr)
        return 130
    except OSError as exc:
        print('Export failed: ' + str(exc), file=sys.stderr)
        return 1


if 'currentProgram' in globals() and 'getScriptArgs' in globals():
    export_program(currentProgram, export_args(getScriptArgs()))
elif __name__ == '__main__':
    import sys
    sys.exit(main())
