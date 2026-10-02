"""ELF launcher compatibility with mocked Ghidra/readelf; no hardware access."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
SCRIPT = TOOLS / 'ghidra_export_headless.py'


class SymbolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='symbols test ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.install = self.root / 'ghidra'
        (self.install / 'support').mkdir(parents=True)
        self.log = self.root / 'calls.jsonl'
        launch = self.install / 'support' / 'launch.sh'
        launch.write_text('''#!/usr/bin/env python3
import os,sys,json
from pathlib import Path
a=sys.argv[1:]
with open(os.environ['CALL_LOG'],'a') as f:f.write(json.dumps(a)+'\\n')
i=a.index('-postScript');label=a[i+2]
if os.environ.get('FAIL_CORE')==label:sys.exit(7)
if label=='ovlinfo':sys.exit(0)
out=Path(a[i+3]); zero=os.environ.get('OVERLAY_ONLY')=='1'
counts={'basic_blocks_resident':0 if zero else 1,'functions_resident':0 if zero else 1}
for prefix in ('basic_blocks','functions','callgraph'):
 if zero and prefix!='callgraph':continue
 (out/(prefix+'_core'+label+'.txt')).write_text('0x10 0x20\\n')
(out/('symbols_core'+label+'.json')).write_text(json.dumps({'counts':counts}))
cores={p.stem[len('symbols_core'):]:json.loads(p.read_text()) for p in out.glob('symbols_core*.json')}
(out/'symbols.json').write_text(json.dumps({'cores':cores}))
''')
        launch.chmod(0o755)
        bindir = self.root / 'bin'; bindir.mkdir()
        readelf = bindir / 'readelf'
        readelf.write_text('''#!/usr/bin/env python3
print("Symbol table '.symtab' contains 4 entries:")
print('1: 00000000 0 FILE LOCAL DEFAULT ABS source.c')
print('2: 00000010 16 FUNC LOCAL DEFAULT 3 resident')
print('3: 00000020 16 FUNC LOCAL DEFAULT 9 overlay')
print('4: 00000030 16 FUNC GLOBAL DEFAULT 3 global_fn')
''')
        readelf.chmod(0o755)
        self.elfdir = self.root / 'ELFs'; self.elfdir.mkdir()
        for label in ('H', 'F'):
            (self.elfdir / ('FW_' + label + 'Core.elf')).write_bytes(b'fake elf')
        self.out = self.root / 'output'
        self.env = dict(os.environ, CALL_LOG=str(self.log), GHIDRA_HOME=str(self.install),
                        MAXMEM='16G', PATH=str(bindir)+os.pathsep+os.environ['PATH'])
        for key in ('OVL_MAP','MAXCPU','PROCESSOR','JAVA_HOME','NO_DWARF','AGGRESSIVE'):
            self.env.pop(key, None)
        for label in ('H', 'F'):
            (self.root / ('FW_'+label+'Core_overlay_map.json')).write_text(
                json.dumps({'regions': {'.OVL_REGION_04': {'section_index': 9}}}))
        self.env['OVL_MAP'] = str(self.root / 'FW_*{label}Core_overlay_map.json')

    def run_export(self, core='all', *flags):
        source = self.elfdir if core=='all' else self.elfdir / 'FW_HCore.elf'
        cmd = [sys.executable,str(SCRIPT),'symbols']
        return subprocess.run(cmd+[str(source),core,str(self.out)]+list(flags),env=self.env,
                              capture_output=True,text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_all_cores_legacy_env_overlay_and_pc_seed(self):
        pcs = self.root / 'PCs'; pcs.mkdir()
        (pcs/'pcsr_coreH.txt').write_text('0x10')
        result = self.run_export('all', str(pcs), '--maxcpu','3')
        self.assertEqual(result.returncode,0,result.stderr)
        calls = self.calls(); self.assertEqual(len(calls),2)
        for call in calls:
            self.assertEqual(call[3],'16G')
            self.assertIn('nodwarf',call);self.assertIn('aggressive',call)
            self.assertEqual(call[call.index('-max-cpu')+1],'3')
            self.assertFalse(Path(call[6]).exists())
        self.assertIn(str(pcs/'pcsr_coreH.txt'), calls[1])
        for label in ('H','F'):
            self.assertEqual((self.out/('filemap_core'+label+'.txt')).read_text(),'0x00000010 source.c\n')
            self.assertEqual((self.out/('filemap_core'+label+'_ovl4.txt')).read_text(),'0x00000020 source.c\n')
            self.assertTrue((self.out/('basic_blocks_core'+label+'_ovl4.txt')).exists())
        self.assertEqual(set(json.loads((self.out/'symbols.json').read_text())['cores']),{'H','F'})

    def test_missing_map_does_not_inherit_previous_core_sections(self):
        (self.root/'FW_HCore_overlay_map.json').unlink()
        result=self.run_export()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.out/'filemap_coreH_ovl4.txt').exists())
        self.assertIn('0x00000020 source.c', (self.out/'filemap_coreH.txt').read_text())
        self.assertTrue((self.out/'filemap_coreF_ovl4.txt').exists())

    def test_failed_batch_keeps_old_output_and_cleans_projects(self):
        self.out.mkdir(); old=self.out/'basic_blocks_coreH_ovl9.txt';old.write_text('old')
        self.env['FAIL_CORE']='H'
        result=self.run_export()
        self.assertEqual(result.returncode,7,result.stderr)
        self.assertEqual(old.read_text(),'old')
        self.assertEqual(list(self.out.iterdir()),[old])
        for call in self.calls(): self.assertFalse(Path(call[6]).exists())

    def test_single_core_preserves_other_fragments_removes_stale_overlays(self):
        self.out.mkdir()
        (self.out/'symbols_coreF.json').write_text('{"counts":{}}')
        stale=self.out/'functions_coreH_ovl99.txt';stale.write_text('old')
        result=self.run_export('H','--processor','','--no-dwarf','0','--maxmem','12G')
        self.assertEqual(result.returncode,0,result.stderr)
        call=self.calls()[0]
        self.assertNotIn('-processor',call);self.assertNotIn('nodwarf',call)
        self.assertEqual(call[3],'12G');self.assertFalse(stale.exists())
        self.assertEqual(set(json.loads((self.out/'symbols.json').read_text())['cores']),{'H','F'})

    def test_overlay_diagnostic_and_overlay_only_export(self):
        result=self.run_export('ovlinfo')
        self.assertEqual(result.returncode,0,result.stderr);self.assertFalse(self.out.exists())
        self.env['OVERLAY_ONLY']='1'
        result=self.run_export('H')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.out/'basic_blocks_coreH.txt').read_text(),'')

    def test_maps_are_isolated_and_compact_json_merges(self):
        spec=importlib.util.spec_from_file_location('maps',SCRIPT)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        a=self.root/'a.json'; b=self.root/'b.json'
        a.write_text('{"OVL_REGION_01":{"section_index":3},"OVL_REGION_02":{"section_index":9}}')
        b.write_text('{"regions":[{"name":"OVL_REGION_03","section_index":10}]}')
        self.assertEqual(module.overlay_sections(str(a)+','+str(b),'H'),{3:1,9:2,10:3})
        self.assertEqual(module.overlay_sections('', 'F'),{})
        b.write_text('{"OVL_REGION_03":{"section_index":9}}')
        with self.assertRaises(ValueError):module.overlay_sections(str(a)+','+str(b),'H')
