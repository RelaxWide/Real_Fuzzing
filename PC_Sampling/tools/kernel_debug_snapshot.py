#!/usr/bin/env python3
"""Compare working/failing kernel environments without opening NVMe or J-Link.

Collect sysfs settings, PCI configuration (lspci), kernel options and local
debug-library identities. Does not send NVMe commands, authenticate, reset,
unbind, change power settings, or read sjtag_addrs.json.
"""
import argparse
import ctypes.util
import difflib
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
POWER = ('control', 'runtime_status', 'autosuspend_delay_ms',
         'runtime_enabled', 'pm_qos_latency_tolerance_us')
BDF = re.compile(r'^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$')


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError as exc:
        return '<unavailable: %s>' % exc.strerror


def command(argv):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=15,
                                env=dict(os.environ, LC_ALL='C'))
        return dict(rc=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return dict(error=str(exc))


def identity(path):
    p = Path(path)
    try:
        h = hashlib.sha256()
        with p.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(block)
        return dict(path=str(p.resolve()), sha256=h.hexdigest())
    except OSError as exc:
        return dict(path=str(p), error=str(exc))


def power(path):
    return {name: read(path / 'power' / name) for name in POWER
            if (path / 'power' / name).exists()}


def ancestry(path):
    rows = {}
    for p in (path,) + tuple(path.parents):
        if not str(p).startswith('/sys/devices/'):
            continue
        row = dict(power=power(p))
        if (p / 'driver').is_symlink():
            row['driver'] = (p / 'driver').resolve().name
        if BDF.fullmatch(p.name):
            row['pci'] = command(['lspci', '-D', '-vv', '-s', p.name])
        if row['power'] or 'pci' in row:
            rows[str(p)] = row
    return rows


def collect(nvme):
    ctrl = Path('/sys/class/nvme') / nvme
    if not ctrl.exists():
        raise ValueError('%s missing; use the DUT controller name visible in this boot' % ctrl)
    data = dict(kernel=platform.release(), cmdline=read('/proc/cmdline'),
                python=dict(version=sys.version, executable=sys.executable),
                controller={k: read(ctrl / k) for k in ('address', 'model', 'firmware_rev', 'state')},
                controller_path=ancestry(ctrl.resolve()), modules={}, usb={}, files={})
    for module in ('pcie_aspm', 'pcie_portdrv', 'nvme_core', 'nvme',
                   'usbcore', 'xhci_hcd', 'intel_idle', 'processor'):
        params = Path('/sys/module') / module / 'parameters'
        data['modules'][module] = {p.name: read(p) for p in sorted(params.glob('*')) if p.is_file()}
    for p in sorted(Path('/sys/bus/usb/devices').glob('*')):
        if read(p / 'idVendor').lower() != '1366':
            continue
        data['usb'][p.name] = dict(
            attributes={k: read(p / k) for k in ('idVendor', 'idProduct', 'product', 'speed', 'version')},
            ancestry=ancestry(p.resolve()))
    for name in ('ap_write_probe.py', 'sfe76_link.py', 'dap_access.py', 'sjtag_unlock.py'):
        data['files'][name] = identity(ROOT / 'risc-v' / name)
    try:
        from importlib import metadata
        package = metadata.distribution('pylink-square')
        data['pylink'] = dict(version=package.version, path=str(package.locate_file('')))
    except ImportError:
        # Python 3.7 fallback, without importing pylink or opening a probe.
        data['pylink'] = dict(error='importlib.metadata unavailable')
    except Exception as exc:
        data['pylink'] = dict(error=str(exc))
    data['jlink_library_lookup'] = ctypes.util.find_library('jlinkarm')
    data['library_environment'] = {k: os.environ.get(k) for k in ('LD_LIBRARY_PATH', 'PYTHONPATH')}
    libraries = set()
    for directory in ('/opt/SEGGER', '/usr/lib', '/usr/local/lib'):
        base = Path(directory)
        pattern = '**/libjlinkarm.so*' if directory == '/opt/SEGGER' else 'libjlinkarm.so*'
        libraries.update(p.resolve() for p in base.glob(pattern) if p.is_file())
    for directory in ('/usr/lib/x86_64-linux-gnu', '/usr/lib/aarch64-linux-gnu'):
        libraries.update(p.resolve() for p in Path(directory).glob('libjlinkarm.so*') if p.is_file())
    data['jlink_libraries'] = [identity(p) for p in sorted(libraries)]
    config = Path('/boot/config-' + platform.release())
    try:
        if config.exists():
            config_text = config.read_text()
        else:
            with gzip.open('/proc/config.gz', 'rt') as stream:
                config_text = stream.read()
        data['kernel_config'] = [line for line in config_text.splitlines()
            if re.match(r'^(# )?CONFIG_(PCIE|PCI_|PM|USB|IOMMU|INTEL_IOMMU|AMD_IOMMU|NVME|BLK_DEV_NVME)', line)]
    except OSError as exc:
        data['kernel_config'] = dict(error=str(exc))
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nvme', default='nvme0', help='DUT controller name, not namespace')
    parser.add_argument('--out', help='new JSON output file (will not overwrite)')
    parser.add_argument('--compare', nargs=2, metavar=('WORKING', 'FAILING'))
    args = parser.parse_args()
    if args.compare:
        if args.out:
            parser.error('--compare and --out cannot be combined')
        try:
            records = [json.loads(Path(p).read_text()) for p in args.compare]
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        text = [json.dumps(r, ensure_ascii=False, indent=2, sort_keys=True).splitlines(True) for r in records]
        sys.stdout.writelines(difflib.unified_diff(*text, fromfile=args.compare[0], tofile=args.compare[1]))
        return 0
    if not args.out or not re.fullmatch(r'nvme[0-9]+', args.nvme):
        parser.error('use --out FILE and --nvme nvmeN')
    if Path(args.out).exists():
        parser.error('output exists; choose a new file name')
    try:
        data = collect(args.nvme)
        with open(args.out, 'x') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write('\n')
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print('Saved %s (kernel %s); J-Link USB devices: %d' %
          (args.out, data['kernel'], len(data['usb'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
