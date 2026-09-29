"""Read-only Linux capability discovery for v11 exception preflight.

PCIe Base 5.0 §§6.6.1/6.6.2: warm reset is a powered fundamental reset;
REFCLK switching is not a portable software reset primitive. FLR is optional,
link-preserving; hot reset is a distinct bus/link operation. Never label an
arbitrary sysfs reset as FLR or silently substitute another method.
"""
import json
from pathlib import Path
import re


BDF = re.compile(r'^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$')


def gpio_value(raw):
    text = raw.decode(errors='replace') if isinstance(raw, bytes) else str(raw)
    # User's PMU v4.1 example: [GetGpio][OK]D1] 1. Reject ambiguous reads.
    values = re.findall(r'^\s*\[GetGpio\]\[OK\]D1\]\s*([01])\s*$', text, re.M)
    if len(values) != 1:
        raise ValueError('GetGpio did not return exactly one D1 digital value')
    return int(values[0])


def register_value(output, name):
    value = json.loads(output)[name]
    if isinstance(value, str):
        value = int(value, 16) if value.lower().startswith('0x') or re.search('[a-fA-F]', value) else int(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f'invalid {name} register')
    return value


def pci_method_support(bdf, method, root=Path('/sys/bus/pci/devices')):
    if not BDF.fullmatch(bdf):
        return 'UNCONFIGURED', 'invalid PCI BDF'
    device = root / bdf
    try:
        methods = (device / 'reset_method').read_text().split()
    except OSError as exc:
        return 'UNSUPPORTED', f'reset_method unavailable: {exc}'
    if method not in methods or not (device / 'reset').exists():
        return 'UNSUPPORTED', f'{method} not in enabled kernel reset methods: {methods}'
    if method == 'bus':
        # A bus reset affects siblings. In the first implementation, do not
        # widen a single-DUT test to another endpoint or bridge downstream.
        parent = device.resolve().parent
        peers = sorted(p.name for p in parent.iterdir() if BDF.fullmatch(p.name))
        if peers != [bdf]:
            return 'UNSUPPORTED', f'bus reset scope is not a single DUT: {peers}'
    return 'AVAILABLE', f'kernel reset_method={method}; driver callbacks coordinate reinitialization'


def subsystem_support(cap, bdf, root=Path('/sys/class/nvme')):
    if not cap & (1 << 36):  # NVMe CAP.NSSRS (NSSRC in Linux headers)
        return 'UNSUPPORTED', 'CAP.NSSRS=0'
    # Match the DUT by BDF, then conservatively bound scope by visible NQNs.
    # Duplicate placeholder NQNs may exclude a supported device; never widen scope.
    found = []
    for ctrl in root.glob('nvme[0-9]*'):
        try:
            if (ctrl / 'address').read_text().strip() == bdf:
                found.append(ctrl)
        except OSError:
            continue
    if len(found) != 1:
        return 'UNCONFIGURED', 'cannot resolve subsystem membership for DUT'
    try:
        subsystem = (found[0] / 'subsysnqn').read_text().strip()
        members = []
        for ctrl in root.glob('nvme[0-9]*'):
            if (ctrl / 'subsysnqn').read_text().strip() == subsystem:
                members.append(ctrl.name)
    except OSError as exc:
        return 'UNCONFIGURED', f'cannot establish subsystem scope: {exc}'
    # Equal NQNs are conservatively considered shared; no cross-DUT operation.
    if len(members) != 1:
        return 'UNSUPPORTED', f'subsystem scope includes multiple controllers: {members}'
    return 'AVAILABLE', 'CAP.NSSRS=1; single visible controller in subsystem'
