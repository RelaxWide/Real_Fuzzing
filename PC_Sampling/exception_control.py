"""v11 exception scheduling and finite, partially repeatable test profiles.

No hardware is touched on import. A profile is prefix + repeated body + suffix;
only the body repeats (e.g. preparation, PERST pulses, then normal completion).
The main thread owns the event while nvme-cli is already running. This overlaps
I/O without a second thread racing PM, recovery, the next command, or Ctrl+C.
Actual device-internal overlap is NOT implied by a live nvme-cli PID.
"""
from dataclasses import dataclass
import json
import math
from pathlib import Path
import random
import re
import subprocess
import tempfile
import sys
from exception_probe import gpio_value, register_value, pci_method_support, subsystem_support
import time


BUILTIN_EFFECTS = {
    'controller_reset': 'none', 'nssr': 'none', 'flr': 'none', 'hot_reset': 'none',
    'pci_remove': 'none', 'pci_rescan': 'none',
    'power_off': 'power_off', 'power_on': 'power_on', 'wait': 'none',
}


def action_effect(action, adapters):
    return BUILTIN_EFFECTS.get(action, adapters.get(action, {}).get('effect', 'none'))


class ExceptionFailure(RuntimeError):
    pass


def number(value, name, minimum=0.0):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f'{name}: finite number required')
    if not math.isfinite(value) or value < minimum:
        raise ValueError(f'{name}: must be >= {minimum}')
    return float(value)


def config_value(config, path):
    value = config
    for key in path.split('.'):
        value = value[key]
    return number(value, path, 0.001)


@dataclass(frozen=True)
class Profile:
    name: str
    steps: tuple
    timeout_sec: float
    ready_timeout_sec: float


def compile_profiles(options, config):
    """Validate all profiles before touching a device; never infer PMU GPIOs.

    `ready_timeout_ref` points to an EXISTING JSON value in seconds, rather
    than copying a POR requirement into a second setting that can diverge.
    """
    number(options.get('resume_timeout_sec', 30), 'resume_timeout_sec', 0.001)
    number(options.get('recovery_observation_sec', 0), 'recovery_observation_sec')
    count = options.get('recovery_observation_commands', 1)
    if type(count) is not int or not 0 <= count <= 10000:
        raise ValueError('recovery_observation_commands must be 0..10000')
    preflight = options.get('preflight', {})
    if not isinstance(preflight, dict) or type(preflight.get('enabled', True)) is not bool:
        raise ValueError('exceptions.preflight must be an object with boolean enabled')
    attempts = preflight.get('attempts_per_kind', 1)
    if type(attempts) is not int or not 1 <= attempts <= 10:
        raise ValueError('preflight.attempts_per_kind must be 1..10')
    adapters = options.get('adapters', {})
    if not isinstance(adapters, dict):
        raise ValueError('exceptions.adapters must be an object')
    for name, adapter in adapters.items():
        if name in BUILTIN_EFFECTS:
            raise ValueError(f'reserved adapter: {name}')
        argv = adapter.get('argv') if isinstance(adapter, dict) else None
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            raise ValueError(f'adapter {name}: nonempty argv array required (no shell)')
        check = adapter.get('readback')
        if check is not None:
            if (not isinstance(check, dict) or type(check.get('expected')) is not int
                    or check['expected'] not in (0, 1)
                    or not isinstance(check.get('argv'), list) or not check['argv']
                    or not all(isinstance(x, str) and x for x in check['argv'])):
                raise ValueError(f'adapter {name}: invalid GPIO readback')
        if adapter.get('effect', 'none') not in ('none', 'power_off', 'power_on', 'assert', 'deassert'):
            raise ValueError(f'adapter {name}: invalid effect')
        for word in argv:
            # Explicit replacements only; arbitrary Python format expressions are not accepted.
            rest = word.replace('{device}', '').replace('{pmu_script}', '')
            if '{' in rest or '}' in rest:
                raise ValueError(f'adapter {name}: unsupported placeholder')
    profiles = []
    rows = options.get('profiles', [{'name': 'controller_reset',
        'body': [{'action': 'controller_reset'}], 'repeat': 1,
        'timeout_sec': 30, 'ready_timeout_sec': 30}])
    if not isinstance(rows, list) or not rows:
        raise ValueError('exceptions.profiles must be a nonempty list')
    names = set()
    for row in rows:
        name = row['name']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', name) or name in names:
            raise ValueError('profile names must be unique alphanumeric identifiers')
        names.add(name)
        repeat = row.get('repeat', 1)
        if isinstance(repeat, bool) or not isinstance(repeat, int) or not 1 <= repeat <= 10000:
            raise ValueError(f'{name}: repeat must be 1..10000')
        prefix, body, suffix = (row.get(key, []) for key in ('prefix', 'body', 'suffix'))
        if not all(isinstance(x, list) for x in (prefix, body, suffix)) or not body:
            raise ValueError(f'{name}: prefix/body/suffix arrays and nonempty body required')
        if len(prefix) + len(body) * repeat + len(suffix) > 10000:
            raise ValueError(f'{name}: too many expanded steps')
        steps = []
        powered, asserted = True, False
        for step in prefix + body * repeat + suffix:
            action = step['action']
            if action not in BUILTIN_EFFECTS and action not in adapters:
                raise ValueError(f'{name}: adapter {action!r} is not configured')
            hold = (config_value(config, step['hold_ref']) if 'hold_ref' in step else
                    number(step.get('hold_sec', 0), f'{name}.{action}.hold_sec'))
            effect = action_effect(action, adapters)
            if effect == 'power_off':
                powered = False
            elif effect == 'power_on':
                powered = True
            elif effect == 'assert':
                asserted = True
            elif effect == 'deassert':
                asserted = False
            steps.append((action, hold))
        if not powered or asserted:
            raise ValueError(f'{name}: profile must end powered ON and deasserted')
        effects = {action_effect(a, adapters) for a, _ in steps}
        cleanup = options.get('restore_actions', [])
        if not isinstance(cleanup, list) or any(a not in adapters and a not in BUILTIN_EFFECTS for a in cleanup):
            raise ValueError('restore_actions must name configured adapters')
        restore_effects = {action_effect(a, adapters) for a in cleanup}
        if 'power_off' in effects and 'power_on' not in restore_effects:
            raise ValueError(f'{name}: power_off requires a power_on restore action')
        if 'assert' in effects and 'deassert' not in restore_effects:
            raise ValueError(f'{name}: assert requires a deassert restore action')
        timeout = number(row.get('timeout_sec', 30), name + '.timeout_sec', 0.001)
        if sum(hold for _, hold in steps) >= timeout:
            raise ValueError(f'{name}: holds consume the entire profile deadline')
        if 'ready_timeout_ref' in row:
            ready = config_value(config, row['ready_timeout_ref'])
        elif 'power_off' in effects or 'power_on' in effects:
            raise ValueError(f'{name}: power profiles must reference existing POR timeout JSON key')
        else:
            ready = number(row.get('ready_timeout_sec', 30), name + '.ready_timeout_sec', 0.001)
        profiles.append(Profile(name, tuple(steps), timeout, ready))
    return profiles


class CommandRunner:
    """Bounded subprocess waits, including D-state. Never communicate() after kill.

    Reset/helper processes that exceed a deadline are retained and logged: a
    failed kill is not proof that a late hardware operation cannot still run.
    Such an event stops the campaign; it never queues a second reset behind it.
    """
    def __init__(self, emit):
        self.emit = emit
        self.pending = []

    def run(self, argv, deadline, *, supply_control=False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ExceptionFailure('deadline expired before helper launch')
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(argv, stdout=out, stderr=err, start_new_session=True)
            proc._exception_supply_control = supply_control
            try:
                proc.wait(timeout=remaining)
            except BaseException:
                self.pending.append(proc)
                self.emit('helper_pending', pid=proc.pid, argv=argv)
                raise
            out.seek(0)
            err.seek(0)
            stdout, stderr = out.read(65536), err.read(65536)
            self.emit('helper', pid=proc.pid, argv=argv, rc=proc.returncode,
                      stdout=stdout.decode(errors='replace'), stderr=stderr.decode(errors='replace'))
            return proc.returncode, stdout, stderr

    def has_pending(self, *, supply_only=False):
        return any(proc.poll() is None and
                   (not supply_only or getattr(proc, '_exception_supply_control', True))
                   for proc in self.pending)


def csts_ready(output):
    """nvme show-regs -o json: require RDY=1 and CFS=0; never parse prose."""
    data = json.loads(output)
    value = data.get('csts')
    if isinstance(value, str):
        value = int(value, 16) if re.search(r'[a-fA-F]|^0x', value) else int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xffffffff:
        raise ValueError('missing/invalid CSTS in nvme show-regs JSON')
    return bool(value & 1) and not bool(value & 2), value


class ExceptionController:
    def __init__(self, options, config, device, pmu_script, log_path, clock=time.monotonic):
        self.options = options
        self.config = config
        self.clock = clock
        self.profiles = compile_profiles(options, config)
        self.interval = 60 * number(options.get('min_interval_minutes', 5), 'min_interval_minutes')
        self.initial_delay = 60 * number(options.get('initial_delay_minutes', 5), 'initial_delay_minutes')
        self.delay = number(options.get('trigger_delay_ms', 0), 'trigger_delay_ms') / 1000
        self.cleanup_timeout = number(options.get('cleanup_timeout_sec', 10), 'cleanup_timeout_sec', 0.001)
        self.device = device
        self.pmu_script = pmu_script
        self.log_path = Path(log_path)
        self.rng = random.Random(options.get('seed', 0))
        self.next_at = float('inf')
        self.active = None
        self.serial = None
        self.bdf = None
        self.counter = 0
        self.powered = True
        self.asserted = False
        self.runner = CommandRunner(self.emit)
        self.last_result = None
        self.preflight_results = {}
        self.run_started = False

    def emit(self, phase, **fields):
        row = dict(event_id=self.active, phase=phase, monotonic=self.clock(), **fields)
        if phase in ('preflight', 'begin', 'resumed', 'preserved_failure', 'capture', 'restore_failed'):
            import logging
            logging.getLogger('pcfuzz').warning('[Exception] %s %s %s', self.active, phase,
                                                fields.get('reason', fields.get('profile', '')))
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(row, ensure_ascii=False, default=str) + '\n')

    def arm(self):
        ctrl = re.fullmatch(r'/dev/(nvme\d+)(?:n\d+)?', self.device)
        if not ctrl:
            raise ValueError('controller reset requires a local /dev/nvmeN controller')
        self.device = '/dev/' + ctrl[1]
        self.sysfs = Path('/sys/class/nvme') / ctrl[1]
        self.serial = (self.sysfs / 'serial').read_text().strip()
        self.bdf = (self.sysfs / 'address').read_text().strip()
        if not self.serial or not self.bdf:
            raise ValueError('cannot establish DUT identity')
        self.next_at = float('inf')
        self.emit('armed', serial=self.serial, bdf=self.bdf, device=self.device,
                  options=self.options, profiles=[vars(p) for p in self.profiles])

    def due(self):
        return bool(self.profiles) and self.active is None and self.clock() >= self.next_at

    def _action(self, action, deadline):
        if action == 'wait':
            return
        if action == 'controller_reset':
            argv = ['nvme', 'reset', self.device]
            effect = 'none'
        elif action == 'nssr':
            argv, effect = ['nvme', 'subsystem-reset', self.device], 'none'
        elif action in ('flr', 'hot_reset'):
            method = 'flr' if action == 'flr' else 'bus'
            status, reason = pci_method_support(self.bdf, method)
            if status != 'AVAILABLE':
                raise ExceptionFailure(reason)
            # Keep method selection + reset + restoration in one bounded child.
            # Kernel PCI reset invokes NVMe reset_prepare/reset_done callbacks.
            program = ("import pathlib,sys; p=pathlib.Path(sys.argv[1]); "
                       "m=p/'reset_method'; old=m.read_text(); "
                       "m.write_text(sys.argv[2]);\n"
                       "try: (p/'reset').write_text('1')\n"
                       "finally: m.write_text(old)\n")
            argv = [sys.executable, '-c', program, '/sys/bus/pci/devices/' + self.bdf, method]
            effect = 'none'
        elif action in ('pci_remove', 'pci_rescan'):
            self._reenumerated = True
            path = ('/sys/bus/pci/devices/' + self.bdf + '/remove' if action == 'pci_remove'
                    else '/sys/bus/pci/rescan')
            argv = [sys.executable, '-c', "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('1')", path]
            effect = 'none'
        elif action == 'power_off':
            argv, effect = [sys.executable, self.pmu_script, '7', '1'], 'power_off'
        elif action == 'power_on':
            voltage = self.config['runtime_hw']['clkreq_voltage_mv']
            argv = [sys.executable, self.pmu_script, '4', '1', str(voltage), '0', '12000', '0', '0']
            effect = 'power_on'
        else:
            adapter = self.options['adapters'][action]
            argv = [x.replace('{device}', self.device).replace('{pmu_script}', self.pmu_script)
                    for x in adapter['argv']]
            effect = adapter.get('effect', 'none')
        # Track uncertain OFF/assert BEFORE execution: even a failing helper may
        # have changed the board. ON/deassert become confirmed only after rc=0.
        if effect == 'power_off':
            self.powered = False
        elif effect == 'assert':
            self.asserted = True
        rc, _, err = self.runner.run(
            argv, deadline, supply_control=(action in self.options.get('adapters', {})
                                            or effect in ('power_off', 'power_on', 'assert', 'deassert')))
        if rc:
            raise ExceptionFailure(f'{action}: rc={rc}: {err.decode(errors="replace")[:300]}')
        if effect == 'power_on':
            self.powered = True
        elif effect == 'deassert':
            self.asserted = False
        adapter = self.options.get('adapters', {}).get(action, {})
        if 'readback' in adapter:
            if effect == 'deassert':
                self.asserted = True  # remain uncertain until readback succeeds
            check = adapter['readback']
            args = [x.replace('{pmu_script}', self.pmu_script) for x in check['argv']]
            rc, out, err = self.runner.run(args, deadline, supply_control=True)
            value = gpio_value(out) if rc == 0 else None
            self.emit('gpio_readback', action=action, value=value, expected=check['expected'])
            if value != check['expected']:
                if effect == 'deassert':
                    self.asserted = True  # release not confirmed; cleanup must retry
                raise ExceptionFailure(f'{action}: GPIO readback mismatch: {value}')
            if effect == 'deassert':
                self.asserted = False

    def restore_supply(self):
        """Only ON/deassert; never cycle power or issue a recovery reset."""
        if self.powered and not self.asserted:
            return
        if self.runner.has_pending(supply_only=True):
            raise ExceptionFailure('hardware helper still running; cannot race supply cleanup')
        deadline = self.clock() + self.cleanup_timeout
        for action in self.options.get('restore_actions', []):
            effect = action_effect(action, self.options.get('adapters', {}))
            if (effect == 'power_on' and not self.powered) or (effect == 'deassert' and self.asserted):
                self.emit('restore_supply', action=action)
                self._action(action, deadline)
        if not self.powered or self.asserted:
            raise ExceptionFailure('supply/assert state could not be restored')

    def wait_ready(self, deadline):
        while self.clock() < deadline:
            # remove/rescan may change nvmeN. Resolve by the original serial AND
            # PCI function; do not assume that the old node still names the DUT.
            if getattr(self, '_reenumerated', False):
                matches = []
                for candidate in Path('/sys/class/nvme').glob('nvme[0-9]*'):
                    try:
                        if ((candidate / 'serial').read_text().strip() == self.serial
                                and (candidate / 'address').read_text().strip() == self.bdf):
                            matches.append(candidate)
                    except OSError:
                        continue
                if len(matches) == 1:
                    self.sysfs = matches[0]
                    self.device = '/dev/' + self.sysfs.name
            # A replaced device must not pass simply because its RDY bit is set.
            try:
                serial = (self.sysfs / 'serial').read_text().strip()
                bdf = (self.sysfs / 'address').read_text().strip()
                state = (self.sysfs / 'state').read_text().strip()
            except OSError:
                serial = bdf = state = None
            if serial and (serial != self.serial or bdf != self.bdf):
                raise ExceptionFailure('DUT identity changed after reset')
            if serial == self.serial and state == 'live' and Path(self.device).exists():
                rc, out, _ = self.runner.run(['nvme', 'show-regs', self.device, '-o', 'json'], deadline)
                if not rc:
                    ready, value = csts_ready(out)
                    self.emit('ready_probe', csts=value, ready=ready)
                    if value & 2:
                        raise ExceptionFailure('CSTS.CFS=1')
                    if ready and self.clock() <= deadline:
                        return
            time.sleep(min(0.05, max(0, deadline - self.clock())))
        raise ExceptionFailure('CTRL RDY/recognition deadline exceeded')

    def _run_profile(self, profile):
        deadline = self.clock() + profile.timeout_sec
        ready_deadline = None
        for index, (action, hold) in enumerate(profile.steps):
            if self.clock() >= deadline:
                raise ExceptionFailure('profile deadline exceeded')
            self.emit('step_start', index=index, action=action)
            effect = action_effect(action, self.options.get('adapters', {}))
            # Start before ON/reset helper: command latency and trailing
            # sleeps must not silently extend the existing POR requirement.
            if effect in ('power_off', 'assert'):
                ready_deadline = None  # a deliberate new OFF/assert interval
            action_deadline = deadline
            if effect in ('power_on', 'deassert') or action in ('controller_reset', 'nssr', 'flr', 'hot_reset'):
                ready_deadline = self.clock() + profile.ready_timeout_sec
            if ready_deadline is not None:
                action_deadline = min(deadline, ready_deadline)
            self._action(action, action_deadline)
            self.emit('step_end', index=index, action=action)
            if hold:
                if self.clock() + hold > action_deadline:
                    raise ExceptionFailure('hold would exceed profile/RDY deadline')
                time.sleep(hold)
        if ready_deadline is None:
            ready_deadline = self.clock() + profile.ready_timeout_sec
        self.wait_ready(ready_deadline)
        self._ready_deadline = ready_deadline

    def restore_nvme_environment(self):
        """After RDY only: fresh support/feature reads, bounded writes and readback.

        Never consult or replace the fuzzer's saved pre-campaign feature values.
        Unsupported APST/KATO are skipped only on explicit Identify evidence.
        """
        deadline = self.clock() + self.options.get('resume_timeout_sec', 30)
        def command(argv):
            rc, out, err = self.runner.run(argv, deadline)
            if rc:
                raise ExceptionFailure(f'resume command failed: {argv}: {err!r}')
            return out
        raw = command(['nvme', 'id-ctrl', self.device, '-o', 'json'])
        ident = json.loads(raw)
        if ident.get('sn', '').strip() != self.serial:
            raise ExceptionFailure('resume Identify serial mismatch')
        apsta, kas = register_value(raw, 'apsta'), register_value(raw, 'kas')
        for fid, supported, mask in ((0x0c, bool(apsta & 1), 1), (0x0f, kas > 0, 0xffffffff),
                                     (0x02, True, 0x1f)):
            if not supported:
                self.emit('resume_feature', fid=fid, status='UNSUPPORTED')
                continue
            def read():
                out = command(['nvme', 'get-feature', self.device, '-n', '0', '-f', hex(fid)])
                values = re.findall(r'current\s+value\s*:\s*(?:0x)?([0-9a-fA-F]+)',
                                    out.decode(errors='replace'), re.I)
                if len(values) != 1:
                    raise ExceptionFailure(f'cannot read current feature {fid:#x}')
                return int(values[0], 16)
            before = read()
            if before & mask:
                argv = ['nvme', 'set-feature', self.device, '-n', '0', '-f', hex(fid), '-v', '0']
                if fid == 0x0c:
                    with tempfile.NamedTemporaryFile() as table:
                        table.write(bytes(256))
                        table.flush()
                        command(argv + ['--data-len', '256', '--data', table.name])
                else:
                    command(argv)
            after = read()
            if after & mask:
                raise ExceptionFailure(f'resume feature {fid:#x} readback mismatch: {after:#x}')
            self.emit('resume_feature', fid=fid, before=before, after=after, status='VERIFIED')

    def capability(self, profile):
        for action, _ in profile.steps:
            if action in ('flr', 'hot_reset'):
                result = pci_method_support(self.bdf, 'flr' if action == 'flr' else 'bus')
                if result[0] != 'AVAILABLE':
                    return result
            elif action == 'nssr':
                rc, out, err = self.runner.run(['nvme', 'show-regs', self.device, '-o', 'json'],
                                               self.clock() + profile.ready_timeout_sec)
                if rc:
                    raise ExceptionFailure('cannot read CAP for NSSR: ' + err.decode(errors='replace'))
                result = subsystem_support(register_value(out, 'cap'), self.bdf)
                if result[0] != 'AVAILABLE':
                    return result
            elif action in ('power_on', 'power_off') or action in self.options.get('adapters', {}):
                adapter = self.options.get('adapters', {}).get(action, {})
                uses_pmu = action in ('power_on', 'power_off') or any(
                    '{pmu_script}' in x for x in adapter.get('argv', []))
                if uses_pmu and not Path(self.pmu_script).is_file():
                    return 'UNCONFIGURED', 'PMU script unavailable on this host'
        return 'AVAILABLE', 'control path available; active preflight required'

    def preflight(self, before, resumed):
        """Only explicit absence skips. A fault during a trial preserves/stops.

        Static capability is not proof of successful operation. This routine
        runs each requested profile once at idle, observes RDY/identity and a
        normal Identify command, then verifies the sampler. No recovery POR.
        """
        passed = []
        settings = self.options.get('preflight', {})
        trials = settings.get('attempts_per_kind', 1)
        if isinstance(trials, bool) or not isinstance(trials, int) or not 1 <= trials <= 10:
            raise ValueError('preflight.attempts_per_kind must be 1..10')
        try:
            self.wait_ready(self.clock() + min(p.ready_timeout_sec for p in self.profiles))
            for profile in self.profiles:
                self.active = 'preflight-' + profile.name
                self.last_result = dict(event_id=self.active, profile=profile.name, phase='preflight')
                status, reason = self.capability(profile)
                self.preflight_results[profile.name] = dict(status=status, reason=reason)
                if status != 'AVAILABLE':
                    self.emit('preflight', profile=profile.name, status=status, reason=reason)
                    continue
                if settings.get('enabled', True):
                    for attempt in range(trials):
                        self.emit('preflight_start', profile=vars(profile), attempt=attempt + 1)
                        before()
                        self._run_profile(profile)
                        rc, out, err = self.runner.run(['nvme', 'id-ctrl', self.device, '-o', 'json'],
                                                       self.clock() + profile.ready_timeout_sec)
                        if rc or json.loads(out).get('sn', '').strip() != self.serial:
                            raise ExceptionFailure('preflight Identify failed or serial mismatch')
                        resumed()
                    status, reason = 'PASS', 'profile applied; RDY, DUT identity, Identify and sampler verified'
                else:
                    status, reason = 'UNVERIFIED', 'active trial disabled explicitly; capability only'
                self.preflight_results[profile.name] = dict(status=status, reason=reason)
                self.emit('preflight', profile=profile.name, status=status, reason=reason)
                passed.append(profile)
            self.preflight_results['refclk_toggle'] = dict(status='UNCONFIGURED',
                reason='no platform REFCLK control; CLKREQ is not direct REFCLK gating')
            self.emit('preflight', profile='refclk_toggle', **self.preflight_results['refclk_toggle'])
            self.profiles = passed
            self.next_at = self.clock() + self.initial_delay if passed else float('inf')
            self.emit('preflight_complete', enabled=[p.name for p in passed], results=self.preflight_results)
            self.last_result = None
        except BaseException as exc:
            if self.last_result is None:
                self.last_result = dict(event_id='preflight-baseline', phase='preflight')
            self.last_result.update(outcome='preserved_failure', reason=str(exc))
            failed = self.last_result.get('profile', 'baseline')
            self.preflight_results[failed] = dict(status='FAIL_PRESERVED', reason=str(exc))
            self.next_at = float('inf')
            try:
                self.restore_supply()
            except Exception as cleanup:
                self.emit('restore_failed', reason=str(cleanup))
            self.emit('preflight_failure', reason=str(exc), results=self.preflight_results)
            raise
        finally:
            self.active = None

    def execute(self, process, context, before, resumed):
        """Called only after Popen. None means sampling was left untouched.

        A missed_window result means before() stopped sampling but no reset ran;
        the caller retains normal command completion with invalid coverage.
        `before` stops sampling without reconnect/reset. `resumed` reconnects the
        observation infrastructure only AFTER DUT RDY and identity are verified.
        """
        if not self.due():
            return None
        if self.delay:
            try:
                process.wait(timeout=self.delay)
            except subprocess.TimeoutExpired:
                pass
        if process.poll() is not None:
            self.emit('missed_window', pid=process.pid, context=context)
            # Avoid a per-command log storm when commands are all shorter than the delay.
            self.next_at = self.clock() + self.interval
            return None
        self.counter += 1
        self.active = f'exception-{self.counter:06d}'
        profile = self.rng.choice(self.profiles)
        self.last_result = dict(event_id=self.active, profile=profile.name, context=context)
        self.emit('begin', profile=vars(profile), context=context, pid=process.pid,
                  overlap='host_process_alive_only')
        try:
            before()
            if process.poll() is not None:
                self.last_result['outcome'] = 'missed_window'
                self.emit('missed_window', pid=process.pid, observation_valid=False)
                return self.last_result
            self._run_profile(profile)
            ready_deadline = self._ready_deadline
            # Interrupted commands are not replayed and never counted as success.
            # A still-running ioctl is evidence, not permission to start another one.
            try:
                out, err = process.communicate(timeout=max(0.001, ready_deadline - self.clock()))
            except subprocess.TimeoutExpired as exc:
                raise ExceptionFailure('original command still pending after RDY') from exc
            self.emit('interrupted_command', rc=process.returncode,
                      stdout=out.decode(errors='replace')[:8192], stderr=err.decode(errors='replace')[:8192])
            resumed()
            self.last_result['outcome'] = 'resumed'
            self.emit('resumed', command_rc=process.returncode)
            return self.last_result
        except BaseException as exc:
            self.last_result.update(outcome='interrupted' if isinstance(exc, KeyboardInterrupt) else 'preserved_failure',
                                    reason=str(exc))
            self.emit(self.last_result['outcome'], reason=str(exc), pid=process.pid)
            # Supply is needed for dumps. Only restore if known OFF/asserted;
            # never reset an already-powered failed device.
            try:
                self.restore_supply()
            except Exception as cleanup:
                self.emit('restore_failed', reason=str(cleanup))
            raise
        finally:
            self.next_at = self.clock() + self.interval
            self.active = None


class ExceptionFuzzerMixin:
    """Small v11 integration surface over the unchanged v10.3 command builders.

    No command-name allowlist: every command reaching the common transport can
    be interrupted. Existing user-selected commands and transport guards remain.
    """
    RC_EXCEPTION = -1011

    def __init__(self, config):
        options = self.exception_config.get('exceptions', {})
        enabled = options.get('enabled', False)
        if not isinstance(enabled, bool):
            raise ValueError('exceptions.enabled must be boolean')
        # Validate before super().__init__ can initialize device-facing helpers.
        if enabled:
            compile_profiles(options, self.exception_config)
            for name in ('min_interval_minutes', 'initial_delay_minutes', 'trigger_delay_ms'):
                number(options.get(name, 0), name)
        self._exception_controller = None
        self._exception_preserve = False
        self._exception_interrupted = False
        self._exception_window_truncated = False
        self._exception_recovery_remaining = 0
        self._exception_recovery_until = 0
        self._exception_recovery_event = None
        self._exception_recovery_window = False
        self._exception_pm_depth = 0
        self._exception_epoch = 0
        self._exception_sequence_events = []
        super().__init__(config)
        if enabled:
            self._exception_controller = ExceptionController(
                options, self.exception_config, config.nvme_device, config.pmu_script,
                self.output_dir / 'exceptions.jsonl')

    def _learning_baseline(self, phase='first_request'):
        result = super()._learning_baseline(phase)
        # Calibration and startup retain their baseline behavior. Fuzzing,
        # sequences and IO engines subsequently share the same injection path.
        if phase == 'fuzz_start' and self._exception_controller:
            try:
                self._exception_controller.arm()
                self._exception_controller.preflight(self._exception_before, self._exception_resumed)
            except KeyboardInterrupt:
                # A helper runs in its own session and may still be changing the
                # hardware. Exit through fault preservation, never normal I/O cleanup.
                self._exception_preserve = True
                self._timeout_crash = True
                self._exception_user_interrupt()
                raise
            except Exception as exc:
                self._exception_capture(exc)
            import logging
            logging.getLogger('pcfuzz').warning('[Exception] preflight complete; enabled=%s',
                [] if self._exception_preserve else [p.name for p in self._exception_controller.profiles])
        return result

    def _llm_backend_meta(self, task, ctx):
        meta = super()._llm_backend_meta(task, ctx)
        meta['device_epoch'] = self._exception_epoch
        return meta

    def _set_power_combo(self, *args, **kwargs):
        self._exception_pm_depth += 1
        try:
            return super()._set_power_combo(*args, **kwargs)
        finally:
            self._exception_pm_depth -= 1

    def _exception_before(self):
        self.sampler.stop_sampling()
        self.sampler._stop_worker()

    def _exception_resumed(self):
        # Called only after RDY/identity. Restoration is not sequence replay.
        controller = self._exception_controller
        if self._exception_preserve or controller.runner.has_pending():
            raise ExceptionFailure('cannot restore environment while preserving/pending helper')
        self.config.nvme_device = controller.device
        monitor = getattr(self, 'state_monitor', None)
        if monitor is not None:
            monitor._device = controller.device
        combo = self._current_combo
        baseline = type(combo)(0, type(combo.pcie_l)(0), type(combo.pcie_d)(0))
        if self.config.pm_inject_prob > 0:
            original_policy = self._orig_aspm_policy
            try:
                self._detect_pcie_info()
            finally:
                # Rediscovery refreshes PCI addresses/capabilities, not the
                # pre-campaign host policy saved for L0/exit restoration.
                self._orig_aspm_policy = original_policy
            if (not self._set_pcie_l_state(baseline.pcie_l)
                    or not self._set_pcie_d_state(baseline.pcie_d)):
                raise ExceptionFailure('resume L0/D0 configuration failed')
            for bdf, cap in ((self._pcie_bdf, self._pcie_cap_offset),
                             (self._pcie_root_bdf, self._pcie_root_cap_offset)):
                if bdf and cap is not None:
                    value = self._setpci_read(bdf, cap + 0x10, 'w')
                    if value is None or value == 0xffff or value & 0x103:
                        raise ExceptionFailure('resume L0 readback failed')
        controller.restore_nvme_environment()
        self._current_ps = 0
        if self.config.pm_inject_prob > 0:
            self._current_combo = baseline
        if not self.sampler._reinit_target() and not self.sampler._reconnect():
            self._sampler_recovery_failed = True
            raise ExceptionFailure('DUT RDY, but sampler reconnection failed')
        err = getattr(self.sampler, 'openocd_error', None)
        if err is not None:
            err.clear()
        self._exception_recovery_remaining = controller.options.get('recovery_observation_commands', 1)
        self._exception_recovery_until = time.monotonic() + controller.options.get('recovery_observation_sec', 0)
        self._exception_recovery_event = controller.active
        self._invalidate_device_caches('v11 exception: resume same sequence')
        self._state_snap_prev = None
        self._exception_epoch += 1
        if hasattr(self.sampler, 'take_observations'):
            self.sampler.take_observations()  # discard reset-window observations
        self.sampler.current_trace.clear()

    def _exception_on_spawn(self, process, seed, timeout_ms):
        controller = self._exception_controller
        if controller is None or self._exception_pm_depth or not controller.due():
            return None
        # A delay longer than the normal watchdog must not postpone a real hang.
        if controller.delay >= timeout_ms / 1000.0:
            return None
        context = dict(command=self._seed_meta(seed), exec=self.executions,
                       wire=getattr(self, '_last_wire', None),
                       sequence_index=(self._learning_sequence or {}).get('index'),
                       workload=getattr(self, '_wl_active_pattern', None),
                       device_epoch=self._exception_epoch)
        try:
            result = controller.execute(process, context, self._exception_before, self._exception_resumed)
            if result is None:
                return None
            if result.get('outcome') == 'missed_window':
                # No reset took place. Keep the actual command status, but the
                # stopped observation window cannot measure its coverage yield.
                self._exception_window_truncated = True
                return None
        except KeyboardInterrupt:
            # Do not kill a still-pending ioctl and accidentally provoke kernel
            # abort/reset while preserving a failed/unfinished reset event.
            if controller.last_result and controller.last_result.get('outcome') == 'interrupted':
                self._exception_preserve = True
                self._timeout_crash = True
            self._exception_user_interrupt()
            raise
        except Exception as exc:
            self._crash_nvme_pid = process.pid if process.poll() is None else None
            self._exception_capture(exc)
            result = controller.last_result or {'outcome': 'preserved_failure', 'reason': str(exc)}
        self._exception_interrupted = True
        self._last_nvme_status = None
        self._last_cmd_submitted = False
        self._exception_sequence_events.append(result)
        if self._learning_sequence is not None:
            from llm_learning import seed_item
            self._learning_sequence['executed'].append(seed_item(seed))
            self._learning_sequence['setup_ok'] = False
            self._learning_sequence.setdefault('exception_events', []).append(result.get('event_id'))
        if self._seq_sink is not None:
            # Retain the interrupted step for sequence provenance; it is NOT
            # counted as a successful completion or a coverage reward.
            self._seq_sink['commands'].append(seed)
        if self._cmd_history:
            self._cmd_history[-1]['exception_event'] = result.get('event_id')
        return self.RC_EXCEPTION

    def _exception_capture(self, reason):
        """Reuse dumps, NOT _handle_timeout_crash (which has automatic POR gates)."""
        from datetime import datetime
        import logging
        self._exception_preserve = True
        self._timeout_crash = True
        self._fw_hang_captured = True
        now = datetime.now()
        dest = self.crashes_dir / ('exception_' + now.strftime('%Y%m%d_%H%M%S_%f'))
        dest.mkdir(parents=True, exist_ok=True)
        controller = self._exception_controller
        controller.emit('capture', reason=str(reason), directory=str(dest))
        (dest / 'exception.json').write_text(json.dumps(
            dict(reason=str(reason), event=controller.last_result,
                 powered=controller.powered, asserted=controller.asserted,
                 helper_pids=[p.pid for p in controller.runner.pending if p.poll() is None]),
            ensure_ascii=False, indent=2), encoding='utf-8')
        logging.getLogger('pcfuzz').error('[Exception] stopped; no recovery POR/reset: %s', reason)
        try:
            self.sampler._stop_worker()
            self._snapshot_crash_context(dest, now)
        except Exception as exc:
            controller.emit('capture_error', reason=str(exc))
        # Power restoration was attempted before entering this method. A known
        # OFF state cannot yield a useful firmware dump; retain that fact.
        if not controller.powered or controller.asserted or controller.runner.has_pending(supply_only=True):
            controller.emit('dump_unavailable', powered=controller.powered, asserted=controller.asserted,
                            reason='supply not stable or hardware helper pending')
            return
        for enabled, name, dump in (
                (self.config.enable_jlink_dump, 'JLINK', self._run_jlink_dump),
                (self.config.enable_ufas, 'UFAS', self._run_ufas_dump),
                (self.config.enable_debug_tool_dump, 'DebugTool', self._run_debug_tool_dump)):
            if not enabled:
                continue
            try:
                if name == 'JLINK':
                    self._shutdown_openocd_for_jlink()
                if name == 'DebugTool' and self.sampler.USES_JLINK_USB:
                    self.sampler.close()
                controller.emit('dump_start', backend=name)
                dump(dest_dir=dest)
                controller.emit('dump_returned', backend=name)
            except Exception as exc:
                controller.emit('dump_error', backend=name, reason=str(exc))

    def _stop_sampling_checked(self, context='command'):
        if not self._exception_interrupted:
            result = super()._stop_sampling_checked(context)
            if getattr(self, '_exception_recovery_window', False):
                observations = (self.sampler.take_observations()
                                if hasattr(self.sampler, 'take_observations') else [])
                self._exception_controller.emit('recovery_observation',
                    recovery_event=self._exception_recovery_event,
                    pcs=sorted(self.sampler.current_trace), observations=observations)
                if self._seq_sink is not None:
                    self._seq_sink['exception_recovery'] = True
                self._exception_window_truncated = True
            if getattr(self, '_exception_window_truncated', False):
                self._learning_window_valid = False
                self._learning_window_failed = True
                if hasattr(self.sampler, 'take_observations'):
                    self.sampler.take_observations()
                self.sampler.current_trace.clear()
            return result
        # Expected link loss must not trigger legacy recovery/POR, nor become
        # learning evidence. The event already stopped/reconnected the sampler.
        self.sampler.stop_sampling()
        self.sampler._stop_worker()
        if hasattr(self.sampler, 'take_observations'):
            self.sampler.take_observations()
        self.sampler.current_trace.clear()
        self._learning_last_send = None
        self._learning_account_send = None
        self._learning_window_valid = False
        self._learning_window_failed = True
        return 0, not self._exception_preserve

    def _send_nvme_command(self, *args, **kwargs):
        if self._exception_preserve:
            return self.RC_EXCEPTION
        if (not self._exception_interrupted and not self._seq_sink
                and not self._learning_sequence and not getattr(self, '_wl_active_pattern', None)):
            self._exception_sequence_events.clear()
        # This marker belongs to one send, including callers (calibration) that
        # do not use _account_command. Never mask the next command's watchdog.
        self._exception_interrupted = False
        self._exception_window_truncated = False
        self._exception_recovery_window = bool(
            getattr(self, '_exception_recovery_remaining', 0) > 0
            or time.monotonic() < getattr(self, '_exception_recovery_until', 0)
            or (self._exception_sequence_events and (self._learning_sequence or self._seq_sink)))
        result = super()._send_nvme_command(*args, **kwargs)
        if result == self.RC_SKIP:
            self._exception_finish_command()
        if self._exception_recovery_window and result not in (self.RC_SKIP, self.RC_EXCEPTION):
            self._exception_window_truncated = True  # stop multi-send batches at this window
            self._exception_recovery_remaining = max(0, getattr(self, '_exception_recovery_remaining', 0) - 1)
        return result

    def _exception_finish_command(self):
        """Retire per-command flags, retaining campaign preservation and event budgets."""
        self._exception_interrupted = False
        self._exception_window_truncated = False
        self._exception_recovery_window = False

    def _calibrate_seed(self, *args, **kwargs):
        # Calibration performs its own accounting and never calls _account_command.
        try:
            return super()._calibrate_seed(*args, **kwargs)
        finally:
            self._exception_finish_command()

    def _account_command(self, seed, fuzz_data, rc, last_samples, **kwargs):
        try:
            return self._exception_account_command(seed, fuzz_data, rc, last_samples, **kwargs)
        finally:
            self._exception_finish_command()

    def _exception_account_command(self, seed, fuzz_data, rc, last_samples, **kwargs):
        if (getattr(self, '_exception_window_truncated', False)
                and rc not in (self.RC_TIMEOUT, self.RC_ERROR, self.RC_EXCEPTION, self.RC_SKIP)):
            self.executions += 1
            self.stats['coverage_unobserved'] = self.stats.get('coverage_unobserved', 0) + 1
            label = self._tracking_label(seed.cmd, seed)
            stat = self.cmd_stats[label]
            stat['exec'] += 1
            stat['coverage_unobserved'] = stat.get('coverage_unobserved', 0) + 1
            self.rc_stats[label][rc] += 1
            status = self._last_nvme_status
            self._learning_window_valid = False
            self._learning_observe(seed, status, rc, set(), 0,
                                   kwargs.get('source', 'c1'), kwargs.get('seq_member', False))
            self._last_nvme_status = None
            if self._fw_commit_reset_pending:
                self._fw_commit_reset_pending = False
                self._reconnect_after_fw_commit()
            if self._seq_sink is not None:
                self._seq_sink['commands'].append(seed)
            self._exception_controller.emit('account_unobserved', command=seed.cmd.name,
                rc=rc, status=status, exec=self.executions, observation_valid=False)
            return False, 0, 'continue'
        if rc != self.RC_EXCEPTION:
            result = super()._account_command(seed, fuzz_data, rc, last_samples, **kwargs)
            if self._exception_sequence_events and self._exception_controller:
                self._exception_controller.emit('continuation', command=seed.cmd.name,
                    rc=rc, exec=self.executions, source=kwargs.get('source', 'c1'),
                    events=[r.get('event_id') for r in self._exception_sequence_events])
            return result
        self._exception_interrupted = False
        self.executions += 1
        self.stats['exception_interrupted'] = self.stats.get('exception_interrupted', 0) + 1
        self._last_nvme_status = None
        self._learning_last_send = None
        self._learning_account_send = None
        self._learning_window_valid = False
        if hasattr(self, 'cmd_stats'):
            stat = self.cmd_stats[self._tracking_label(seed.cmd, seed)]
            stat['exec'] += 1
            stat['exception_interrupted'] = stat.get('exception_interrupted', 0) + 1
        state = self._learning_sequence
        if state is not None and state['index'] >= state['length'] - 1:
            self._learning_sequence = None
        self._exception_controller.emit('account_interrupted', exec=self.executions,
            command=seed.cmd.name, source=kwargs.get('source', 'c1'),
            events=[r.get('event_id') for r in self._exception_sequence_events])
        return False, 0, 'break' if self._exception_preserve else 'continue'

    def _learning_observe(self, *args, **kwargs):
        state = self._learning_sequence
        if not state or not state.get('exception_events'):
            return super()._learning_observe(*args, **kwargs)
        # A setup interrupted by reset is not a successful setup, but a later
        # expected error must not cancel the user's requested remaining steps.
        preserve = state['preserve']
        state['preserve'] = False
        try:
            return super()._learning_observe(*args, **kwargs)
        finally:
            state['preserve'] = preserve

    def _finalize_seq_sink(self):
        try:
            if self._seq_sink and self._seq_sink.get('exception_recovery'):
                self._seq_sink['interesting'] = False
            if self._exception_sequence_events and self._exception_controller:
                self._exception_controller.emit('sequence_end',
                    events=[r.get('event_id') for r in self._exception_sequence_events],
                    new_pcs=(self._seq_sink or {}).get('new_pcs', 0),
                    commands=[s.cmd.name for s in (self._seq_sink or {}).get('commands', [])])
                # Ordinary sequence replay has no reset descriptor yet. Do not
                # publish a misleading reproducer that silently omits the event.
                if self._seq_sink is not None:
                    self._seq_sink['interesting'] = False
            return super()._finalize_seq_sink()
        finally:
            self._exception_sequence_events.clear()

    def _exception_user_interrupt(self):
        controller = self._exception_controller
        if controller:
            try:
                controller.restore_supply()
            except Exception as exc:
                controller.emit('interrupt_restore_failed', reason=str(exc))

    def _restore_held_wp(self, *args, **kwargs):
        if self._exception_preserve:
            return False
        return super()._restore_held_wp(*args, **kwargs)

    def _recover_after_unsupported_skip(self):
        if self._exception_controller:
            # Never let an old ignore/repro/unsupported branch clear the fault
            # with POR during an exception campaign.
            self._exception_capture('legacy automatic POR recovery suppressed')
            return False
        return super()._recover_after_unsupported_skip()


def make_fuzzer(base, config):
    return type('NVMeFuzzerV11', (ExceptionFuzzerMixin, base), {'exception_config': config})
