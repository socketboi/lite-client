"""Validate native v4 wire/process evidence; RAM measurements are diagnostic."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from analyze_checkpoint import compare, validate_rows
from analyze_network import parse_records, require, cpu_ticks
from native_checkpoint_plan import (NATIVE_INPUTS, DEVICE_INPUTS, validate_plan,
                                    phase_table, device_settings)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_inputs(root, plan):
    validate_plan(plan)
    require(set(plan['inputs']) == NATIVE_INPUTS and
            all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v)
                for v in plan['inputs'].values()), 'invalid native input manifest')
    for name, expected in plan['inputs'].items():
        require(digest(root/name) == expected, 'native input changed: '+name)
    config = json.loads((root/'settings.json').read_text())
    identity = json.loads((root/'device.json').read_text())
    client = json.loads((root/'client.json').read_text())
    require((root/'phases.tsv').read_text() == phase_table(plan), 'native phase table differs')
    require((root/'settings.sh').read_text() == device_settings(config, identity, client),
            'native settings differ from frozen configuration')
    return identity


def analyze(root):
    plan = json.loads((root/'plan.json').read_text())
    identity = validate_inputs(root, plan)
    device = root/'device-results'
    manifest = dict(line.split('  ', 1)[::-1] for line in (device/'device.sha256').read_text().splitlines())
    require(manifest == {name: plan['inputs'][name] for name in DEVICE_INPUTS},
            'executed device manifest differs')
    state = json.loads((device/'device-state.json').read_text())
    require(all(type(state.get(key)) is int for key in ('exit_code', 'cleanup_exit',
                'phases_completed', 'elapsed_seconds')) and
            state['exit_code'] == state['cleanup_exit'] == 0 and state['phases_completed'] == 24 and
            state['deadline_exceeded'] is False and 0 < state['elapsed_seconds'] <= 1200,
            'native driver, cleanup or deadline guard failed')
    for name in ('boot-before', 'boot-after'):
        require((device/name).read_text().strip() == identity['boot_id'], 'device boot identity changed')
    require((device/'board-name').read_text().strip() == identity['board_name'], 'device board differs')
    require((device/'interfaces-before').read_bytes() == (device/'interfaces-after').read_bytes(),
            'device interface set changed')
    configuration = (device/'configuration-before').read_text()
    require(configuration and configuration == (device/'configuration-after').read_text(),
            'device configuration changed or missing')
    require((device/'plan.sha256').read_text().strip() == digest(root/'plan.json'),
            'executed native plan differs')
    stand = json.loads((root/'stand-state.json').read_text())
    require(stand == dict(server_sha256=plan['inputs']['reference.host'],
            dest_sha256=plan['inputs']['dest.host'], phases_completed=24,
            alive_after_phases=True, server_exit=0, dest_exit=-15, cleanup_exit=0),
            'native stand identity, liveness or stop failed')
    progress = [json.loads(line) for line in (root/'progress.jsonl').read_text().splitlines()]
    require(progress == [entry for phase in plan['phases'] for entry in
            (dict(phase=phase, stage='start'), dict(phase=phase, stage='complete', alive=True))],
            'native progress differs')
    samples = []
    for line in (device/'resources.tsv').read_text().splitlines():
        fields = [int(value) for value in line.split()]
        require(len(fields) == 6, 'invalid native resource sample')
        phase_id, elapsed, available, rss, fds, threads = fields
        require(0 <= phase_id < 24 and 0 <= elapsed <= state['elapsed_seconds'] and
                available >= 0 and rss > 0 and fds > 0 and threads > 0,
                'invalid native resource sample counters')
        samples.append(fields)
    require(samples and all(a[1] <= b[1] and a[0] <= b[0] for a, b in zip(samples, samples[1:])),
            'native resource samples are missing or unordered')
    phases = []
    for phase in plan['phases']:
        key = str(phase['id'])
        receipt = json.loads((device/(key+'.json')).read_text())
        binary = 'lc-tunnel.native' if phase['role'] == 'lc' else 'reference.native'
        expected_exit = 143 if phase['role'] == 'lc' else 0
        probe = (device/(key+'.probe-exit')).read_text().strip()
        require(probe in ('52', '56'),
                'invalid native wrong-key probe')
        beginning, ending = receipt['observed_from_seconds'], receipt['observed_until_seconds']
        require(type(beginning) is int and type(ending) is int and
                0 <= beginning < ending <= state['elapsed_seconds'] and ending-beginning >= 8,
                'invalid native observation interval')
        require(receipt == dict(phase_id=phase['id'], binary_sha256=plan['inputs'][binary],
                alive_before_probe=True, alive_after_probe=True, probe_exit=int(probe),
                stop_signal=15, client_exit=expected_exit, monitor_exit=143, observed_from_seconds=beginning,
                observed_until_seconds=ending), 'invalid native client receipt')
        before, before_id = cpu_ticks((device/(key+'.stat-before')).read_text().strip())
        after, after_id = cpu_ticks((device/(key+'.stat-after')).read_text().strip())
        require(before_id == after_id and after >= before, 'native process identity or CPU changed')
        group = [s for s in samples if s[0] == phase['id']]
        require(group, 'missing phase resource observations')
        require(group[0][1] <= beginning+1 and group[-1][1] >= ending-2 and
                all(beginning <= s[1] <= ending for s in group) and
                all(b[1]-a[1] <= 2 for a, b in zip(group, group[1:])),
                'native resource observation gap')
        phases.append(dict(phase_id=phase['id'], cpu_ticks=after-before,
            peak_rss_kib=max(s[3] for s in group), peak_fds=max(s[4] for s in group),
            peak_threads=max(s[5] for s in group), minimum_memavailable_kib=min(s[2] for s in group)))
    records = parse_records((root/'dest.log').read_text())
    empty = [r for r in records if r['bytes'] == 0]
    require(all(not r['prefaces'] and not r['paths'] and not r['frames'] for r in empty),
            'invalid native preflight capture')
    rows = [r for r in records if r['bytes']]
    require(len(rows) == 120, 'incomplete native wire capture')
    for phase in plan['phases']:
        group = [r for r in rows if (r['sample'], r['role'], r['scenario']) ==
                 (phase['round'], phase['role'], phase['scenario'])]
        validate_rows(group, phase['scenario'], phase['round'])
    comparisons = compare(rows)
    return dict(schema=plan['schema'], acceptance_scope='checkpoint',
        resource_policy=plan['resource_policy'], memory_acceptance_threshold=None,
        checkpoint_criteria_met=all(c['criteria_met'] for c in comparisons),
        comparisons=comparisons, phases=phases, samples=len(samples),
        minimum_memavailable_kib=min(s[2] for s in samples),
        limitations=['A bounded spider checkpoint is not a mixed-workload soak or a release decision.',
                     'CANCEL and selected-path rates are descriptive; retry connections are dependent.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    result = analyze(parser.parse_args().directory)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['checkpoint_criteria_met'] else 1)
