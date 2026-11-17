"""Three-round host G2 checkpoint; it does not replace the frozen experiment."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import statistics

from analyze_network import OPENING_SETTINGS, parse_records, require

SCENARIOS = ('bigbody', 'gzbody', 'latebig', 'closeafter')
ROLES = ('ref', 'lc')
SCHEMA = 'host-g2-checkpoint-v4'
INPUTS = frozenset({'lc-tunnel.host', 'reference.host', 'dest.host', 'fingerprint.fpt',
                    'ca.pem', 'leaf.pem', 'leaf.key', 'client.json', 'server.json',
                    'driver.py', 'analyze_checkpoint.py', 'analyze_network.py',
                    'checkpoint_process.py', 'source.sha256'})


def checkpoint_criteria():
    # Scheduler-dependent CANCEL/path rates are observations, not acceptance
    # thresholds. Keep the independent candidate latency-regression budget.
    return dict(timing_regression_us=100)


def make_plan(inputs):
    require(set(inputs) == INPUTS and
            all(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value)
                for value in inputs.values()), 'invalid checkpoint input manifest')
    phases = []
    for n in (1, 2, 3):
        for si, scenario in enumerate(SCENARIOS):
            roles = ROLES if (n + si) % 2 else tuple(reversed(ROLES))
            phases += [dict(round=n, role=role, scenario=scenario) for role in roles]
    return dict(schema=SCHEMA, rounds=3, scenarios=list(SCENARIOS),
                connections_per_probe=5, criteria_frozen=True,
                acceptance_scope='checkpoint', criteria=checkpoint_criteria(),
                phases=phases, inputs=dict(inputs))


def validate_rows(rows, scenario, round_id):
    require(len(rows) == 5, 'incomplete checkpoint retry group')
    for row in rows:
        require(row['bytes'] > 0 and row['prefaces'] == 1 and not row['invalid'] and
                row['cancel'] in (0, 1) and row['sample'] == round_id,
                'invalid checkpoint capture')
        require(row['clock'] == 'io-return-v2' and row['first_request_us'] is not None,
                'missing checkpoint timing')
        settings = [f for f in row['frames'] if 'SETTINGS ack=false' in f]
        require(len(row['frames']) >= 2 and settings == [OPENING_SETTINGS] and row['frames'][0] == OPENING_SETTINGS and
                row['frames'][1] == '[4] WINDOW_UPDATE stream=0 +1073741824',
                'checkpoint opening differs from pinned reference')
        if scenario == 'closeafter':
            require(len(row['paths']) == 1 and
                    re.fullmatch(r'/(?:h(?:[0-9]|1[0-9]))?', row['paths'][0]),
                    'invalid checkpoint harvest path')
            streams = (1,)
        else:
            target = {'bigbody': '/bb', 'gzbody': '/gz', 'latebig': '/late'}[scenario]
            require(row['paths'] == ['/', target], 'invalid checkpoint redirect paths')
            streams = (1, 3)
        require(all(any(f'HEADERS stream={stream} end=true' in f for f in row['frames'])
                    for stream in streams), 'missing checkpoint HEADERS')


def summarize(rows):
    return dict(connections=len(rows), cancel=sum(r['cancel'] for r in rows),
                harvested=sum(bool(re.fullmatch(r'/h(?:[0-9]|1[0-9])', r['paths'][0]))
                              for r in rows),
                median_first_request_us=statistics.median(r['first_request_us'] for r in rows))


def compare_scenario(rows, scenario):
    require(scenario in SCENARIOS, 'unsupported checkpoint scenario')
    groups = {role: [r for r in rows if r['role'] == role and r['scenario'] == scenario]
              for role in ROLES}
    require(all(len(group) == 15 for group in groups.values()),
            'checkpoint requires 15 connections per client/scenario')
    summary = {role: summarize(group) for role, group in groups.items()}
    cancel_gap = abs(summary['lc']['cancel'] - summary['ref']['cancel']) * 100 / 15
    harvest_gap = abs(summary['lc']['harvested'] - summary['ref']['harvested']) * 100 / 15
    timing_delta = (summary['lc']['median_first_request_us'] -
                    summary['ref']['median_first_request_us'])
    timing_regression = max(0, timing_delta)
    return dict(scenario=scenario, clients=summary,
                cancellation_gap_pp=cancel_gap, harvesting_gap_pp=harvest_gap,
                timing_median_gap_us=abs(timing_delta),
                timing_median_delta_us=timing_delta,
                timing_regression_us=timing_regression)


def compare(rows):
    comparisons = [compare_scenario(rows, scenario) for scenario in SCENARIOS]
    for comparison in comparisons:
        comparison['criteria_met'] = (comparison['timing_regression_us'] <=
                                      checkpoint_criteria()['timing_regression_us'])
    return comparisons


def analyze(root):
    plan = json.loads((root / 'plan.json').read_text())
    require(plan['schema'] == SCHEMA and plan['rounds'] == 3 and
            plan['scenarios'] == list(SCENARIOS) and plan['connections_per_probe'] == 5 and
            plan['criteria'] == checkpoint_criteria() and
            plan.get('criteria_frozen') is True and
            plan.get('acceptance_scope') == 'checkpoint' and 'G2Closed' not in plan,
            'unsupported checkpoint design')
    require(len(plan['phases']) == 24 and
            {(p['round'], p['role'], p['scenario']) for p in plan['phases']} ==
            {(n, role, sc) for n in (1, 2, 3) for role in ROLES for sc in SCENARIOS},
            'invalid checkpoint phase coverage')
    require(set(plan['inputs']) == INPUTS, 'incomplete checkpoint input manifest')
    orders = defaultdict(set)
    for n in (1, 2, 3):
        phases = plan['phases'][(n - 1) * 8:n * 8]
        require(all(p['round'] == n for p in phases), 'checkpoint round ordering')
        for first, second in zip(phases[::2], phases[1::2]):
            require(first['scenario'] == second['scenario'] and
                    {first['role'], second['role']} == set(ROLES), 'unpaired checkpoint phase')
            orders[first['scenario']].add(first['role'])
    require(all(orders[sc] == set(ROLES) for sc in SCENARIOS), 'uncounterbalanced checkpoint')
    for name, expected in plan['inputs'].items():
        require(Path(name).name == name and
                hashlib.sha256((root / name).read_bytes()).hexdigest() == expected,
                'checkpoint input changed: ' + name)
    state = json.loads((root / 'run-state.json').read_text())
    require(state['exit_code'] == state['cleanup_exit'] == 0 and state['rounds_completed'] == 3 and
            state.get('phases_completed') == 24,
            'checkpoint driver or cleanup failed')
    require((root / 'stand-state.json').is_file(), 'missing checkpoint stand receipt')
    stand = json.loads((root / 'stand-state.json').read_text())
    require(stand.get('server_sha256') == plan['inputs']['reference.host'] and
            stand.get('dest_sha256') == plan['inputs']['dest.host'] and
            stand.get('alive_after_phases') is True and
            stand.get('server_exit') == 0 and stand.get('dest_exit') == -15,
            'checkpoint stand identity, liveness or stop failed')
    progress = [json.loads(line) for line in (root / 'progress.jsonl').read_text().splitlines()]
    require(len(progress) == 48, 'incomplete checkpoint progress')
    for phase, start, complete in zip(plan['phases'], progress[::2], progress[1::2]):
        require(start == dict(phase=phase, stage='start') and
                complete == dict(phase=phase, stage='complete', alive=True),
                'invalid checkpoint progress ordering')
        key = f"{phase['round']}-{phase['role']}-{phase['scenario']}"
        probe_exit = (root / (key + '.probe-exit')).read_text().strip()
        require(probe_exit in ('52', '56'),
                'invalid wrong-key checkpoint probe')
        require((root / (key + '.json')).is_file(), 'missing checkpoint client receipt')
        receipt = json.loads((root / (key + '.json')).read_text())
        binary = 'lc-tunnel.host' if phase['role'] == 'lc' else 'reference.host'
        expected_exit = -15 if phase['role'] == 'lc' else 0
        require(receipt.get('phase') == phase and
                receipt.get('binary_sha256') == plan['inputs'][binary] and
                receipt.get('alive_before_probe') is True and
                receipt.get('alive_after_probe') is True and
                receipt.get('probe_exit') == int(probe_exit) and
                receipt.get('stop_signal') == 15 and receipt.get('client_exit') == expected_exit,
                'checkpoint client identity, liveness, probe or stop failed')
    records = parse_records((root / 'dest.log').read_text())
    empty = [r for r in records if r['bytes'] == 0]
    require(all(r['prefaces'] == 0 and not r['paths'] and not r['frames'] for r in empty),
            'invalid empty checkpoint preflight')
    rows = [r for r in records if r['bytes'] != 0]
    require(len(rows) == 120 and all(r['role'] in ROLES and r['scenario'] in SCENARIOS and
                                    r['sample'] in (1, 2, 3) for r in rows),
            'invalid checkpoint connection coverage')
    rounds = []
    for n in (1, 2, 3):
        for sc in SCENARIOS:
            for role in ROLES:
                group = [r for r in rows if (r['sample'], r['scenario'], r['role']) == (n, sc, role)]
                validate_rows(group, sc, n)
                rounds.append(dict(round=n, role=role, scenario=sc, **summarize(group)))
    comparisons = compare(rows)
    return dict(schema=SCHEMA, acceptance_scope='checkpoint',
                checkpoint_criteria_met=all(r['criteria_met'] for r in comparisons),
                criteria=checkpoint_criteria(),
                comparisons=comparisons, rounds=rounds, excluded_empty_preflights=len(empty),
                limitations=['Host checkpoint does not replace the frozen experiment or native acceptance.',
                             'CANCEL and selected-path frequencies are descriptive, not acceptance thresholds.',
                             'This capture does not prove bounded device memory or absence of leaks.',
                             'Related retries are not independent statistical observations.',
                             'Timing is the destination io-return-v2 clock, not end-to-end VPN latency.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--prepare-plan', action='store_true',
                        help='freeze inputs before a new run; never overwrite an existing plan')
    args = parser.parse_args()
    if args.prepare_plan:
        result = make_plan({name: hashlib.sha256((args.directory / name).read_bytes()).hexdigest()
                            for name in INPUTS})
        with (args.directory / 'plan.json').open('x', encoding='utf-8') as output:
            output.write(json.dumps(result, indent=2) + '\n')
    else:
        result = analyze(args.directory)
    print(json.dumps(result, indent=2))
    if not args.prepare_plan and not result['checkpoint_criteria_met']:
        raise SystemExit(1)
