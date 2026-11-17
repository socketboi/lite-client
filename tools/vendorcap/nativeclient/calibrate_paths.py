"""Validate a frozen Xray-versus-itself path-rate control; never grant acceptance."""
import argparse
import hashlib
import json
from pathlib import Path

from analyze_checkpoint import compare_scenario, validate_rows
from analyze_network import parse_records, require


INPUTS = {'xray', 'dest', 'ca.pem', 'leaf.pem', 'leaf.key', 'client.json', 'server.json',
          'driver.py', 'calibrate_paths.py', 'analyze_checkpoint.py', 'analyze_network.py',
          'source.sha256'}


def make_plan():
    phases = []
    for block in range(1, 13):
        for round_id in (1, 2, 3):
            roles = ('ref', 'lc') if (block + round_id) % 2 == 0 else ('lc', 'ref')
            for role in roles:
                phases.append(dict(block=block, round=round_id, role=role))
    return dict(schema='host-xray-path-calibration-v1', blocks=12, rounds=3,
                scenario='closeafter', connections_per_phase=5, expected_connections=360,
                implementations=dict(ref='xray', lc='xray'), acceptance=False,
                criteria=dict(rate_gap_pp=10, timing_regression_us=100),
                startup_wait_seconds=2, quiet_wait_seconds=6, max_seconds=1200,
                phases=phases)


def validate_plan(plan):
    expected = make_plan()
    require(set(plan) == set(expected) | {'inputs'}, 'unexpected calibration plan fields')
    require(all(plan[key] == value for key, value in expected.items()),
            'calibration design, criteria, coverage or counterbalance changed')
    require(set(plan['inputs']) == INPUTS, 'incomplete calibration input manifest')


def compare_control(rows):
    # This frozen Xray-versus-itself experiment measures the old metric's
    # rejection rate. It is not the current LiteClient acceptance policy.
    comparison = compare_scenario(rows, 'closeafter')
    comparison['criteria_met'] = (comparison['cancellation_gap_pp'] <= 10 and
                                   comparison['harvesting_gap_pp'] <= 10 and
                                   comparison['timing_regression_us'] <= 100)
    return comparison


def analyze(root):
    plan = json.loads((root / 'plan.json').read_text())
    validate_plan(plan)
    for name, expected in plan['inputs'].items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == expected,
                'calibration input changed: ' + name)
    state = json.loads((root / 'run-state.json').read_text())
    require(state == dict(exit_code=0, cleanup_exit=0, phases_completed=72, blocks_completed=12),
            'calibration driver, coverage or cleanup failed')
    progress = [json.loads(line) for line in (root / 'progress.jsonl').read_text().splitlines()]
    require(len(progress) == 144, 'incomplete calibration progress')
    for phase, start, complete in zip(plan['phases'], progress[::2], progress[1::2]):
        require(start == dict(phase=phase, stage='start') and
                complete == dict(phase=phase, stage='complete'), 'calibration phase order changed')
        key = f"{phase['block']:02d}-{phase['round']}-{phase['role']}"
        receipt = json.loads((root / (key + '.json')).read_text())
        require(receipt == dict(phase=phase, binary_sha256=plan['inputs']['xray'],
                alive_before_probe=True, alive_after_probe=True, probe_exit=receipt.get('probe_exit'),
                stop_signal=15, client_exit=0) and receipt['probe_exit'] in (52, 56),
                key + ': invalid executed identity, liveness, probe or client exit')
    results = []
    for block in range(1, 13):
        directory = root / f'block-{block:02d}'
        stand = json.loads((directory / 'stand-state.json').read_text())
        require(stand == dict(server_sha256=plan['inputs']['xray'], dest_sha256=plan['inputs']['dest'],
                alive_after_phases=True, server_exit=0, dest_exit=-15),
                'calibration stand identity, liveness or cleanup failed')
        records = parse_records((directory / 'dest.log').read_text())
        require(all(r['bytes'] != 0 or (not r['paths'] and not r['frames'] and
                    r['prefaces'] == 0 and not r['invalid']) for r in records),
                'malformed empty calibration capture')
        rows = [r for r in records if r['bytes'] != 0]
        require(len(rows) == 30 and all(r['role'] in ('ref', 'lc') and r['scenario'] == 'closeafter'
                and r['sample'] in (1, 2, 3) for r in rows), 'calibration wire coverage differs')
        for round_id in (1, 2, 3):
            for role in ('ref', 'lc'):
                group = [r for r in rows if r['role'] == role and r['sample'] == round_id]
                validate_rows(group, 'closeafter', round_id)
        comparison = compare_control(rows)
        # Apply the unchanged rate criterion independently of latency/cancellation.
        rate_met = comparison['harvesting_gap_pp'] <= plan['criteria']['rate_gap_pp']
        results.append(dict(block=block, path_rate_criterion_met=rate_met, **comparison))
    return dict(acceptance=False, G2Closed=False, blocks=results,
                path_rate_rejections=sum(not row['path_rate_criterion_met'] for row in results),
                limitations=[
                    'Both labels execute identical ordinary Xray bytes and configuration.',
                    'This is a fixed host control, not native acceptance or a client comparison.',
                    'Retries within a phase share a cache; individual connections are not independent trials.',
                    'Block rejection counts do not establish a population false-rejection rate.',
                    'No blocks are dropped, pooled for acceptance or repeated to obtain an outcome.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(analyze(parser.parse_args().directory), indent=2))
