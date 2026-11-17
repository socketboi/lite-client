"""Validate paired closeafter cache observations; never grant G2 acceptance."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from analyze_checkpoint import validate_rows
from analyze_network import parse_records, require


FULL_MASK = (1 << 21) - 1
ORIGINALS = {'src/reality/paths.c', 'src/cmd/lc-tunnel/main.c',
             'vendor/Xray-core/transport/internet/reality/reality.go',
             'vendor/Xray-core/main/run.go'}
OBSERVERS = {'paths.trace.c', 'main.trace.c', 'reality.trace.go', 'run.trace.go', 'cache.trace.go'}
INPUTS = {'lc.ordinary', 'lc.trace', 'xray.ordinary', 'xray.trace', 'dest.host',
          'fingerprint.fpt', 'ca.pem', 'leaf.pem', 'leaf.key', 'server.json',
          'client.json', 'driver.py', 'analyze_cache.py', 'analyze_checkpoint.py',
          'analyze_network.py', 'observer-inputs.json', 'source.sha256'} | OBSERVERS
NATIVE_ORIGINALS = (ORIGINALS - {'vendor/Xray-core/main/run.go'}) | {
    'tools/vendorcap/nativeclient/runner/main.go'}
NATIVE_OBSERVERS = (OBSERVERS - {'run.trace.go'}) | {'runner.trace.go'}
NATIVE_INPUTS = (INPUTS - {'run.trace.go'}) | {'runner.trace.go', 'client.pb', 'client.args',
    'device.sh', 'monitor.sh', 'stand.sh', 'toolchain.txt'}


def validate_native(root, plan, phases):
    require(plan.get('architecture') == 'mipsel' and plan.get('guard_memavailable_kib') == 4096 and
            plan.get('max_device_seconds') == 240, 'native cache trace guard changed')
    state = json.loads((root / 'device-state.json').read_text())
    require(state == dict(exit_code=0, monitor_exit=0, boot_unchanged=True,
                          config_unchanged=True, interfaces_unchanged=True),
            'native cache trace device, monitor or restoration failed')
    samples = []
    for line in (root / 'memory.tsv').read_text().splitlines():
        fields = line.split()
        require(len(fields) == 3 and fields[0].isdigit() and fields[2].isdigit(),
                'invalid native cache memory sample')
        samples.append((int(fields[0]), fields[1], int(fields[2])))
    labels = ['staging'] + [f"{p['round']}-{p['role']}" for p in phases] + ['cleanup']
    seen = []
    for _, label, _ in samples:
        require(label in labels, 'unexpected native cache memory phase')
        if not seen or seen[-1] != label:
            seen.append(label)
    require(seen == labels, 'native cache memory staging/phase/cleanup coverage missing')
    require(all(0 < b[0] - a[0] <= 3 for a, b in zip(samples, samples[1:])) and
            samples[-1][0] - samples[0][0] <= 240,
            'native cache memory sampling gap or device deadline exceeded')
    require(all(s[2] >= 4096 for s in samples), 'native cache memory guard tripped')
    for label in labels[1:-1]:
        group = [s for s in samples if s[1] == label]
        require(len(group) >= 8 and group[-1][0] - group[0][0] >= 7,
                'incomplete native cache memory phase: ' + label)
    return min(s[2] for s in samples)


def parse_cache(text, context):
    lines = [(i, line) for i, line in enumerate(text.splitlines()) if line.startswith('CACHE')]
    require(len(lines) >= 3, context + ': cache dump missing')
    begin = re.fullmatch(r'CACHE_BEGIN ([0-9]+) ([0-9]+)', lines[0][1])
    end = re.fullmatch(r'CACHE_END ([0-9]+)', lines[-1][1])
    require(begin is not None and end is not None, context + ': incomplete cache dump')
    count, overflow = map(int, begin.groups())
    require(0 < count <= 128 and overflow == 0 and int(end[1]) == count,
            context + ': overflowing or inconsistent cache dump')
    rows = []
    for _, line in lines[1:-1]:
        match = re.fullmatch(r'CACHE ([0-9]+) (draw|commit) ([0-9]+) ([0-9]+) ([0-9]+) (\S+)', line)
        require(match is not None, context + ': invalid cache event')
        index, kind, before, size, mask, path = match.groups()
        rows.append(dict(index=int(index), kind=kind, before=int(before),
                         count=int(size), mask=int(mask), path=path))
    require([r['index'] for r in rows] == list(range(count)),
            context + ': missing or reordered cache events')
    return rows


def classify_cache(events, wire, context):
    require(len(wire) == 5, context + ': expected five nonempty wire connections')
    current_count, current_mask = 1, 1
    draws, commits, roots_before, roots_after = [], 0, [], []
    for row in events:
        if row['kind'] == 'commit':
            require(row['before'] == current_count and row['count'] == 21 and
                    row['mask'] == FULL_MASK and row['path'] == '-',
                    context + ': commit lost or failed to insert cache members')
            current_count, current_mask = row['count'], row['mask']
            commits += 1
        else:
            require(row['before'] == 0 and row['count'] == current_count and
                    row['mask'] == current_mask,
                    context + ': cache changed between commit and draw')
            match = re.fullmatch(r'/(?:h([0-9]|1[0-9]))?', row['path'])
            require(match is not None, context + ': unexpected selected path')
            bit = 0 if match[1] is None else int(match[1]) + 1
            require(row['mask'] & (1 << bit), context + ': selected a path absent from cache')
            draws.append(row['path'])
            if row['path'] == '/':
                (roots_after if commits else roots_before).append(row['index'])
    require(len(draws) == commits == 5, context + ': incomplete draw or commit coverage')
    require(Counter(draws) == Counter(row['paths'][0] for row in wire),
            context + ': selected paths disagree with transmitted paths')
    return dict(draws=len(draws), commits=commits, final_count=current_count,
                final_mask=current_mask, root_draws_before_commit=roots_before,
                root_draws_after_commit=roots_after,
                selected_paths=draws)


def analyze(root, *, native=False):
    plan = json.loads((root / 'plan.json').read_text())
    schema = 'native-cache-retention-trace-v1' if native else 'host-cache-retention-trace-v1'
    inputs = NATIVE_INPUTS if native else INPUTS
    originals = NATIVE_ORIGINALS if native else ORIGINALS
    observers = NATIVE_OBSERVERS if native else OBSERVERS
    require(plan.get('schema') == schema and
            plan.get('rounds') == 2 and plan.get('scenario') == 'closeafter' and
            plan.get('connections_per_phase') == 5 and plan.get('acceptance') is False,
            'unsupported cache trace plan')
    phases = [dict(round=n, role=role) for n, roles in
              ((1, ('ref', 'lc')), (2, ('lc', 'ref'))) for role in roles]
    require(plan.get('phases') == phases, 'cache trace must counterbalance paired role order')
    require(set(plan.get('inputs', {})) == inputs, 'incomplete cache trace input manifest')
    for name, expected in plan['inputs'].items():
        require(Path(name).name == name and hashlib.sha256((root / name).read_bytes()).hexdigest() == expected,
                'cache trace input changed: ' + name)
    sources = {}
    for line in (root / 'source.sha256').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None and match[2] not in sources, 'invalid source identity manifest')
        sources[match[2]] = match[1]
    observer = json.loads((root / 'observer-inputs.json').read_text())
    observer_schema = 'spider-cache-observers-native-v1' if native else 'spider-cache-observers-v1'
    require(observer.get('schema') == observer_schema and
            set(observer.get('originals', {})) == originals and
            all(sources.get(name) == digest for name, digest in observer['originals'].items()) and
            set(observer.get('observers', {})) == observers and
            all(plan['inputs'][name] == digest for name, digest in observer['observers'].items()),
            'observer source identity differs from the frozen originals or generated files')
    state = json.loads((root / 'run-state.json').read_text())
    require(state.get('exit_code') == state.get('cleanup_exit') == 0 and
            state.get('phases_completed') == 4, 'cache trace driver or cleanup failed')
    records = parse_records((root / 'dest.log').read_text())
    empty = [r for r in records if r['bytes'] == 0]
    require(all(not r['paths'] and not r['frames'] and r['prefaces'] == 0 and not r['invalid']
                for r in empty), 'invalid empty cache trace preflight')
    wire = [r for r in records if r['bytes'] != 0]
    require(len(wire) == 20 and all(r['scenario'] == 'closeafter' and
            r['role'] in ('lc', 'ref') and r['sample'] in (1, 2) for r in wire),
            'cache trace wire coverage differs from the plan')
    result = []
    for phase in phases:
        key = f"{phase['round']}-{phase['role']}"
        receipt = json.loads((root / (key + '.json')).read_text())
        binary = 'lc.trace' if phase['role'] == 'lc' else 'xray.trace'
        require(receipt == dict(phase=phase, alive_before_probe=True, alive_after_probe=True,
                binary_sha256=plan['inputs'][binary], probe_exit=receipt.get('probe_exit'),
                stop_signal=15, client_exit=(143 if native else -15) if phase['role'] == 'lc' else 0) and
                receipt['probe_exit'] in (52, 56),
                key + ': invalid launched binary, liveness, probe or exit receipt')
        group = [r for r in wire if (r['sample'], r['role']) == (phase['round'], phase['role'])]
        validate_rows(group, 'closeafter', phase['round'])
        events = parse_cache((root / (key + '.log')).read_text(), key)
        result.append(dict(phase=phase, **classify_cache(events, group, key)))
    result = dict(G2Closed=False, acceptance=False, connections=20, phases=result,
                limitations=['Instrumentation is not timing, frequency or G2 acceptance evidence.',
                             'Path multisets match per phase; cache events are not linked to individual sockets.',
                             'A legal root draw after commit does not imply cache loss.',
                             'This diagnostic does not replace or revise the ordinary checkpoint.'])
    if native:
        result['minimum_sampled_memavailable_kib'] = validate_native(root, plan, phases)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--native', action='store_true', help='Require native plan and device guards.')
    args = parser.parse_args()
    result = analyze(args.directory, native=args.native)
    print(json.dumps(result, indent=2))
