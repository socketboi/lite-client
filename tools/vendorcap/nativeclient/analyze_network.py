"""Validate a bounded paired native network diagnostic, never grant G2 acceptance."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import statistics
import tarfile


class EvidenceError(ValueError):
    pass


# vendor/x-net/http2/transport.go::newClientConn opening SETTINGS, with the
# pinned transport defaults. Order and payload length are observable wire data.
OPENING_SETTINGS = ('[24] SETTINGS ack=false [ENABLE_PUSH = 0] '
                    '[INITIAL_WINDOW_SIZE = 4194304] [MAX_FRAME_SIZE = 1048576] '
                    '[MAX_HEADER_LIST_SIZE = 10485760]')


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def parse_records(text):
    records = []
    current = None
    for line in text.splitlines():
        match = re.fullmatch(r'(\S+) (\w+) \| ([0-9]+) bytes', line)
        if match:
            current = dict(role=match[1], scenario=match[2], bytes=int(match[3]),
                           sample=None, prefaces=0, cancel=0, paths=[], frames=[],
                           first_request_us=None, clock=None, invalid=False)
            records.append(current)
        elif current is not None:
            match = re.fullmatch(r'  sample ([0-9]+)', line)
            if match:
                current['sample'] = int(match[1])
            if line.startswith('  PREFACE'):
                current['prefaces'] += 1
            if re.match(r'  \[[0-9]+\]\s+RST_STREAM stream=1 CANCEL(?:\s|$)', line):
                current['cancel'] += 1
            if line.startswith('    :path: '):
                current['paths'].append(line.split(':path: ', 1)[1])
            if line.startswith('  timing clock='):
                current['clock'] = line.split('clock=', 1)[1]
            match = re.match(r'  timing r\+([0-9]+) .*HEADERS1e', line)
            if match and current['first_request_us'] is None:
                current['first_request_us'] = int(match[1])
            if re.search(r'frame error:|bytes left undecoded:|bytes that are not a preface:', line):
                current['invalid'] = True
            if re.match(r'  \[[0-9]+\]', line):
                current['frames'].append(re.sub(r'^(\[[0-9]+\])\s+', r'\1 ', line.strip()))
    return records


def validate_group(rows, count, context):
    require(len(rows) == count, f'{context}: connection count {len(rows)}, expected {count}')
    for row in rows:
        require(row['bytes'] > 0 and row['prefaces'] == 1 and not row['invalid'],
                f'{context}: invalid frame capture')
        require(row['cancel'] in (0, 1), f'{context}: duplicate CANCEL')
        require(row['clock'] == 'io-return-v2' and row['first_request_us'] is not None,
                f'{context}: missing receiver timing')
        target = {'bigbody': '/bb', 'gzbody': '/gz'}[row['scenario']]
        require(row['paths'] == ['/', target], f'{context}: unexpected redirect paths')
        settings = [line for line in row['frames'] if 'SETTINGS ack=false' in line]
        require(settings == [OPENING_SETTINGS] and row['frames'][0] == OPENING_SETTINGS,
                f'{context}: opening SETTINGS differ from pinned reference')
        require(len(row['frames']) >= 2 and
                row['frames'][1] == '[4] WINDOW_UPDATE stream=0 +1073741824',
                f'{context}: opening window credit differs from pinned reference')
        for stream in (1, 3):
            require(any(f'HEADERS stream={stream} end=true' in line for line in row['frames']),
                    f'{context}: missing stream {stream} HEADERS')


def frame_order(row):
    """Keep control order and credit values; omit randomized HPACK size/field ordering."""
    return tuple(frame.partition(']')[2].strip().split(' order=', 1)[0]
                 for frame in row['frames'])


def credit_before_redirect_headers(row):
    frames = frame_order(row)
    first = frames.index('HEADERS stream=1 end=true')
    following = frames.index('HEADERS stream=3 end=true')
    credits = [i for i, frame in enumerate(frames) if i > first
               and frame.startswith('WINDOW_UPDATE stream=0 +')]
    return bool(credits and min(credits) < following)


def host_control(root, records):
    require((root / 'host-control.log').read_text().rstrip().endswith('HOST_CONTROL_EXIT=0'),
            'host reference control did not finish')
    result = {}
    for role, name in [('ref', 'full'), ('lc', 'selected')]:
        for sample, scenario in [(19, 'bigbody'), (20, 'gzbody')]:
            rows = [r for r in records if r['role'] == role and r['sample'] == sample
                    and r['scenario'] == scenario]
            validate_group(rows, 5, f'host {name} {scenario}')
            result[f'{name}-{scenario}'] = dict(connections=len(rows), cancel=sum(r['cancel'] for r in rows))
    require(sum(r['sample'] in (19, 20) for r in records) == 20,
            'unexpected host-control records')
    return result


def cpu_ticks(text):
    prefix, separator, remainder = text.rpartition(') ')
    identity = re.fullmatch(r'([0-9]+) \((.*)', prefix)
    fields = remainder.split()
    require(separator and identity is not None and len(fields) >= 20, 'invalid proc stat')
    user, system, born = int(fields[11]), int(fields[12]), int(fields[19])
    require(user >= 0 and system >= 0 and born > 0, 'invalid proc CPU/start counters')
    ticks = user + system
    return ticks, (int(identity[1]), identity[2], born)


def qdisc_delay(text):
    require(text.startswith('qdisc netem '), 'unexpected qdisc')
    drops = re.findall(r'\(dropped ([0-9]+),', text)
    require(drops == ['0'], 'netem dropped packets')
    match = re.search(r' delay ([0-9.]+)(ms|us|s)\b', text)
    if match is None:
        return 0  # iproute2 omits the delay attribute when it is zero.
    return float(match[1]) * {'ms': 1, 'us': .001, 's': 1000}[match[2]]


def memory_coverage(log, keys, floor):
    """Check the one-second monitor across staging and every serial phase.

    Two missed ticks are tolerated for scheduling and whole-second timestamps.
    Each phase includes two seconds of startup and six seconds after the probe;
    coverage shorter than those fixed waits cannot describe the complete phase.
    Host and device wall clocks are deliberately not assumed synchronized.
    """
    samples = []
    for line in log.splitlines():
        match = re.fullmatch(r'([0-9]+) ([0-9]+) ?(\S*)', line)
        require(match is not None, 'invalid memory sample')
        samples.append((int(match[1]), int(match[2]), match[3]))
    require(samples and min(row[1] for row in samples) >= floor,
            'memory safety floor crossed')
    require(all(0 < right[0] - left[0] <= 3 for left, right in zip(samples, samples[1:])),
            'memory monitor has missing or reordered ticks')
    blocks = []
    for stamp, available, phase in samples:
        if not blocks or blocks[-1][0] != phase:
            blocks.append((phase, []))
        blocks[-1][1].append(stamp)
    require([phase for phase, _ in blocks] == ['', *keys],
            'memory monitor does not cover staging and all ordered phases')
    for phase, stamps in blocks[1:]:
        require(len(stamps) >= 8 and stamps[-1] - stamps[0] >= 7,
                f'{phase}: incomplete memory coverage of fixed phase waits')
    return samples


def analyze(root, host_only=False):
    records = parse_records((root / 'dest.log').read_text())
    result = {'G2Closed': False, 'host_control': host_control(root, records)}
    if host_only:
        return result
    plan = json.loads((root / 'plan.json').read_text())
    phases = plan['phases']
    require(plan['G2Closed'] is False and plan['criteria_changed'] is False,
            'diagnostic plan must not grant acceptance or change criteria')
    require(plan['guard_memavailable_kib'] >= 4096, 'memory guard weakened')
    require([p['id'] for p in phases] == list(range(len(phases))) and phases,
            'phase IDs must be contiguous')
    keys = [(p['role'], p['scenario'], p['sample']) for p in phases]
    require(len(set(keys)) == len(keys), 'duplicate capture labels')
    per_phase = plan['expected_connections_per_phase']
    require(per_phase == 5 and plan['expected_total_connections'] == len(phases) * per_phase,
            'unexpected planned connection count')
    for phase in phases:
        require(phase['role'] in ('lc', 'ref') and phase['scenario'] in ('bigbody', 'gzbody'),
                'unsupported diagnostic role/scenario')
        require(1 <= phase['sample'] <= 18, 'invalid or reserved native sample label')
        require(phase['condition'] in ('local', 'egress20') and
                phase['delay_ms'] == {'local': 0, 'egress20': 20}[phase['condition']],
                'unexpected planned network condition')
    with tarfile.open(root / 'device.tar.gz') as archive:
        entries = [m for m in archive.getmembers() if m.isfile()]
        names = [m.name.removeprefix('./') for m in entries]
        require(len(set(names)) == len(names), 'duplicate archive members')
        files = {name: archive.extractfile(member).read() for name, member in zip(names, entries)}
    def text(name):
        require(name in files, f'missing device evidence: {name}')
        return files[name].decode()
    require(text('result.exit').strip() == '0' and text('restore.exit').strip() == '0',
            'device or restoration failed')
    require(not {'resource-stop', 'forced-stop'} & files.keys(), 'resource guard or forced stop')
    require(files['boot-before'] == files['boot-after'], 'device rebooted')
    require(text('plan.json') == (root / 'plan.json').read_text(), 'device plan changed')
    checks = text('config-after.log').splitlines()
    require(checks and all(line.endswith(': OK') for line in checks), 'device configuration changed')
    manifest = {}
    for line in text('inputs.sha256').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([a-zA-Z0-9._-]+)', line)
        require(match is not None and match[2] not in manifest, 'invalid input manifest')
        manifest[match[2]] = match[1]
    require(set(manifest) == {'lc-tunnel.mips', 'reference.mips', 'client.pb', 'wrong',
                              'ca.pem', 'fingerprint.fpt', 'plan.json', 'phases.tsv'},
            'unexpected manifest coverage')
    for name, digest in manifest.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest,
                f'host input changed: {name}')
        if name in files:
            require(hashlib.sha256(files[name]).hexdigest() == digest,
                    f'device input changed: {name}')
    require(Counter(text('verified-inputs.log').splitlines()) ==
            Counter(name + ': OK' for name in manifest), 'unverified device inputs')
    completed = re.findall(r'^PROBE_COMPLETE phase=([0-9]+) role=(\w+) scenario=(\w+) condition=(\w+)$',
                           text('run.log'), re.M)
    require(completed == [(str(p['id']), p['role'], p['scenario'], p['condition']) for p in phases],
            'incomplete or reordered probes')
    require('PAIRED_NETWORK_NATIVE_COMPLETED=1' in text('run.log'), 'missing completion marker')
    controls = [json.loads(line) for line in (root / 'controls.jsonl').read_text().splitlines()]
    require(len(controls) == len(phases), 'controller phase count')
    selected = [r for r in records if (r['role'], r['scenario'], r['sample']) in keys]
    require(len(selected) == plan['expected_total_connections'], 'native connection count')
    excluded_empty = 0
    for row in records:
        if (row['role'], row['scenario'], row['sample']) in keys or row['sample'] in (19, 20):
            continue
        require(row['bytes'] == 0 and row['sample'] is None and row['scenario'] == 'none'
                and row['role'] not in ('lc', 'ref'), 'unplanned wire capture')
        excluded_empty += 1
    phase_results, phase_keys = [], []
    for phase, control in zip(phases, controls):
        context = f"phase {phase['id']}"
        require(control['phase'] == phase, context + ': controller differs from plan')
        require(qdisc_delay(control['qdisc']) == phase['delay_ms'], context + ': wrong qdisc delay')
        qdisc_delay(control['previous_qdisc'])
        key = f"{phase['id']}-{phase['condition']}-{phase['role']}-{phase['scenario']}-{phase['sample']}"
        phase_keys.append(key)
        require(json.loads(text(key + '.control')) == phase, context + ': device control response')
        require(qdisc_delay(text(key + '.qdisc')) == phase['delay_ms'], context + ': final qdisc')
        # The wrong-key request must reach the client and finish by peer closure.
        # Timeout, connection refusal and local curl failures do not prove this.
        require(text(key + '.probe-exit').strip() in ('52', '56'),
                context + ': wrong-key probe did not finish by empty reply or receive failure')
        rows = [r for r in selected if (r['role'], r['scenario'], r['sample']) ==
                (phase['role'], phase['scenario'], phase['sample'])]
        validate_group(rows, per_phase, context)
        before, birth_before = cpu_ticks(text(key + '.before.stat'))
        after, birth_after = cpu_ticks(text(key + '.after.stat'))
        require(birth_before == birth_after and after >= before, context + ': process changed')
        status = text(key + '.final.status')
        rss = re.search(r'^VmRSS:\s+([0-9]+) kB$', status, re.M)
        hwm = re.search(r'^VmHWM:\s+([0-9]+) kB$', status, re.M)
        threads = re.search(r'^Threads:\s+([0-9]+)$', status, re.M)
        require(rss is not None and hwm is not None and threads is not None,
                context + ': missing process resource counters')
        phase_results.append(dict(phase=phase, cancel=sum(r['cancel'] for r in rows),
                                  cpu_ticks=after - before,
                                  final_rss_kib=int(rss[1]), reported_hwm_kib=int(hwm[1]),
                                  final_threads=int(threads[1]),
                                  first_request_us_median=statistics.median(r['first_request_us'] for r in rows)))
    summaries = []
    for condition in ('local', 'egress20'):
        for scenario in ('bigbody', 'gzbody'):
            for role in ('lc', 'ref'):
                group = [r for r in phase_results if all(r['phase'][k] == v for k, v in
                         [('condition', condition), ('scenario', scenario), ('role', role)])]
                require(group, 'missing condition/scenario/role')
                samples = {r['phase']['sample'] for r in group}
                captures = [r for r in selected if r['role'] == role and r['scenario'] == scenario
                            and r['sample'] in samples]
                orders = Counter(frame_order(r) for r in captures)
                summaries.append(dict(condition=condition, scenario=scenario, role=role,
                                      retry_groups=len(group), connections=len(group) * per_phase,
                                      cancel=sum(r['cancel'] for r in group),
                                      group_cancel_counts=[r['cancel'] for r in group],
                                      cpu_ticks_per_group_median=statistics.median(r['cpu_ticks'] for r in group),
                                      maximum_reported_hwm_kib=max(r['reported_hwm_kib'] for r in group),
                                      final_threads_max=max(r['final_threads'] for r in group),
                                      credit_before_redirect_headers=sum(credit_before_redirect_headers(r) for r in captures),
                                      frame_order_variants=[dict(connections=n, frames=list(order))
                                                            for order, n in orders.items()],
                                      first_request_us_group_median=statistics.median(r['first_request_us_median'] for r in group)))
    samples = memory_coverage(text('memory.log'), phase_keys, plan['guard_memavailable_kib'])
    result.update(native=summaries, phases=phase_results, excluded_empty_preflights=excluded_empty,
                  minimum_memavailable_kib=min(int(row[1]) for row in samples),
                  memory_samples=len(samples),
                  binary_sha256={name: manifest[name] for name in ('lc-tunnel.mips', 'reference.mips')},
                  limitations=['Related retries are not independent connections.',
                               'CPU is raw process ticks after startup, including the post-probe interval; tick frequency is not measured.',
                               'One-second resource samples miss short-lived threads and peaks.',
                               'Only server eth0 egress is delayed, not both directions.',
                               'This diagnostic never grants G2 acceptance or changes its thresholds.'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--host-only', action='store_true')
    args = parser.parse_args()
    result = analyze(args.directory, args.host_only)
    (args.directory / ('host-analysis.json' if args.host_only else 'analysis.json')).write_text(
        json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
