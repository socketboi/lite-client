"""Replay private native/DNS/policy coexistence evidence; no device access."""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re

BODY_SHA = hashlib.sha256(bytes(range(256)) * 4096).hexdigest()
INPUTS = frozenset({
    'auth', 'obfs', 'uuid', 'cert.pem', 'probe', 'upload-token',
    'native-policy-soak.sh', 'router-lib.sh', 'plane-reality.sh',
    'plane-hysteria.sh', 'reality.response', 'hysteria.response',
    'domains-base', 'dns-addresses.conf', 'settings.sh', 'policy-seed.json',
})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]


def domain_name(value):
    return isinstance(value, str) and len(value) <= 253 and re.fullmatch(
        r'[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})*', value) is not None


def owner_set(name):
    return 'p4d_' + hashlib.sha256(name.encode('ascii')).hexdigest()[:32]


def address(value, family):
    require(isinstance(value, str), 'invalid policy address')
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError('invalid policy address') from exc
    require(parsed.version == family, 'policy address family mismatch')
    return int(parsed)


def addresses(values, family):
    require(isinstance(values, list), 'invalid policy address list')
    parsed = {address(value, family) for value in values}
    require(len(parsed) == len(values), 'duplicate policy address')
    return parsed


def intervals(values):
    """IPv4 union entries, without expanding potentially large CIDR ranges."""
    require(isinstance(values, list), 'invalid IPv4 union')
    result = []
    for value in values:
        if isinstance(value, str) and '/' not in value and '-' not in value:
            first = last = address(value, 4)
        elif isinstance(value, str) and '-' in value:
            parts = value.split('-')
            require(len(parts) == 2, 'invalid IPv4 interval')
            first, last = (address(part, 4) for part in parts)
        elif isinstance(value, dict) and set(value) == {'range'}:
            parts = value['range']
            require(isinstance(parts, list) and len(parts) == 2, 'invalid IPv4 interval')
            first, last = (address(part, 4) for part in parts)
        else:
            if isinstance(value, dict) and set(value) == {'prefix'}:
                prefix = value['prefix']
                require(isinstance(prefix, dict) and set(prefix) == {'addr', 'len'} and
                        type(prefix['len']) is int and 0 <= prefix['len'] <= 32,
                        'invalid IPv4 prefix')
                address(prefix['addr'], 4)
                value = prefix['addr'] + '/' + str(prefix['len'])
            require(isinstance(value, str) and '/' in value, 'invalid IPv4 union element')
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError('invalid IPv4 prefix') from exc
            require(network.version == 4, 'policy address family mismatch')
            first, last = int(network.network_address), int(network.broadcast_address)
        require(first <= last, 'reversed IPv4 interval')
        result.append((first, last))
    return result


def merged(interval_values):
    result = []
    for first, last in sorted(interval_values):
        if result and first <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(result[-1][1], last))
        else:
            result.append((first, last))
    return result


def policy(path, expected_names=None):
    metadata = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(metadata, dict) and type(metadata.get('version')) is int and metadata['version'] == 1 and
            isinstance(metadata.get('domains'), list), 'invalid policy metadata')
    owners, set_names = {}, set()
    for entry in metadata['domains']:
        require(isinstance(entry, dict) and domain_name(entry.get('name')), 'invalid policy owner')
        name = entry['name']
        require(name not in owners and entry.get('set') == owner_set(name) and
                entry['set'] not in set_names, 'duplicate or mismatched policy owner')
        owners[name] = (entry['set'], addresses(entry.get('ips'), 4), addresses(entry.get('ips6', []), 6))
        set_names.add(entry['set'])
    if expected_names is not None:
        require(metadata.get('initialized') is True and set(owners) == expected_names,
                'actual policy domains differ from the selected workload')
        require(all(ips and ips6 for _, ips, ips6 in owners.values()), 'policy owners are not warmed for A/AAAA')
    return owners, intervals(metadata.get('fallback_ips', []))


def kernel_policy(path, owners, fallback):
    snapshot = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(snapshot, dict) and isinstance(snapshot.get('nftables'), list),
            'invalid kernel snapshot')
    sets = {}
    for entry in snapshot['nftables']:
        require(isinstance(entry, dict), 'invalid kernel entry')
        if 'set' not in entry:
            continue
        value = entry['set']
        require(isinstance(value, dict) and isinstance(value.get('name'), str) and
                value.get('family') == 'inet' and value.get('table') == 'lc_policy_soak',
                'invalid kernel set namespace')
        require(value['name'] not in sets, 'duplicate kernel set')
        sets[value['name']] = value
    expected = {name + suffix for name, _, _ in owners.values() for suffix in ('', '_6')}
    require({name for name in sets if name.startswith('p4d_')} == expected,
            'kernel owner sets differ from the selected workload')
    want4, want6 = set(), set()
    for name, ips, ips6 in owners.values():
        for suffix, family, wanted in (('', 4, ips), ('_6', 6, ips6)):
            value = sets[name + suffix]
            require(value.get('type') == ('ipv4_addr' if family == 4 else 'ipv6_addr') and
                    value.get('flags', []) == [], 'invalid kernel owner type or flags')
            require(addresses(value.get('elem', []), family) == wanted, 'kernel owner addresses differ')
        want4.update(ips)
        want6.update(ips6)
    for name, kind, flags in (('domains_vpn', 'ipv4_addr', ['interval']),
                              ('domains_vpn6', 'ipv6_addr', [])):
        require(name in sets and sets[name].get('type') == kind and
                sets[name].get('flags', []) == flags, 'invalid kernel union type or flags')
    require(merged(intervals(sets['domains_vpn'].get('elem', []))) ==
            merged([(ip, ip) for ip in want4] + fallback), 'kernel IPv4 union differs')
    require(addresses(sets['domains_vpn6'].get('elem', []), 6) == want6, 'kernel IPv6 union differs')


def analyze(root):
    root = Path(root)
    plan = json.loads((root / 'plan.json').read_text(encoding='utf-8'))
    device, peer, stage = root / 'device-results', root / 'peer', root / 'stage'
    require(plan['schema'] == 'native-policy-coexistence-v2', 'unsupported evidence schema')
    require(plan.get('observer_timeouts') == dict(tcp_connect_seconds=20, tcp_total_seconds=30, udp_receive_seconds=20),
            'unexpected observer timeout budget')
    require(plan['phases'] in (['reality', 'hysteria'], ['hysteria', 'reality']),
            'both native planes are required exactly once')
    require(plan['active_seconds_per_plane'] >= 900, 'coexistence requires fifteen minutes per plane')
    require(type(plan['domains']) is int and plan['domains'] >= 1375, 'large policy workload is missing')
    require(plan['traffic_period'] == 10, 'unexpected traffic schedule')
    require(plan['resource_policy'] == 'flash-only' and plan['ram_limits'] is None, 'unexpected resource policy')
    require(set(plan['inputs']) == INPUTS, 'incomplete frozen input manifest')
    for name, digest in plan['inputs'].items():
        require(hashlib.sha256((stage / name).read_bytes()).hexdigest() == digest,
                'changed input: ' + name)
    selected = (stage / 'domains-base').read_text(encoding='utf-8').splitlines()
    require(all(domain_name(name) for name in selected) and len(selected) == len(set(selected)),
            'invalid or duplicate selected domains')
    require(len(selected) == plan['domains'], 'actual domain count differs from the plan')
    selected = set(selected)
    # A seed can be empty or belong to a previous selection. The timed workload
    # must finish with every selected owner populated in both address families.
    policy(stage / 'policy-seed.json')
    status = json.loads((device / 'result.json').read_text(encoding='utf-8'))
    require(status == dict(exit=0, cleanup=0, finished=1, profile_retained=True),
            'device workload or cleanup failed')
    for name in ('hostkeys', 'boot', 'interfaces'):
        require((device / (name + '-before')).read_bytes() ==
                (device / (name + '-after')).read_bytes(), 'unexpected change: ' + name)
    for name in ('oom', 'owner-dns'):
        require((device / (name + '-before.summary')).read_bytes() ==
                (device / (name + '-after.summary')).read_bytes(), 'resource failure or owner DNS restart: ' + name)
    before = dict(line.split(None, 1)[::-1] for line in (device / 'config-before').read_text(encoding='utf-8').splitlines())
    after = dict(line.split(None, 1)[::-1] for line in (device / 'config-after').read_text(encoding='utf-8').splitlines())
    for config in set(before) | set(after):
        if config != '/etc/config/lite-client':
            require(before.get(config) == after.get(config), 'unrelated configuration changed: ' + config)
    phases, traffic, operations = (rows(device / name) for name in
                                   ('phases.jsonl', 'traffic.jsonl', 'policy.jsonl'))
    require([(r['plane'], r['event']) for r in phases] ==
            [(p, e) for p in plan['phases'] for e in ('start', 'end')], 'incomplete phase boundaries')
    require(all(b['uptime'] >= a['uptime'] for a, b in zip(phases, phases[1:])),
            'overlapping or reversed phase boundaries')
    require(all(r['plane'] in plan['phases'] for r in operations), 'unexpected policy plane')
    expected_requests = set()
    processes = [line.split() for line in (device / 'processes.tsv').read_text(encoding='utf-8').splitlines()]
    worker_pids, other_lc_processes = {}, {}
    dns = {}
    for plane in plan['phases']:
        owners, fallback = policy(device / (plane + '.policy.json'), selected)
        kernel_policy(device / (plane + '.kernel.json'), owners, fallback)
        start, end = [r for r in phases if r['plane'] == plane]
        require(end['uptime'] - start['uptime'] >= plan['active_seconds_per_plane'], 'compressed phase: ' + plane)
        cases = [r for r in traffic if r['plane'] == plane]
        require(len(cases) >= plan['active_seconds_per_plane'] // 10 - 1, 'missing traffic bursts: ' + plane)
        require([r['burst'] for r in cases] == list(range(len(cases))), 'duplicate or missing burst')
        require(start['pid'] == end['pid'] and {r['pid'] for r in cases} == {start['pid']},
                'native process restarted')
        require(len({r['birth'] for r in cases}) == 1, 'native PID was reused')
        require(all(r['tcp'] == 4 and r['udp'] == 64 for r in cases), 'partial traffic burst')
        times = [r['uptime'] for r in cases]
        require(start['uptime'] <= times[0] <= start['uptime'] + 30, 'late workload start')
        # A policy transaction may outlast the timed window; final checkpoint
        # and consistency checks follow it. Require traffic across the planned
        # active window rather than treating those checks as missing traffic.
        deadline = start['uptime'] + plan['active_seconds_per_plane']
        require(deadline - times[-1] <= 30 and times[-1] <= end['uptime'],
                'workload ended before the timed window')
        require(all(abs(t - (start['uptime'] + r['burst'] * plan['traffic_period'])) <= 30
                    for t, r in zip(times, cases)), 'traffic schedule drift')
        require(all(0 < b - a <= 45 for a, b in zip(times, times[1:])), 'traffic observation gap')
        actions = [r for r in operations if r['plane'] == plane]
        require([r['cycle'] for r in actions] == list(range(len(actions))), 'missing policy cycles')
        require(len(actions) >= 8 and {r['operation'] for r in actions} ==
                {'checkpoint', 'apply', 'rollback'}, 'policy churn or rollback is missing')
        require(all(r['end'] >= r['start'] and r['pid'] == start['pid'] for r in actions),
                'policy operation changed the native process')
        require(all(start['uptime'] <= r['start'] < deadline and r['end'] <= end['uptime']
                    for r in actions), 'policy operation outside the timed phase')
        require(all(b['start'] >= a['end'] for a, b in zip(actions, actions[1:])),
                'overlapping or reversed policy operations')
        cohorts = {}
        for stamp, pid, name, rss, hwm, threads in processes:
            if name == 'lc-tunnel' and start['uptime'] + 10 < int(stamp) < end['uptime'] - 10:
                cohorts.setdefault(int(stamp), set()).add(int(pid))
        require(len(cohorts) >= 20, 'native worker observation is incomplete')
        # Readiness also invokes the binary (for example --planes). A process
        # inventory shares their comm with the service. Every member of the
        # modal service core must remain in every snapshot; replacing a worker
        # removes its old PID and fails this check. Report other PIDs explicitly.
        observed = Counter(frozenset(c) for c in cohorts.values())
        core = observed.most_common(1)[0][0]
        require(start['pid'] in core and all(core.issubset(c) for c in cohorts.values()),
                'native worker cohort changed')
        worker_pids[plane] = sorted(core)
        other_lc_processes[plane] = sorted(set().union(*cohorts.values()) - core)
        queries, failures = map(int, (device / (plane + '.dns.summary')).read_text(encoding='utf-8').split())
        require(queries >= 1000 and 0 <= failures < queries and queries - failures >= 512,
                'DNS workload is missing')
        dns[plane] = dict(queries=queries, failures=failures)
        for r in cases:
            for stream in range(1, 5):
                expected_requests.add((plane, r['burst'], stream))
    require(len(traffic) == sum(1 for r in traffic if r['plane'] in plan['phases']), 'unexpected plane')
    requests = rows(peer / 'http.jsonl')
    observed = []
    for request in requests:
        plane, burst, stream = request['path'].strip('/').split('/')
        observed.append((plane, int(burst), int(stream)))
        require(request['sha256'] == BODY_SHA and request['tls'] == (int(stream) in (2, 4)),
                'peer payload or TLS mismatch')
    require(len(observed) == len(set(observed)) and set(observed) == expected_requests,
            'missing or duplicate peer receipts')
    payloads = (device / 'payloads.sha256').read_text(encoding='utf-8').splitlines()
    require(len(payloads) == len(expected_requests) and all(line.split()[0] == BODY_SHA for line in payloads),
            'device payload hashes are incomplete')
    echoes = (peer / 'udp.jsonl').read_text(encoding='utf-8').splitlines()
    require(len(echoes) == len(set(echoes)) == len(traffic) * 64, 'missing or replayed UDP echoes')
    peer_status = json.loads((peer / 'stand-result.json').read_text(encoding='utf-8'))
    require(peer_status['exits'] == [0, 0, 0], 'peer termination failed')
    memory = [list(map(int, line.split())) for line in (device / 'memory.tsv').read_text(encoding='utf-8').splitlines()]
    require(memory and memory[0][0] <= phases[0]['uptime'] + 5 and
            memory[-1][0] >= phases[-1]['uptime'] - 10, 'resource observation is incomplete')
    peaks = {}
    for stamp, pid, name, rss, hwm, threads in processes:
        peaks[name] = max(peaks.get(name, 0), int(hwm))
    return dict(accepted=True, scope='bounded native/DNS/policy coexistence on a lab router',
                phases=plan['phases'], seconds_per_plane=plan['active_seconds_per_plane'],
                domains=len(selected), tcp_payloads=len(payloads), tcp_bytes=len(payloads) * 1048576,
                udp_echoes=len(echoes), dns=dns, policy_operations=len(operations), worker_pids=worker_pids,
                other_lc_processes=other_lc_processes,
                observer_timeouts=plan['observer_timeouts'],
                minimum_sampled_available_kib=min(r[1] for r in memory), sampled_peak_hwm_kib=peaks,
                resource_policy='flash-only', ram_limits=None, performance_comparison=False,
                limitations=['Owned DNS service and nft namespace; API is a frozen local fixture.',
                             'Loopback interception checks policy membership; this is not a LAN/NAT or production rollout test.',
                             'Phase end includes policy verification after the timed traffic window.',
                             'One-second process sampling is a lower bound for short-lived tools.',
                             'Stable process core is inferred from inventory; other same-name PIDs are reported without PPID or command-line classification.',
                             'DNS timeouts during deliberate resolver restarts are counted separately.',
                             'Unclassified pre-HTTP peer terminations: ' + str(len(peer_status.get('errors', [])))])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.directory), indent=2))
