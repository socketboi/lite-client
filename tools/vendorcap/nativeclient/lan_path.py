"""Replay isolated LAN/NAT/TPROXY receipts from an explicitly designated lab router."""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path

from policy_soak import BODY_SHA, require, rows

INPUTS = frozenset({'native-lan.sh', 'router-lib.sh', 'plane-reality.sh', 'plane-hysteria.sh',
                    'probe', 'cert.pem', 'settings.sh', 'reality.response', 'hysteria.response'})
PEER_INPUTS = frozenset({'stand.py', 'xray', 'hysteria', 'cert.pem', 'key.pem', 'upload-token',
                         'none.json', 'salamander.json', 'reality.json'})
LABELS = ('nat', 'reality-selected', 'reality-direct', 'reality-reloaded',
          'hysteria-selected', 'hysteria-direct', 'hysteria-reloaded')


def check_inputs(directory, hashes, required):
    require(isinstance(hashes, dict) and set(hashes) == required, 'incomplete frozen inputs')
    for name, expected in hashes.items():
        require(hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected, 'changed input: ' + name)


def check_certificate_paths(value):
    if isinstance(value, list):
        for child in value:
            check_certificate_paths(child)
    elif isinstance(value, dict):
        paths = {'cert': 'cert.pem', 'key': 'key.pem', 'certificateFile': 'cert.pem', 'keyFile': 'key.pem'}
        for name, child in value.items():
            if name in paths:
                require(child == paths[name], 'unfrozen peer certificate path')
            else:
                check_certificate_paths(child)


def analyze(root):
    plan = json.loads((root / 'plan.json').read_text(encoding='utf-8'))
    require(plan.get('schema') == 'native-lan-path-v1', 'unsupported LAN plan')
    peer_ip, wan_ip, client_ip = (str(ipaddress.IPv4Address(plan[key])) for key in ('peer_ipv4', 'wan_ipv4', 'client_ipv4'))
    require(len({peer_ip, wan_ip, client_ip}) == 3, 'LAN path endpoints overlap')
    stage, device, peer = (root / name for name in ('stage', 'device', 'peer'))
    check_inputs(stage, plan['inputs'], INPUTS)
    check_inputs(peer, plan['peer_inputs'], PEER_INPUTS)
    for name in ('none.json', 'salamander.json', 'reality.json'):
        check_certificate_paths(json.loads((peer / name).read_text()))
    status = json.loads((device / 'result.json').read_text())
    require(status == dict(exit=0, cleanup=0, finished=1, profile_retained=True), 'LAN workload or cleanup failed')
    for name in ('hostkeys', 'service', 'boot', 'interfaces', 'rules', 'routes', 'rules6', 'routes6', 'oom', 'dns'):
        before, after = ((device / (name + '-' + side)).read_bytes() for side in ('before', 'after'))
        require(before == after and (name in ('oom', 'routes6') or bool(before)), 'unexpected change or missing observation: ' + name)
    require((device / 'service-before').read_text().split()[0] == plan['service_sha256'], 'unexpected installed service bytes')
    configs = [dict(line.split(None, 1)[::-1] for line in (device / ('config-' + side)).read_text().splitlines())
               for side in ('before', 'after')]
    for name in set(configs[0]) | set(configs[1]):
        if name != '/etc/config/lite-client':
            require(configs[0].get(name) == configs[1].get(name), 'unrelated configuration changed')
    traffic = rows(device / 'traffic.jsonl')
    require(traffic == [dict(label=label, tcp=4, udp=64) for label in LABELS], 'incomplete or reordered LAN traffic')
    expected_requests = {(label, stream) for label in LABELS for stream in range(1, 5)}
    payloads = [line.split('\t') for line in (device / 'payloads.tsv').read_text().splitlines()]
    require(len(payloads) == len(expected_requests) and {(p[0], int(p[1])) for p in payloads} == expected_requests and
            all(p[2] == BODY_SHA for p in payloads), 'incomplete or corrupt LAN payloads')
    receipts = rows(peer / 'http.jsonl')
    seen = set()
    direct = {label for label in LABELS if label == 'nat' or label.endswith('-direct')}
    for receipt in receipts:
        label, burst, stream = receipt['path'].strip('/').split('/')
        stream = int(stream)
        require((label, stream) in expected_requests and (label, stream) not in seen and burst == '0', 'unexpected or duplicate LAN receipt')
        require(receipt['remote'] == (wan_ip if label in direct else peer_ip), 'NAT/proxy source mismatch')
        require(receipt['sha256'] == BODY_SHA and receipt['tls'] == (stream in (2, 4)), 'LAN payload or TLS mismatch')
        seen.add((label, stream))
    require(seen == expected_requests, 'missing LAN peer receipts')
    echoes = rows(peer / 'udp-remote.jsonl')
    require(len(echoes) == len(LABELS) * 64 and len({row['sha256'] for row in echoes}) == len(echoes), 'missing or replayed LAN UDP echoes')
    require(Counter(row['remote'] for row in echoes) == Counter({wan_ip: len(direct) * 64, peer_ip: (len(LABELS) - len(direct)) * 64}),
            'UDP NAT/proxy source mismatch')
    for index, label in enumerate(LABELS):
        require(all(row['remote'] == (wan_ip if label in direct else peer_ip) for row in echoes[index * 64:(index + 1) * 64]),
                'UDP source differs from the selected LAN path')
        require(json.loads((device / (label + '.udp.json')).read_text()) == dict(echoes=64, bytes=8192), 'incomplete device UDP echoes')
    for plane in ('reality', 'hysteria'):
        kernel = json.loads((device / (plane + '.kernel.json')).read_text())
        rules = [row['rule'] for row in kernel['nftables'] if 'rule' in row]
        require(len(rules) == 2 and all(rule['family'] == 'inet' and rule['table'] == 'lc_lan_path' and rule['chain'] == 'inbound'
                for rule in rules), 'unexpected LAN kernel rules')
        counters = [expr['counter'] for rule in rules for expr in rule['expr'] if 'counter' in expr]
        require(len(counters) == 2 and all(type(counter['packets']) is int and counter['packets'] > 0 for counter in counters),
                'LAN TCP/UDP interception counters are missing')
    phases = rows(device / 'phases.jsonl')
    require([p['plane'] for p in phases] == ['reality', 'hysteria'] and
            all(type(p['pid']) is int and p['pid'] > 0 and p['stable'] is True and p['firewall_reload'] is True for p in phases), 'incomplete LAN lifecycle')
    peer_state = json.loads((peer / 'stand-result.json').read_text())
    require(peer_state['exits'] == [0, 0, 0], 'LAN reference shutdown failed')
    return dict(accepted=True, tcp_bytes=len(payloads) * 1048576, udp_echoes=len(echoes), paths=list(LABELS),
                nat_source_verified=True, real_fw4_reload=True,
                limitations=['A veth namespace supplies LAN ingress through the lab bridge; no physical LAN cable is exercised.',
                             'API responses are frozen fixtures; this does not qualify production API delivery.',
                             'This is a correctness check, not a throughput comparison.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    print(json.dumps(analyze(parser.parse_args().directory), indent=2))
