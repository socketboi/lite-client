"""Frozen native four-scenario checkpoint design; no acceptance is granted here."""

import shlex
from analyze_checkpoint import SCENARIOS, ROLES, checkpoint_criteria
from analyze_network import require

DEVICE_INPUTS = frozenset({'lc-tunnel.native', 'reference.native', 'client.pb',
                          'fingerprint.fpt', 'ca.pem', 'settings.sh', 'phases.tsv',
                          'native-device.sh'})
NATIVE_INPUTS = DEVICE_INPUTS | frozenset({'client.json', 'server.json', 'reference.host',
    'dest.host', 'leaf.pem', 'leaf.key', 'device.json', 'settings.json', 'source.sha256',
    'native_checkpoint.py', 'analyze_native_checkpoint.py', 'native_checkpoint_plan.py',
    'analyze_checkpoint.py', 'analyze_network.py', 'checkpoint_process.py'})


def phase_table(plan):
    return ''.join(f"{p['id']}\t{p['round']}\t{p['role']}\t{p['scenario']}\n" for p in plan['phases'])


def device_settings(config, identity, client):
    require(set(identity) == {'board_name', 'boot_id', 'architecture'}, 'invalid device identity')
    require(identity['architecture'] in ('mipsel', 'aarch64'), 'unsupported device architecture')
    require(config['max_seconds'] == 1200 and config['startup_wait_seconds'] == 2 and
            config['quiet_wait_seconds'] == 6, 'native runner timing guards changed')
    peer = client['outbounds'][0]['settings']['vnext'][0]
    tls = client['outbounds'][0]['streamSettings']['realitySettings']
    values = dict(EXPECTED_BOARD=identity['board_name'], EXPECTED_BOOT=identity['boot_id'],
        CONTROL_URL=f"http://{config['advertised_host']}:{config['control_port']}",
        CONTROL_TOKEN=config['control_token'], SERVER_ADDRESS=peer['address'],
        SERVER_PORT=peer['port'], SERVER_NAME=tls['serverName'], WRONG_KEY=tls['publicKey'],
        SHORT_ID=tls['shortId'], UUID=peer['users'][0]['id'])
    require(peer['address'] == config['advertised_host'] and peer['port'] == 14480,
            'native client and advertised stand differ')
    require(all(isinstance(v, (str, int)) and '\n' not in str(v) and '\r' not in str(v)
                for v in values.values()), 'invalid native settings value')
    return ''.join(key+'='+shlex.quote(str(value))+'\n' for key, value in values.items())


def make_plan():
    phases = []
    for n in (1, 2, 3):
        first = list(SCENARIOS[:-1])
        shift = n - 1
        for sc in first[shift:] + first[:shift] + ['closeafter']:
            roles = ROLES if (n + SCENARIOS.index(sc)) % 2 else tuple(reversed(ROLES))
            for role in roles:
                phases.append(dict(id=len(phases), round=n, condition='local',
                                   role=role, scenario=sc, sample=n))
    plan = dict(schema='native-g2-checkpoint-v4', rounds=3, scenarios=list(SCENARIOS),
                phases=phases, expected_connections_per_phase=5,
                expected_total_connections=120, acceptance_scope='checkpoint', criteria_frozen=True,
                criteria=checkpoint_criteria(),
                resource_policy='flash-only', max_device_seconds=1200,
                network='Same device and LAN/server path; no configured netem.',
                journals='Device tmpfs and container-local storage; export after cleanup.')
    validate_plan(plan)
    return plan


def validate_plan(plan):
    require(plan['schema'] == 'native-g2-checkpoint-v4' and plan['rounds'] == 3 and
            plan['scenarios'] == list(SCENARIOS) and
            plan.get('acceptance_scope') == 'checkpoint' and 'G2Closed' not in plan and
            plan.get('criteria_frozen') is True and
            plan['criteria'] == checkpoint_criteria(),
            'unsupported native checkpoint design')
    require(plan['expected_connections_per_phase'] == 5 and
            plan['expected_total_connections'] == 120 and
            plan.get('resource_policy') == 'flash-only' and 'guard_memavailable_kib' not in plan and
            plan['max_device_seconds'] == 1200,
            'native checkpoint count or guard changed')
    phases = plan['phases']
    require(len(phases) == 24 and [p['id'] for p in phases] == list(range(24)),
            'native checkpoint phase IDs')
    require({(p['round'], p['role'], p['scenario'], p['sample'], p['condition']) for p in phases}
            == {(n, role, sc, n, 'local') for n in (1, 2, 3) for role in ROLES for sc in SCENARIOS},
            'native checkpoint coverage')
    orders = {sc: set() for sc in SCENARIOS}
    for n in (1, 2, 3):
        group = phases[(n - 1) * 8:n * 8]
        require(all(p['round'] == n for p in group), 'native checkpoint round order')
        require(all(p['scenario'] == 'closeafter' for p in group[-2:]),
                'closeafter must finish each native round')
        for first, second in zip(group[::2], group[1::2]):
            require(first['scenario'] == second['scenario'] and
                    {first['role'], second['role']} == set(ROLES), 'unpaired native checkpoint')
            orders[first['scenario']].add(first['role'])
    require(all(order == set(ROLES) for order in orders.values()),
            'native checkpoint lacks per-scenario role counterbalance')
