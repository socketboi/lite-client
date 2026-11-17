import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from lan_path import BODY_SHA, INPUTS, PEER_INPUTS, LABELS, analyze


class LanFirewallEnvironmentTests(unittest.TestCase):
    def test_real_firewall_receives_owner_paths_and_preserves_its_exit_code(self):
        source = Path(__file__).with_name('native-lan.sh').read_text()
        function = 'fw4() (\n' + source.split('\nfw4() (\n', 1)[1].split('\n)', 1)[0] + '\n)\n'
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'fw4'
            binary.write_text('''#!/bin/sh
[ "$1" = reload ] || exit 80
[ -z "${INSTALL_DIR+x}${SHARE_DIR+x}${ROUTER_RUNTIME_DIR+x}${VPN_PLANE_LOCK+x}" ] || exit 81
exit "$FW4_TEST_RC"
''')
            binary.chmod(0o700)
            script = '''PATH="$1:$PATH"; export PATH
INSTALL_DIR=private; SHARE_DIR=private; ROUTER_RUNTIME_DIR=private; VPN_PLANE_LOCK=private
export INSTALL_DIR SHARE_DIR ROUTER_RUNTIME_DIR VPN_PLANE_LOCK
FW4_TEST_RC=$2; export FW4_TEST_RC
''' + function + '''
if fw4 reload; then result=0; else result=$?; fi
[ "$INSTALL_DIR" = private ] && [ "$SHARE_DIR" = private ] || exit 82
exit "$result"
'''
            for code in (0, 17):
                with self.subTest(firewall_exit=code):
                    result = subprocess.run(['sh', '-ec', script, 'fixture', directory, str(code)], capture_output=True)
                    self.assertEqual(result.returncode, code, result.stderr)


class LanPathTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.device, self.peer, self.stage = (self.root / name for name in ('device', 'peer', 'stage'))
        for directory in (self.device, self.peer, self.stage):
            directory.mkdir()
        hashes = []
        for directory, names in ((self.stage, INPUTS), (self.peer, PEER_INPUTS)):
            current = {}
            for name in names:
                data = json.dumps(dict(tls=dict(cert='cert.pem', key='key.pem'))).encode() if name.endswith('.json') else ('frozen-' + name).encode()
                (directory / name).write_bytes(data)
                current[name] = hashlib.sha256(data).hexdigest()
            hashes.append(current)
        self.write(self.root / 'plan.json', dict(schema='native-lan-path-v1', peer_ipv4='192.0.2.10',
                   wan_ipv4='192.0.2.20', client_ipv4='198.51.100.2', inputs=hashes[0], peer_inputs=hashes[1], service_sha256='a'*64))
        self.write(self.device / 'result.json', dict(exit=0, cleanup=0, finished=1, profile_retained=True))
        for name in ('hostkeys', 'boot', 'interfaces', 'rules', 'routes', 'rules6', 'routes6', 'oom', 'dns', 'config'):
            for side in ('before', 'after'):
                (self.device / (name + '-' + side)).write_text('hash /etc/config/network\n' if name == 'config' else 'same\n')
        for side in ('before', 'after'):
            (self.device / ('service-' + side)).write_text('a'*64 + '  /etc/init.d/lite-client\n')
        self.jsonl(self.device / 'traffic.jsonl', [dict(label=label, tcp=4, udp=64) for label in LABELS])
        requests, payloads, echoes = [], [], []
        for index, label in enumerate(LABELS):
            source = '192.0.2.20' if label == 'nat' or label.endswith('-direct') else '192.0.2.10'
            for stream in range(1, 5):
                requests.append(dict(path=f'/{label}/0/{stream}', tls=stream in (2, 4), sha256=BODY_SHA, remote=source))
                payloads.append(f'{label}\t{stream}\t{BODY_SHA}\n')
            echoes.extend(dict(remote=source, sha256=hashlib.sha256(f'{index}-{n}'.encode()).hexdigest()) for n in range(64))
            self.write(self.device / (label + '.udp.json'), dict(echoes=64, bytes=8192))
        self.jsonl(self.peer / 'http.jsonl', requests)
        self.jsonl(self.peer / 'udp-remote.jsonl', echoes)
        (self.device / 'payloads.tsv').write_text(''.join(payloads))
        self.jsonl(self.device / 'phases.jsonl', [dict(plane=plane, pid=i+10, stable=True, firewall_reload=True)
                                               for i, plane in enumerate(('reality', 'hysteria'))])
        for plane in ('reality', 'hysteria'):
            self.write(self.device / (plane + '.kernel.json'), dict(nftables=[dict(rule=dict(family='inet', table='lc_lan_path',
                chain='inbound', expr=[dict(counter=dict(packets=10))])) for _ in range(2)]))
        self.write(self.peer / 'stand-result.json', dict(exits=[0, 0, 0], errors=[]))

    def write(self, path, value):
        path.write_text(json.dumps(value) + '\n')

    def jsonl(self, path, values):
        path.write_text(''.join(json.dumps(value) + '\n' for value in values))

    def test_complete_nat_proxy_reselection_and_firewall_reload_receipts(self):
        result = analyze(self.root)
        self.assertTrue(result['accepted'])
        self.assertEqual((result['tcp_bytes'], result['udp_echoes']), (28 * 1048576, 448))

    def test_successful_http_body_cannot_hide_direct_egress_when_selected(self):
        path = self.peer / 'http.jsonl'
        data = [json.loads(line) for line in path.read_text().splitlines()]
        data[4]['remote'] = '192.0.2.20'
        self.jsonl(path, data)
        with self.assertRaisesRegex(ValueError, 'source mismatch'):
            analyze(self.root)

    def test_equal_udp_source_totals_cannot_hide_the_wrong_phase(self):
        path = self.peer / 'udp-remote.jsonl'
        data = [json.loads(line) for line in path.read_text().splitlines()]
        data[0]['remote'], data[64]['remote'] = data[64]['remote'], data[0]['remote']
        self.jsonl(path, data)
        with self.assertRaisesRegex(ValueError, 'selected LAN path'):
            analyze(self.root)

    def test_zero_udp_kernel_counter_is_rejected(self):
        path = self.device / 'hysteria.kernel.json'
        data = json.loads(path.read_text())
        data['nftables'][1]['rule']['expr'][0]['counter']['packets'] = 0
        self.write(path, data)
        with self.assertRaisesRegex(ValueError, 'counters'):
            analyze(self.root)

    def test_boot_change_is_rejected(self):
        (self.device / 'boot-after').write_text('rebooted\n')
        with self.assertRaisesRegex(ValueError, 'observation: boot'):
            analyze(self.root)

    def test_changed_reference_executable_is_rejected(self):
        (self.peer / 'xray').write_bytes(b'different')
        with self.assertRaisesRegex(ValueError, 'changed input: xray'):
            analyze(self.root)

    def test_different_installed_service_is_rejected_even_if_unchanged_during_run(self):
        for side in ('before', 'after'):
            (self.device / ('service-' + side)).write_text('b'*64 + '  /etc/init.d/lite-client\n')
        with self.assertRaisesRegex(ValueError, 'installed service bytes'):
            analyze(self.root)

    def test_frozen_config_cannot_reference_an_unfrozen_certificate(self):
        path = self.peer / 'none.json'
        self.write(path, dict(tls=dict(cert='/elsewhere/cert.pem', key='key.pem')))
        plan_path = self.root / 'plan.json'
        plan = json.loads(plan_path.read_text())
        plan['peer_inputs']['none.json'] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write(plan_path, plan)
        with self.assertRaisesRegex(ValueError, 'unfrozen peer certificate path'):
            analyze(self.root)


if __name__ == '__main__':
    unittest.main()
