"""Evidence controls: a successful probe alone must not validate a diagnostic."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from analyze_network import analyze, cpu_ticks, EvidenceError, qdisc_delay, parse_records, credit_before_redirect_headers


def capture(role, scenario, sample):
    target = {'bigbody': '/bb', 'gzbody': '/gz'}[scenario]
    return (f'{role} {scenario} | 100 bytes\n  sample {sample}\n  PREFACE #1\n'
            '  [24] SETTINGS ack=false [ENABLE_PUSH = 0] [INITIAL_WINDOW_SIZE = 4194304] '
            '[MAX_FRAME_SIZE = 1048576] [MAX_HEADER_LIST_SIZE = 10485760]\n'
            '  [4] WINDOW_UPDATE stream=0 +1073741824\n'
            f'  [10] HEADERS stream=1 end=true order=:path\n    :path: /\n'
            f'  [10] HEADERS stream=3 end=true order=:path\n    :path: {target}\n  timing clock=io-return-v2\n'
            '  timing r+2000 HEADERS1e capture+1\n')


def stat(user, system, pid=123):
    fields = ['S'] + ['0'] * 20
    fields[11], fields[12], fields[19] = str(user), str(system), '55'
    return f'{pid} (reference worker) ' + ' '.join(fields)


def qdisc(delay=0, drops=0):
    timing = f' delay {delay}ms' if delay else ''
    return f'qdisc netem 8001: root limit 1000{timing}\n Sent 1 bytes 1 pkt (dropped {drops}, overlimits 0 requeues 0)\n backlog 0b 0p requeues 0\n'


class NetworkEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        phases = []
        for sample, condition in [(1, 'local'), (2, 'egress20')]:
            for scenario in ['bigbody', 'gzbody']:
                for role in ['ref', 'lc']:
                    phases.append(dict(id=len(phases), role=role, scenario=scenario,
                                       condition=condition, sample=sample, round=1,
                                       delay_ms=20 if condition == 'egress20' else 0))
        self.plan = dict(phases=phases, G2Closed=False, criteria_changed=False,
                         expected_connections_per_phase=5, expected_total_connections=40,
                         guard_memavailable_kib=4096, max_device_seconds=1200)
        (self.root / 'plan.json').write_text(json.dumps(self.plan))
        (self.root / 'host-control.log').write_text('HOST_CONTROL_EXIT=0\n')
        host = ''.join(capture(role, scenario, sample) * 5 for role in ['ref', 'lc']
                       for sample, scenario in [(19, 'bigbody'), (20, 'gzbody')])
        native = ''.join(capture(p['role'], p['scenario'], p['sample']) * 5 for p in phases)
        (self.root / 'dest.log').write_text(host + native)
        self.files = {name: value.encode() for name, value in {
            'result.exit': '0', 'restore.exit': '0', 'boot-before': 'same-boot',
            'boot-after': 'same-boot', 'config-after.log': '/etc/config/network: OK\n',
            'memory.log': '100 8192 \n'}.items()}
        manifest = []
        for name in ['lc-tunnel.mips', 'reference.mips', 'client.pb', 'wrong', 'ca.pem',
                     'fingerprint.fpt', 'plan.json', 'phases.tsv']:
            if name != 'plan.json':
                (self.root / name).write_bytes(b'fixture-' + name.encode())
            data = (self.root / name).read_bytes()
            manifest.append(hashlib.sha256(data).hexdigest() + '  ' + name)
            if name not in ('lc-tunnel.mips', 'reference.mips'):
                self.files[name] = data
        self.files['inputs.sha256'] = ('\n'.join(manifest) + '\n').encode()
        self.files['verified-inputs.log'] = ''.join(x.split('  ')[1] + ': OK\n' for x in manifest).encode()
        controls, completed = [], []
        self.keys = []
        for phase in phases:
            key = f"{phase['id']}-{phase['condition']}-{phase['role']}-{phase['scenario']}-{phase['sample']}"
            self.keys.append(key)
            self.files['memory.log'] += ''.join(
                f'{101 + phase["id"] * 10 + tick} 8192 {key}\n' for tick in range(10)).encode()
            controls.append(dict(phase=phase, qdisc=qdisc(phase['delay_ms']), previous_qdisc=qdisc()))
            self.files[key + '.control'] = json.dumps(phase).encode()
            self.files[key + '.qdisc'] = qdisc(phase['delay_ms']).encode()
            self.files[key + '.probe-exit'] = b'52'
            self.files[key + '.before.stat'] = stat(3, 2).encode()
            self.files[key + '.after.stat'] = stat(7, 3).encode()
            self.files[key + '.final.status'] = b'VmRSS: 2048 kB\nVmHWM: 8192 kB\nThreads: 3\n'
            completed.append(f"PROBE_COMPLETE phase={phase['id']} role={phase['role']} scenario={phase['scenario']} condition={phase['condition']}")
        self.files['run.log'] = ('\n'.join(completed) + '\nPAIRED_NETWORK_NATIVE_COMPLETED=1\n').encode()
        (self.root / 'controls.jsonl').write_text(''.join(json.dumps(c) + '\n' for c in controls))

    def write_archive(self, duplicate=False):
        with tarfile.open(self.root / 'device.tar.gz', 'w:gz') as archive:
            for name, data in self.files.items():
                member = tarfile.TarInfo('./' + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if duplicate:
                member = tarfile.TarInfo('./result.exit'); member.size = 1
                archive.addfile(member, io.BytesIO(b'0'))

    def test_complete_diagnostic_is_never_acceptance(self):
        self.write_archive()
        result = analyze(self.root)
        self.assertFalse(result['G2Closed'])
        self.assertEqual(len(result['phases']), 8)
        self.assertEqual(sum(row['connections'] for row in result['native']), 40)

    def test_device_failures_are_rejected(self):
        mutations = {
            'failed command': ('result.exit', b'1'),
            'failed restore': ('restore.exit', b'1'),
            'reboot': ('boot-after', b'another-boot'),
            'memory guard': ('resource-stop', b'low memory'),
            'forced stop': ('forced-stop', b'killed'),
            'wrong network': (self.keys[0] + '.qdisc', qdisc(20).encode()),
            'network loss': (self.keys[0] + '.qdisc', qdisc(drops=1).encode()),
            'changed process': (self.keys[0] + '.after.stat', stat(7, 3, pid=124).encode()),
            'CPU went back': (self.keys[0] + '.after.stat', stat(1, 1).encode()),
            'unexpected authenticated response': (self.keys[0] + '.probe-exit', b'0'),
            'external probe deadline': (self.keys[0] + '.probe-exit', b'28'),
            'client did not accept connection': (self.keys[0] + '.probe-exit', b'7'),
            'probe could not run': (self.keys[0] + '.probe-exit', b'127'),
            'changed protobuf': ('client.pb', b'changed'),
            'incomplete probes': ('run.log', b'PAIRED_NETWORK_NATIVE_COMPLETED=1'),
        }
        for name, (path, data) in mutations.items():
            with self.subTest(name=name):
                before = self.files.copy()
                self.files[path] = data
                self.write_archive()
                with self.assertRaises(EvidenceError):
                    analyze(self.root)
                self.files = before

    def test_capture_mutations_are_rejected(self):
        self.write_archive()
        path = self.root / 'dest.log'
        original = path.read_text()
        single = capture('lc', 'bigbody', 1)
        mutants = [original.replace(single, '', 1), original.replace('    :path: /bb', '    :path: /wrong'),
                   original.replace('  timing clock=io-return-v2', ''),
                   original + capture('lc', 'bigbody', 9),
                   original.replace('  PREFACE #1', '  PREFACE #1\n  [3] RST_STREAM stream=1 CANCEL\n  [4] RST_STREAM stream=1 CANCEL'),
                   original.replace('  PREFACE #1', '  PREFACE #1\n  frame error: bad')]
        for mutant in mutants:
            with self.subTest(capture=mutants.index(mutant)):
                path.write_text(mutant)
                with self.assertRaises(EvidenceError):
                    analyze(self.root)
        path.write_text(original)

    def test_settings_are_checked_for_all_reference_and_native_roles(self):
        self.write_archive()
        path = self.root / 'dest.log'
        original = path.read_text()
        for role, sample in [('ref', 19), ('lc', 19), ('ref', 1), ('lc', 1)]:
            block = capture(role, 'bigbody', sample)
            for changed in [block.replace('4194304', '65535'),
                            block.replace('[MAX_FRAME_SIZE = 1048576]', ''),
                            block.replace('[ENABLE_PUSH = 0]', '[ENABLE_PUSH = 0] [ENABLE_PUSH = 0]'),
                            block.replace('[24] SETTINGS', '[18] SETTINGS')]:
                with self.subTest(role=role, sample=sample, changed=changed):
                    path.write_text(original.replace(block, changed, 1))
                    with self.assertRaisesRegex(EvidenceError, 'opening SETTINGS'):
                        analyze(self.root)
        path.write_text(original)

    def test_valid_closure_and_settings_ack_interleavings(self):
        path = self.root / 'dest.log'
        original = path.read_text()
        for position in ('stream=1', 'stream=3'):
            path.write_text(original.replace(f'  [10] HEADERS {position}',
                            f'  [0] SETTINGS ack=true\n  [10] HEADERS {position}')
                            .replace('[24] SETTINGS', '[24]  SETTINGS'))
            self.files[self.keys[0] + '.probe-exit'] = b'56\n'
            self.write_archive()
            self.assertFalse(analyze(self.root)['G2Closed'])
        path.write_text(original)

    def test_memory_monitor_must_cover_staging_and_every_phase(self):
        original = self.files['memory.log']
        rows = original.splitlines(keepends=True)
        mutants = {
            'only one sample': rows[:1],
            'missing staging': rows[1:],
            'missing first phase': rows[:1] + rows[11:],
            'missing final phase': rows[:-10],
            'monitor gap': rows[:4] + rows[9:],
            'partial phase': rows[:3] + rows[11:],
            'clock went backwards': rows[:4] + [rows[2]] + rows[4:],
            'unknown phase': [rows[0]] + [row.replace(self.keys[0].encode(), b'unknown') for row in rows[1:]],
            'malformed sample': rows + [b'bad sample\n'],
            'crossed memory floor': [row.replace(b'8192', b'4095') for row in rows],
        }
        for name, changed in mutants.items():
            with self.subTest(name=name):
                self.files['memory.log'] = b''.join(changed)
                self.write_archive()
                with self.assertRaises(EvidenceError):
                    analyze(self.root)
        self.files['memory.log'] = original

    def test_duplicate_members_and_changed_inputs_are_rejected(self):
        self.write_archive(duplicate=True)
        with self.assertRaises(EvidenceError):
            analyze(self.root)
        self.write_archive()
        (self.root / 'reference.mips').write_bytes(b'another reference')
        with self.assertRaises(EvidenceError):
            analyze(self.root)

    def test_proc_names_and_delay_units(self):
        self.assertEqual(cpu_ticks(stat(3, 4)), (7, (123, 'reference worker', 55)))
        self.assertEqual(qdisc_delay(qdisc(20).replace('20ms', '20000us')), 20)
        with self.assertRaises(EvidenceError):
            cpu_ticks(stat(-4, 9))

    def test_credit_order_is_reported_without_claiming_equivalence(self):
        original = capture('lc', 'bigbody', 1)
        prefix = '  [4] WINDOW_UPDATE stream=0 +5000\n'
        before = original.replace('  [10] HEADERS stream=3', prefix + '  [10] HEADERS stream=3')
        after = original + prefix
        self.assertTrue(credit_before_redirect_headers(parse_records(before)[0]))
        self.assertFalse(credit_before_redirect_headers(parse_records(after)[0]))


if __name__ == '__main__':
    unittest.main()
