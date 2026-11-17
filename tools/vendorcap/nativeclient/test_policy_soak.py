import hashlib
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from policy_soak import BODY_SHA, INPUTS, analyze, intervals, merged


class PolicyIntervalTests(unittest.TestCase):
    def test_full_ipv4_range_is_not_expanded_into_individual_addresses(self):
        self.assertEqual(intervals(['0.0.0.0/0']), [(0, 2**32 - 1)])

    def test_adjacent_and_overlapping_ranges_have_one_canonical_union(self):
        self.assertEqual(merged([(4, 5), (1, 3), (2, 4)]), [(1, 5)])

    def test_reversed_range_cannot_hide_extra_addresses(self):
        with self.assertRaisesRegex(ValueError, 'reversed IPv4 interval'):
            intervals([dict(range=['198.51.100.2', '198.51.100.1'])])

    def test_ipv6_prefix_cannot_substitute_for_ipv4_union(self):
        with self.assertRaisesRegex(ValueError, 'family mismatch'):
            intervals(['2001:db8::/64'])

    def test_boolean_is_not_a_prefix_length(self):
        with self.assertRaisesRegex(ValueError, 'invalid IPv4 prefix'):
            intervals([dict(prefix=dict(addr='198.51.100.1', len=True))])


class DriverIdentityTests(unittest.TestCase):
    def run_prefix(self, mismatched, name='native-policy-soak.sh'):
        source = Path(__file__).with_name(name).read_text(encoding='utf-8')
        prefix = source.split('. ./settings.sh', 1)[0]
        with tempfile.TemporaryDirectory(prefix='lc-lan-' if name=='native-lan.sh' else 'lc-policy-', dir='/tmp') as directory:
            root = Path(directory)
            staged = root / name
            staged.write_text(prefix, encoding='utf-8')
            digest = hashlib.sha256(staged.read_bytes()).hexdigest()
            (root / 'device.sha256').write_text(digest + '  ' + name + '\n', encoding='utf-8')
            driver = staged
            if mismatched:
                driver = root / 'other-driver.sh'
                driver.write_text(prefix + '\n# Different executed bytes.\n', encoding='utf-8')
            return subprocess.run(['sh', str(driver), directory], capture_output=True, text=True)

    def test_executed_driver_matches_frozen_input(self):
        for name in ('native-policy-soak.sh', 'native-lan.sh'):
            with self.subTest(driver=name):
                result = self.run_prefix(False, name)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_valid_staged_driver_cannot_hide_different_executed_driver(self):
        for name in ('native-policy-soak.sh', 'native-lan.sh'):
            with self.subTest(driver=name):
                self.assertNotEqual(self.run_prefix(True, name).returncode, 0)


class WorkloadLivenessTests(unittest.TestCase):
    def test_either_disappeared_workload_stops_the_driver(self):
        source = Path(__file__).with_name('native-policy-soak.sh').read_text(encoding='utf-8')
        function = 'check_loads() {' + source.split('check_loads() {', 1)[1].split('\n}', 1)[0] + '\n}\n'
        for missing in ('traffic', 'dnsload', 'monitor', 'none'):
            with self.subTest(missing=missing):
                script = function + '''traffic=live; dnsload=live; monitor=live
kill() { [ "$2" != dead ]; }
case "$1" in traffic) traffic=dead ;; dnsload) dnsload=dead ;; monitor) monitor=dead ;; esac
check_loads
printf survived
'''
                result = subprocess.run(['sh', '-ec', script, 'fixture', missing], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if missing == 'none' else 1)
                self.assertEqual(result.stdout, 'survived' if missing == 'none' else '')


class NativeProcessTests(unittest.TestCase):
    def test_teardown_finds_descendants_without_task_children(self):
        source = Path(__file__).with_name('native-policy-soak.sh').read_text(encoding='utf-8')
        function = 'terminate_tree() {' + source.split('terminate_tree() {', 1)[1].split('\n}', 1)[0] + '\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pid, parent in [(100, 1), (110, 100), (111, 110), (120, 100), (200, 1)]:
                path = root / str(pid); path.mkdir()
                (path / 'status').write_text(f'Name:\tfixture\nPid:\t{pid}\nPPid:\t{parent}\n')
            script = function.replace('/proc/', str(root) + '/') + '''
kill() { printf '%s\\n' "$1"; }
terminate_tree 100
'''
            result = subprocess.run(['sh', '-ec', script], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            killed = result.stdout.splitlines()
            self.assertEqual(set(killed), {'100', '110', '111', '120'})
            self.assertEqual(len(killed), 4)
            self.assertLess(killed.index('111'), killed.index('110'))
            self.assertEqual(killed[-1], '100')

    def test_procd_transition_values_produce_no_pid_until_a_live_number_exists(self):
        for name in ('native-policy-soak.sh', 'native-lan.sh'):
            source = Path(__file__).with_name(name).read_text(encoding='utf-8')
            function = next(line for line in source.splitlines() if line.startswith('pid_now()'))
            for value in (None, 0, -1, '123', False, 123):
                response = json.dumps({'lite-client': {'instances': {'instance1': {'pid': value}}}})
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'reply'; path.write_text(response)
                    script = 'ubus() { cat "$REPLY"; }\n' + function + '\npid_now\n'
                    result = subprocess.run(['sh', '-ec', 'REPLY=$1\n' + script, 'fixture', str(path)], capture_output=True, text=True)
                with self.subTest(driver=name, value=value):
                    self.assertEqual(result.stdout, '123\n' if value == 123 and type(value) is int else '')
                    if value == 123 and type(value) is int:
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0)


class FinalSelectionTests(unittest.TestCase):
    def exercise(self, fail):
        source = Path(__file__).with_name('native-policy-soak.sh').read_text(encoding='utf-8')
        function = 'finalize_policy() {' + source.split('finalize_policy() {', 1)[1].split('\n}', 1)[0] + '\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'domains-base').write_text('base\n')
            (root / 'selection').write_text('base\ntoggle\n')
            script = '''b=$1; plane=reality
domain_policy_apply() { [ "$FAIL_RESTORE" != 1 ] || return 71; cp "$1" "$b/selection"; }
domain_policy_checkpoint() { printf checkpoint > "$b/checkpoint"; }
domain_policy_read() { cat "$b/selection"; }
nft() { cat "$b/selection"; }
domain_policy_consistent() { cmp "$1" "$2"; }
''' + function + '\nif finalize_policy; then cat "$b/reality.policy.json"; else test ! -e "$b/checkpoint"; exit 19; fi'
            result = subprocess.run(['sh', '-ec', 'FAIL_RESTORE=$2; ' + script, 'fixture', directory, str(int(fail))],
                                    capture_output=True, text=True)
            return result

    def test_odd_selection_count_is_restored_before_final_observation(self):
        result = self.exercise(False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'base\n')

    def test_failed_final_restore_cannot_publish_a_final_snapshot(self):
        self.assertEqual(self.exercise(True).returncode, 19)


class EnvironmentObserverTests(unittest.TestCase):
    def test_concurrent_kernel_observers_do_not_share_snapshot_files(self):
        source = Path(__file__).with_name('native-policy-soak.sh').read_text(encoding='utf-8')
        function = 'kernel_healthy() {' + source.split('kernel_healthy() {', 1)[1].split('\n}', 1)[0] + '\n}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'oom-before.summary').write_text('[1] Out of memory: historical\n')
            (root/'kernel-log').write_text('[1] Out of memory: historical\n')
            script = '''b=$1
dmesg() {
    if [ "$ROLE" = b ]; then
        while [ ! -e "$b/a.comparing" ]; do sleep 0.01; done
    fi
    cat "$b/kernel-log"
}
awk() {
    if [ "$ROLE" = b ]; then
        touch "$b/b.filtering"
        while [ ! -e "$b/a.compared" ]; do sleep 0.01; done
    fi
    command awk "$@"
}
cmp() {
    if [ "$ROLE" = a ]; then
        touch "$b/a.comparing"
        while [ ! -e "$b/b.filtering" ]; do sleep 0.01; done
        status=0
        command cmp "$@" || status=$?
        touch "$b/a.compared"
        return "$status"
    fi
    command cmp "$@"
}
''' + function + '''
(ROLE=a; kernel_healthy) & first=$!
(ROLE=b; kernel_healthy) & second=$!
first_exit=0; wait "$first" || first_exit=$?
second_exit=0; wait "$second" || second_exit=$?
test "$first_exit" = 0 && test "$second_exit" = 0
'''
            result = subprocess.run(['sh','-ec',script,'fixture',directory],
                                    capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(list(root.glob('oom-live.*')),[])

    def kernel_health(self, output, baseline='[1] Out of memory: historical\n', exit_code=0):
        source = Path(__file__).with_name('native-policy-soak.sh').read_text(encoding='utf-8')
        function = 'kernel_healthy() {' + source.split('kernel_healthy() {', 1)[1].split('\n}', 1)[0] + '\n}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'oom-before.summary').write_text(baseline)
            (root/'kernel-log').write_text(output)
            script = 'b=$1; kernel_exit=$2; dmesg() { cat "$b/kernel-log"; return "$kernel_exit"; }\n'
            return subprocess.run(['sh','-ec',script+function+'\nkernel_healthy\n','fixture',directory,str(exit_code)],
                                  capture_output=True,text=True)

    def test_historical_oom_and_new_unrelated_kernel_lines_are_healthy(self):
        self.assertEqual(self.kernel_health('[1] Out of memory: historical\n[2] unrelated\n').returncode,0)

    def test_new_oom_stops_the_resource_observer(self):
        self.assertNotEqual(self.kernel_health('[1] Out of memory: historical\n[2] Out of memory: new victim\n').returncode,0)

    def test_unreadable_kernel_log_is_not_healthy(self):
        self.assertNotEqual(self.kernel_health('',baseline='',exit_code=71).returncode,0)

    def observe(self, setup):
        source = Path(__file__).with_name('native-policy-soak.sh').read_text(encoding='utf-8')
        function = 'observe_environment() {' + source.split('observe_environment() {', 1)[1].split('\n}', 1)[0] + '\n}'
        with tempfile.TemporaryDirectory() as directory:
            script = setup + '\nb=$1\n' + function + '\nif observe_environment before; then cat "$b"/*.summary; else exit 19; fi'
            return subprocess.run(['sh', '-ec', script, 'observer', directory], capture_output=True, text=True)

    def test_real_process_birth_and_filtered_kernel_event_are_recorded(self):
        result = self.observe("dmesg() { printf 'unrelated\\n[1] Out of memory: evidence\\n'; }; pidof() { echo $$; }")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('[1] Out of memory: evidence', result.stdout)
        self.assertNotIn('unrelated', result.stdout)
        self.assertRegex(result.stdout, r'\d+ \d+')

    def test_a_disappeared_dns_process_is_not_hidden_by_sort(self):
        result = self.observe('dmesg() { :; }; pidof() { echo 2147483647; }')
        self.assertEqual(result.returncode, 19)

    def test_failed_kernel_observation_cannot_become_an_empty_success(self):
        result = self.observe('dmesg() { return 71; }; pidof() { :; }')
        self.assertEqual(result.returncode, 19)


class PolicySoakEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.device = self.root / 'device-results'
        self.peer = self.root / 'peer'
        self.stage = stage = self.root / 'stage'
        for path in (self.device, self.peer, stage):
            path.mkdir()
        hashes = {}
        for name in INPUTS:
            content = ('fixture-' + name).encode()
            (stage / name).write_bytes(content)
            hashes[name] = hashlib.sha256(content).hexdigest()
        self.domains = [dict(name=f'd{i:04d}.audit.test',
                            set='p4d_' + hashlib.sha256(f'd{i:04d}.audit.test'.encode()).hexdigest()[:32],
                            ips=[f'10.200.{i // 250}.{i % 250 + 1}'], ips6=[f'2001:db8::{i + 1:x}'])
                        for i in range(1375)]
        self.metadata = dict(version=1, initialized=True, domains=self.domains, fallback_ips=[])
        self.write(stage / 'policy-seed.json', self.metadata)
        (stage / 'domains-base').write_text(''.join(d['name'] + '\n' for d in self.domains), encoding='utf-8')
        for name in ('domains-base', 'policy-seed.json'):
            hashes[name] = hashlib.sha256((stage / name).read_bytes()).hexdigest()
        self.write(self.root / 'plan.json', dict(schema='native-policy-coexistence-v2',
                   observer_timeouts=dict(tcp_connect_seconds=20, tcp_total_seconds=30, udp_receive_seconds=20),
                   phases=['reality', 'hysteria'], active_seconds_per_plane=900,
                   domains=1375, traffic_period=10, resource_policy='flash-only',
                   ram_limits=None, inputs=hashes))
        self.write(self.device / 'result.json', dict(exit=0, cleanup=0, finished=1, profile_retained=True))
        for name in ('hostkeys', 'boot', 'interfaces'):
            for side in ('before', 'after'):
                (self.device / (name + '-' + side)).write_text('unchanged\n', encoding='utf-8')
        for name in ('oom', 'owner-dns'):
            for side in ('before', 'after'):
                (self.device / (name + '-' + side + '.summary')).write_text('', encoding='utf-8')
        for side in ('before', 'after'):
            (self.device / ('config-' + side)).write_text(
                'same /etc/config/network\n' + side + ' /etc/config/lite-client\n', encoding='utf-8')
        phases, traffic, operations, peer, payloads, echoes = [], [], [], [], [], []
        for index, plane in enumerate(('reality', 'hysteria')):
            self.write(self.device / (plane + '.policy.json'), self.metadata)
            self.write(self.device / (plane + '.kernel.json'), self.kernel())
            start = 100 + index * 901
            pid = 10 + index
            phases.extend([dict(plane=plane, event=event, uptime=start + delta, pid=pid)
                           for event, delta in [('start', 0), ('end', 900)]])
            for burst in range(90):
                traffic.append(dict(plane=plane, burst=burst, uptime=start + burst * 10 + 1,
                                    pid=pid, birth='fixture-' + plane, tcp=4, udp=64))
                for stream in range(1, 5):
                    peer.append(dict(path=f'/{plane}/{burst}/{stream}', sha256=BODY_SHA, tls=stream in (2, 4)))
                    payloads.append(BODY_SHA + '  fixture.body')
                echoes.extend(hashlib.sha256(f'{plane}-{burst}-{n}'.encode()).hexdigest() for n in range(64))
            for cycle in range(15):
                operation = 'rollback' if cycle == 2 else ('apply' if cycle % 2 else 'checkpoint')
                operations.append(dict(plane=plane, cycle=cycle, operation=operation,
                                       start=start + cycle * 60, end=start + cycle * 60 + 1, pid=pid))
            (self.device / (plane + '.dns.summary')).write_text('2000\t2\n', encoding='utf-8')
        self.lines(self.device / 'phases.jsonl', phases)
        self.lines(self.device / 'traffic.jsonl', traffic)
        self.lines(self.device / 'policy.jsonl', operations)
        self.lines(self.peer / 'http.jsonl', peer)
        (self.peer / 'udp.jsonl').write_text('\n'.join(echoes) + '\n', encoding='utf-8')
        (self.device / 'payloads.sha256').write_text('\n'.join(payloads) + '\n', encoding='utf-8')
        self.write(self.peer / 'stand-result.json', dict(exits=[0, 0, 0], errors=[]))
        (self.device / 'memory.tsv').write_text('99\t0\n1901\t0\n', encoding='utf-8')
        process_rows = []
        for index in range(2):
            process_rows.extend(f'{120 + index * 901 + n * 20}\t{pid}\tlc-tunnel\t5000\t6000\t4\n'
                                for pid in (10 + index, 20 + index) for n in range(40))
        (self.device / 'processes.tsv').write_text(''.join(process_rows), encoding='utf-8')

    def write(self, path, value):
        path.write_text(json.dumps(value) + '\n', encoding='utf-8')

    def kernel(self):
        sets = [dict(name='domains_vpn', type='ipv4_addr', flags=['interval'],
                     elem=[ip for d in self.domains for ip in d['ips']]),
                dict(name='domains_vpn6', type='ipv6_addr',
                     elem=[ip for d in self.domains for ip in d['ips6']])]
        for d in self.domains:
            sets.extend([dict(name=d['set'], type='ipv4_addr', elem=d['ips']),
                         dict(name=d['set'] + '_6', type='ipv6_addr', elem=d['ips6'])])
        return dict(nftables=[dict(set=dict(family='inet', table='lc_policy_soak', **s)) for s in sets])

    def rewrite_input(self, name, content):
        path = self.stage / name
        path.write_bytes(content)
        plan_path = self.root / 'plan.json'
        plan = json.loads(plan_path.read_text(encoding='utf-8'))
        plan['inputs'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write(plan_path, plan)

    def lines(self, path, values):
        path.write_text(''.join(json.dumps(value) + '\n' for value in values), encoding='utf-8')

    def alter_row(self, filename, index, **values):
        path = self.device / filename
        rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        rows[index].update(values)
        self.lines(path, rows)

    def test_complete_workload_has_no_memory_admission_threshold(self):
        result = analyze(self.root)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['tcp_payloads'], 720)
        self.assertEqual(result['udp_echoes'], 11520)
        self.assertEqual(result['minimum_sampled_available_kib'], 0)
        self.assertIsNone(result['ram_limits'])

    def test_both_planes_can_run_in_reverse_order_without_shortening_windows(self):
        plan_path=self.root/'plan.json'
        plan=json.loads(plan_path.read_text())
        plan['phases']=['hysteria','reality']
        self.write(plan_path,plan)
        swap={'reality':'hysteria','hysteria':'reality'}
        for name in ('phases.jsonl','traffic.jsonl','policy.jsonl'):
            path=self.device/name
            values=[json.loads(line) for line in path.read_text().splitlines()]
            for row in values: row['plane']=swap[row['plane']]
            self.lines(path,values)
        path=self.peer/'http.jsonl'
        values=[json.loads(line) for line in path.read_text().splitlines()]
        for row in values:
            parts=row['path'].split('/'); parts[1]=swap[parts[1]]; row['path']='/'.join(parts)
        self.lines(path,values)
        result=analyze(self.root)
        self.assertTrue(result['accepted'])
        self.assertEqual(result['seconds_per_plane'],900)

    def test_duplicate_plane_cannot_replace_the_other_protocol(self):
        path=self.root/'plan.json';plan=json.loads(path.read_text());plan['phases']=['hysteria','hysteria']
        self.write(path,plan)
        with self.assertRaisesRegex(ValueError,'both native planes'):
            analyze(self.root)

    def test_full_traffic_cannot_substitute_for_eight_policy_operations(self):
        path = self.device / 'policy.jsonl'
        actions = [json.loads(line) for line in path.read_text().splitlines()]
        self.lines(path, [row for row in actions if row['plane'] != 'reality' or row['cycle'] < 7])
        with self.assertRaisesRegex(ValueError, 'policy churn or rollback is missing'):
            analyze(self.root)

    def test_compressed_phase_is_rejected(self):
        self.alter_row('phases.jsonl', 1, uptime=999)
        with self.assertRaisesRegex(ValueError, 'compressed phase'):
            analyze(self.root)

    def test_historical_deadlines_are_not_silently_reinterpreted(self):
        path = self.root / 'plan.json'
        plan = json.loads(path.read_text())
        plan['schema'] = 'native-policy-coexistence-v1'
        self.write(path, plan)
        with self.assertRaisesRegex(ValueError, 'unsupported evidence schema'):
            analyze(self.root)

    def test_observer_budgets_are_required_and_cannot_be_inflated(self):
        path = self.root / 'plan.json'
        plan = json.loads(path.read_text())
        for budget in (None, dict(tcp_connect_seconds=20, tcp_total_seconds=30, udp_receive_seconds=600)):
            with self.subTest(budget=budget):
                plan['observer_timeouts'] = budget
                self.write(path, plan)
                with self.assertRaisesRegex(ValueError, 'unexpected observer timeout budget'):
                    analyze(self.root)

    def test_changed_runtime_is_rejected(self):
        (self.root / 'stage/router-lib.sh').write_text('changed', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'changed input'):
            analyze(self.root)

    def test_inflated_domain_count_in_the_plan_is_rejected(self):
        path = self.root / 'plan.json'
        plan = json.loads(path.read_text(encoding='utf-8'))
        plan['domains'] = 1000000
        self.write(path, plan)
        with self.assertRaisesRegex(ValueError, 'actual domain count'):
            analyze(self.root)

    def test_small_but_correctly_hashed_selection_is_rejected(self):
        names = ''.join(d['name'] + '\n' for d in self.domains[:3]).encode()
        self.rewrite_input('domains-base', names)
        with self.assertRaisesRegex(ValueError, 'actual domain count'):
            analyze(self.root)

    def test_consistent_three_owner_workload_cannot_be_qualified_as_1375(self):
        self.domains = self.domains[:3]
        self.metadata['domains'] = self.domains
        self.rewrite_input('domains-base', ''.join(d['name'] + '\n' for d in self.domains).encode())
        self.rewrite_input('policy-seed.json', json.dumps(self.metadata).encode())
        for plane in ('reality', 'hysteria'):
            self.write(self.device / (plane + '.policy.json'), self.metadata)
            self.write(self.device / (plane + '.kernel.json'), self.kernel())
        with self.assertRaisesRegex(ValueError, 'actual domain count'):
            analyze(self.root)

    def test_small_workload_cannot_lower_the_plan_to_bypass_the_minimum(self):
        path = self.root / 'plan.json'
        plan = json.loads(path.read_text(encoding='utf-8'))
        plan['domains'] = 3
        self.write(path, plan)
        with self.assertRaisesRegex(ValueError, 'large policy workload'):
            analyze(self.root)

    def test_duplicate_selected_names_are_rejected(self):
        names = (self.stage / 'domains-base').read_bytes()
        self.rewrite_input('domains-base', names + names.splitlines()[0] + b'\n')
        with self.assertRaisesRegex(ValueError, 'duplicate selected'):
            analyze(self.root)

    def test_empty_seed_can_be_warmed_before_the_timed_phases(self):
        self.rewrite_input('policy-seed.json', b'{"version":1,"domains":[]}\n')
        self.assertTrue(analyze(self.root)['accepted'])

    def test_well_formed_partial_seed_does_not_replace_final_workload_checks(self):
        seed = dict(version=1, domains=self.domains[:3])
        self.rewrite_input('policy-seed.json', json.dumps(seed).encode())
        self.assertTrue(analyze(self.root)['accepted'])

    def test_malformed_but_correctly_hashed_seed_is_rejected(self):
        seed = copy.deepcopy(self.metadata)
        seed['domains'][0]['set'] = seed['domains'][1]['set']
        self.rewrite_input('policy-seed.json', json.dumps(seed).encode())
        with self.assertRaisesRegex(ValueError, 'mismatched policy owner'):
            analyze(self.root)

    def test_boolean_is_not_a_policy_version(self):
        self.rewrite_input('policy-seed.json', b'{"version":true,"domains":[]}\n')
        with self.assertRaisesRegex(ValueError, 'invalid policy metadata'):
            analyze(self.root)

    def test_smaller_final_policy_is_rejected(self):
        metadata = copy.deepcopy(self.metadata)
        metadata['domains'].pop()
        self.write(self.device / 'reality.policy.json', metadata)
        with self.assertRaisesRegex(ValueError, 'actual policy domains'):
            analyze(self.root)

    def test_unwarmed_final_owner_is_rejected(self):
        metadata = copy.deepcopy(self.metadata)
        metadata['domains'][0]['ips6'] = []
        self.write(self.device / 'reality.policy.json', metadata)
        with self.assertRaisesRegex(ValueError, 'not warmed'):
            analyze(self.root)

    def test_missing_kernel_family_cannot_pass_on_metadata_alone(self):
        kernel = self.kernel()
        kernel['nftables'].pop()
        self.write(self.device / 'reality.kernel.json', kernel)
        with self.assertRaisesRegex(ValueError, 'kernel owner sets'):
            analyze(self.root)

    def test_kernel_addresses_must_match_the_policy(self):
        kernel = self.kernel()
        kernel['nftables'][2]['set']['elem'] = ['203.0.113.99']
        self.write(self.device / 'reality.kernel.json', kernel)
        with self.assertRaisesRegex(ValueError, 'kernel owner addresses'):
            analyze(self.root)

    def test_owner_set_cannot_change_its_kernel_type(self):
        kernel = self.kernel()
        kernel['nftables'][2]['set']['type'] = 'ifname'
        self.write(self.device / 'reality.kernel.json', kernel)
        with self.assertRaisesRegex(ValueError, 'kernel owner type or flags'):
            analyze(self.root)

    def test_policy_cannot_duplicate_an_owner_name(self):
        metadata = copy.deepcopy(self.metadata)
        metadata['domains'].append(copy.deepcopy(metadata['domains'][0]))
        self.write(self.device / 'reality.policy.json', metadata)
        with self.assertRaisesRegex(ValueError, 'duplicate or mismatched policy owner'):
            analyze(self.root)

    def test_kernel_union_cannot_include_unowned_addresses(self):
        kernel = self.kernel()
        kernel['nftables'][0]['set']['elem'].append('203.0.113.99')
        self.write(self.device / 'reality.kernel.json', kernel)
        with self.assertRaisesRegex(ValueError, 'IPv4 union differs'):
            analyze(self.root)

    def test_kernel_union_can_use_compact_ranges_and_prefixes(self):
        kernel = self.kernel()
        kernel['nftables'][0]['set']['elem'] = [
            '10.200.0.1', dict(prefix=dict(addr='10.200.0.2', len=31)),
            dict(range=['10.200.0.4', '10.200.0.250'])
        ] + [ip for d in self.domains[250:] for ip in d['ips']]
        self.write(self.device / 'reality.kernel.json', kernel)
        self.assertTrue(analyze(self.root)['accepted'])

    def test_kernel_namespace_cannot_be_substituted(self):
        kernel = self.kernel()
        kernel['nftables'][0]['set']['table'] = 'unrelated'
        self.write(self.device / 'reality.kernel.json', kernel)
        with self.assertRaisesRegex(ValueError, 'namespace'):
            analyze(self.root)

    def test_duplicate_kernel_names_are_rejected(self):
        kernel = self.kernel()
        kernel['nftables'].append(copy.deepcopy(kernel['nftables'][2]))
        self.write(self.device / 'reality.kernel.json', kernel)
        with self.assertRaisesRegex(ValueError, 'duplicate kernel set'):
            analyze(self.root)

    def test_final_policy_verification_can_follow_the_timed_window(self):
        self.alter_row('phases.jsonl', 3, uptime=1991)
        (self.device / 'memory.tsv').write_text('99\t0\n1991\t0\n', encoding='utf-8')
        self.assertTrue(analyze(self.root)['accepted'])

    def test_overlapping_phases_are_rejected(self):
        self.alter_row('phases.jsonl', 2, uptime=999)
        with self.assertRaisesRegex(ValueError, 'phase boundaries'):
            analyze(self.root)

    def test_bursts_compressed_into_the_beginning_are_rejected(self):
        path = self.device / 'traffic.jsonl'
        cases = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        for case in cases:
            if case['plane'] == 'reality':
                case['uptime'] = 101 + case['burst']
        self.lines(path, cases)
        with self.assertRaisesRegex(ValueError, 'timed window'):
            analyze(self.root)

    def test_restarted_native_process_is_rejected(self):
        self.alter_row('traffic.jsonl', 10, pid=999)
        with self.assertRaisesRegex(ValueError, 'process restarted'):
            analyze(self.root)

    def test_missing_rollback_is_rejected(self):
        self.alter_row('policy.jsonl', 2, operation='checkpoint')
        with self.assertRaisesRegex(ValueError, 'rollback is missing'):
            analyze(self.root)

    def test_operations_before_the_timed_phase_are_rejected(self):
        self.alter_row('policy.jsonl', 0, start=1, end=2)
        with self.assertRaisesRegex(ValueError, 'outside the timed phase'):
            analyze(self.root)

    def test_operations_started_after_traffic_cannot_hide_in_final_verification(self):
        self.alter_row('phases.jsonl', 3, uptime=1991)
        self.alter_row('policy.jsonl', 29, start=1902, end=1903)
        with self.assertRaisesRegex(ValueError, 'outside the timed phase'):
            analyze(self.root)

    def test_started_operation_can_finish_during_final_verification(self):
        self.alter_row('phases.jsonl', 3, uptime=1991)
        self.alter_row('policy.jsonl', 29, start=1900, end=1910)
        (self.device / 'memory.tsv').write_text('99\t0\n1991\t0\n', encoding='utf-8')
        self.assertTrue(analyze(self.root)['accepted'])

    def test_operation_cannot_outlast_observation_of_its_plane(self):
        self.alter_row('policy.jsonl', 29, end=1902)
        with self.assertRaisesRegex(ValueError, 'outside the timed phase'):
            analyze(self.root)

    def test_overlapping_operations_are_rejected(self):
        self.alter_row('policy.jsonl', 1, start=100, end=102)
        with self.assertRaisesRegex(ValueError, 'overlapping or reversed policy operations'):
            analyze(self.root)

    def test_unknown_policy_plane_is_not_silently_counted(self):
        self.alter_row('policy.jsonl', 0, plane='unknown')
        with self.assertRaisesRegex(ValueError, 'unexpected policy plane'):
            analyze(self.root)

    def test_restarted_worker_is_rejected(self):
        path = self.device / 'processes.tsv'
        source = path.read_text(encoding='utf-8')
        self.assertIn('300\t20\tlc-tunnel', source)
        path.write_text(source.replace('300\t20\tlc-tunnel', '300\t999\tlc-tunnel'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'worker cohort changed'):
            analyze(self.root)

    def test_other_same_name_invocations_do_not_replace_the_stable_service_core(self):
        path = self.device / 'processes.tsv'
        path.write_text(path.read_text(encoding='utf-8') + '300\t999\tlc-tunnel\t5000\t6000\t4\n', encoding='utf-8')
        result = analyze(self.root)
        self.assertEqual(result['worker_pids']['reality'], [10, 20])
        self.assertEqual(result['other_lc_processes']['reality'], [999])

    def test_missing_peer_receipt_is_rejected(self):
        path = self.peer / 'http.jsonl'
        path.write_text('\n'.join(path.read_text(encoding='utf-8').splitlines()[1:]) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'peer receipts'):
            analyze(self.root)

    def test_replayed_udp_echo_is_rejected(self):
        path = self.peer / 'udp.jsonl'
        lines = path.read_text(encoding='utf-8').splitlines()
        lines[-1] = lines[0]
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'replayed UDP'):
            analyze(self.root)

    def test_payload_corruption_is_rejected(self):
        path = self.device / 'payloads.sha256'
        path.write_text(path.read_text(encoding='utf-8').replace(BODY_SHA, 'bad', 1), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'payload hashes'):
            analyze(self.root)

    def test_new_oom_record_is_rejected(self):
        (self.device / 'oom-after.summary').write_text('Killed process\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'resource failure'):
            analyze(self.root)

    def test_owner_dns_restart_is_rejected(self):
        (self.device / 'owner-dns-after.summary').write_text('123 456\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'owner DNS restart'):
            analyze(self.root)

    def test_unrelated_configuration_change_is_rejected(self):
        path = self.device / 'config-after'
        path.write_text(path.read_text(encoding='utf-8').replace('same', 'changed'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'unrelated configuration'):
            analyze(self.root)


if __name__ == '__main__':
    unittest.main()
