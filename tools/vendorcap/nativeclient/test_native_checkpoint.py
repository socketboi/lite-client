import json
import importlib.util
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from analyze_network import EvidenceError, OPENING_SETTINGS
from analyze_native_checkpoint import analyze
from checkpoint_process import digest
from native_checkpoint import freeze, serve
from native_checkpoint_plan import NATIVE_INPUTS, DEVICE_INPUTS


class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in NATIVE_INPUTS:
            (self.root/name).write_text('fixture-'+name)
        elf = bytearray(64)
        elf[:6] = b'\x7fELF\x01\x01'
        elf[18] = 8
        for name in ('lc-tunnel.native', 'reference.native'):
            (self.root/name).write_bytes(elf)
        self.identity = dict(board_name='fixture-board', boot_id='fixture-boot', architecture='mipsel')
        self.write(self.root, 'device.json', self.identity)
        self.write(self.root, 'settings.json', dict(advertised_host='stand.invalid', control_port=19880,
            control_listen='127.0.0.1', control_token='a'*64, max_seconds=1200,
            startup_wait_seconds=2, quiet_wait_seconds=6))
        self.write(self.root, 'client.json', dict(outbounds=[dict(
            settings=dict(vnext=[dict(address='stand.invalid', port=14480,
                                      users=[dict(id='fixture-user')])]),
            streamSettings=dict(realitySettings=dict(serverName='stand.invalid',
                 publicKey='fixture-wrong-key', shortId='fixture-short-id')))]))
        self.plan = freeze(self.root)
        self.device = self.root/'device-results'
        self.device.mkdir()
        for name in ('boot-before', 'boot-after'):
            (self.device/name).write_text('fixture-boot\n')
        (self.device/'board-name').write_text('fixture-board\n')
        (self.device/'interfaces-before').write_text('lo\nfixture-interface\n')
        (self.device/'interfaces-after').write_text('lo\nfixture-interface\n')
        for name in ('configuration-before', 'configuration-after'):
            (self.device/name).write_text('a'*64+'  /etc/config/network\n')
        (self.device/'plan.sha256').write_text(digest(self.root/'plan.json')+'\n')
        (self.device/'device.sha256').write_text(''.join(self.plan['inputs'][name]+'  '+name+'\n'
                                                      for name in sorted(DEVICE_INPUTS)))
        self.state = dict(exit_code=0, cleanup_exit=0, phases_completed=24,
                          deadline_exceeded=False, elapsed_seconds=240)
        self.write(self.device, 'device-state.json', self.state)
        self.write(self.root, 'stand-state.json', dict(server_sha256=self.plan['inputs']['reference.host'],
            dest_sha256=self.plan['inputs']['dest.host'], phases_completed=24, alive_after_phases=True,
            server_exit=0, dest_exit=-15, cleanup_exit=0))
        progress, resources, records = [], [], []
        for phase in self.plan['phases']:
            key = str(phase['id'])
            progress += [dict(phase=phase, stage='start'), dict(phase=phase, stage='complete', alive=True)]
            binary = 'lc-tunnel.native' if phase['role'] == 'lc' else 'reference.native'
            self.write(self.device, key+'.json', dict(phase_id=phase['id'],
                binary_sha256=self.plan['inputs'][binary], alive_before_probe=True,
                alive_after_probe=True, probe_exit=52, stop_signal=15,
                client_exit=143 if phase['role'] == 'lc' else 0,
                monitor_exit=143,
                observed_from_seconds=phase['id']*10, observed_until_seconds=phase['id']*10+8))
            (self.device/(key+'.probe-exit')).write_text('52\n')
            (self.device/(key+'.stat-before')).write_text(self.stat(10))
            (self.device/(key+'.stat-after')).write_text(self.stat(20))
            for second in range(9):
                resources.append(f"{phase['id']} {phase['id']*10+second} 16000 2000 6 4\n")
            paths = ['/'] if phase['scenario'] == 'closeafter' else ['/',
                     dict(bigbody='/bb', gzbody='/gz', latebig='/late')[phase['scenario']]]
            for _ in range(5):
                record = f"{phase['role']} {phase['scenario']} | 100 bytes\n  sample {phase['round']}\n"
                record += '  PREFACE #1\n  '+OPENING_SETTINGS+'\n  [4] WINDOW_UPDATE stream=0 +1073741824\n'
                for stream, path in zip((1, 3), paths):
                    record += f'  [10] HEADERS stream={stream} end=true order=:path\n    :path: {path}\n'
                records.append(record+'  timing clock=io-return-v2\n  timing r+100 HEADERS1e capture+1\n')
        self.resources = ''.join(resources)
        (self.device/'resources.tsv').write_text(self.resources)
        (self.root/'progress.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in progress))
        (self.root/'dest.log').write_text(''.join(records))

    @staticmethod
    def stat(cpu, born=1000):
        fields = ['0']*20
        fields[0], fields[11], fields[12], fields[19] = 'S', str(cpu), '2', str(born)
        return '123 (fixture) '+' '.join(fields)+'\n'

    @staticmethod
    def write(root, name, value):
        (root/name).write_text(json.dumps(value))

    def test_complete_native_evidence_has_checkpoint_scope(self):
        result = analyze(self.root)
        self.assertTrue(result['checkpoint_criteria_met'])
        self.assertEqual(result['acceptance_scope'], 'checkpoint')
        self.assertNotIn('G2Closed', result)
        self.assertEqual(len(result['phases']), 24)
        self.assertEqual(result['minimum_memavailable_kib'], 16000)

    def test_failed_cleanup_incomplete_or_deadline_exceeded_cannot_pass(self):
        for key, value in (('exit_code', 1), ('cleanup_exit', 1), ('phases_completed', 23),
                           ('deadline_exceeded', True), ('elapsed_seconds', 1201), ('exit_code', False)):
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                self.write(self.device, 'device-state.json', {**self.state, key: value})
                analyze(self.root)

    def test_invalid_counters_missing_phase_and_invalid_process_are_rejected(self):
        for text in (self.resources.replace('16000', '-1', 1),
                     '\n'.join(s for s in self.resources.splitlines() if not s.startswith('0 '))+'\n',
                     self.resources.replace('2000 6 4', '0 6 4', 1)):
            with self.subTest(text=text[:40]), self.assertRaises(EvidenceError):
                (self.device/'resources.tsv').write_text(text)
                analyze(self.root)

    def test_low_available_memory_is_diagnostic_not_an_acceptance_floor(self):
        for value in ('4095', '0'):
            (self.device/'resources.tsv').write_text(self.resources.replace('16000', value))
            result = analyze(self.root)
            self.assertTrue(result['checkpoint_criteria_met'])
            self.assertEqual(result['minimum_memavailable_kib'], int(value))
            self.assertEqual(result['resource_policy'], 'flash-only')
            self.assertIsNone(result['memory_acceptance_threshold'])

    def test_missing_monitor_window_is_not_resource_acceptance(self):
        (self.device/'resources.tsv').write_text('\n'.join(s for s in self.resources.splitlines()
            if not s.startswith('0 ') or s.startswith('0 0 '))+'\n')
        with self.assertRaisesRegex(EvidenceError, 'observation gap'):
            analyze(self.root)

    def test_boot_and_executed_plan_must_match(self):
        for name in ('boot-after', 'plan.sha256'):
            path = self.device/name
            original = path.read_bytes()
            path.write_text('changed\n')
            with self.subTest(name=name), self.assertRaises(EvidenceError):
                analyze(self.root)
            path.write_bytes(original)

    def test_pid_reuse_is_not_a_cpu_measurement(self):
        (self.device/'0.stat-after').write_text(self.stat(20, born=1001))
        with self.assertRaisesRegex(EvidenceError, 'identity or CPU'):
            analyze(self.root)

    def test_changed_device_configuration_is_rejected(self):
        (self.device/'configuration-after').write_text('changed\n')
        with self.assertRaisesRegex(EvidenceError, 'configuration'):
            analyze(self.root)

    def test_failed_monitor_cannot_pass_with_complete_resource_samples(self):
        receipt = json.loads((self.device/'0.json').read_text())
        self.write(self.device, '0.json', {**receipt, 'monitor_exit': 1})
        with self.assertRaisesRegex(EvidenceError, 'client receipt'):
            analyze(self.root)

    def test_all_native_inputs_are_frozen(self):
        for name in NATIVE_INPUTS:
            path = self.root/name
            original = path.read_bytes()
            path.write_bytes(original+b'changed')
            with self.subTest(name=name), self.assertRaises(EvidenceError):
                analyze(self.root)
            path.write_bytes(original)

    def test_missing_progress_and_failed_probe_are_rejected(self):
        path = self.root/'progress.jsonl'
        original = path.read_text()
        path.write_text('\n'.join(original.splitlines()[:-1])+'\n')
        with self.assertRaisesRegex(EvidenceError, 'progress'):
            analyze(self.root)
        path.write_text(original)
        (self.device/'0.probe-exit').write_text('28\n')
        with self.assertRaises(EvidenceError):
            analyze(self.root)

    def test_freeze_refuses_to_overwrite_any_existing_plan(self):
        before = (self.root/'plan.json').read_bytes()
        with self.assertRaisesRegex(EvidenceError, 'already exists'):
            freeze(self.root)
        self.assertEqual((self.root/'plan.json').read_bytes(), before)

    def prepare_stand_launch(self):
        for name in ('progress.jsonl', 'stand-state.json'):
            (self.root/name).unlink()

    def test_frozen_native_driver_reaches_process_setup(self):
        self.prepare_stand_launch()
        with patch('native_checkpoint.Processes', side_effect=RuntimeError('launch control')) as launch:
            with self.assertRaisesRegex(RuntimeError, 'launch control'):
                serve(self.root)
            launch.assert_called_once()

    def test_unfrozen_native_driver_is_rejected_before_process_setup(self):
        self.prepare_stand_launch()
        changed = self.root/'different-driver.py'
        changed.write_bytes((self.root/'native_checkpoint.py').read_bytes()+b'\n# changed driver\n')
        spec = importlib.util.spec_from_file_location('different_native_driver', changed)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module, 'Processes', side_effect=AssertionError('unexpected process startup')) as launch:
            with self.assertRaisesRegex(EvidenceError, 'frozen native driver'):
                module.serve(self.root)
            launch.assert_not_called()

    def test_unfrozen_native_helpers_are_rejected_before_process_setup(self):
        self.prepare_stand_launch()
        changed = self.root/'different-helper.py'
        changed.write_text('# different executed helper\n')
        for name in ('analyze_native_checkpoint', 'native_checkpoint_plan',
                     'analyze_checkpoint', 'analyze_network', 'checkpoint_process'):
            with self.subTest(module=name), patch.dict(sys.modules,
                    {name: SimpleNamespace(__file__=str(changed))}):
                with patch('native_checkpoint.Processes', side_effect=AssertionError('unexpected process startup')) as launch:
                    with self.assertRaisesRegex(EvidenceError, 'executed helper.*'+name):
                        serve(self.root)
                    launch.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'native shell startup requires Linux')
    def test_device_verifies_executed_script_before_loading_settings(self):
        with tempfile.TemporaryDirectory(prefix='lc-native-', dir='/tmp') as temporary:
            stage = Path(temporary)
            for name in DEVICE_INPUTS:
                shutil.copyfile(self.root/'device-stage'/name, stage/name)
            (stage/'settings.sh').write_text('touch settings-loaded\nexit 67\n')
            (stage/'device.sha256').write_text(''.join(digest(stage/name)+'  '+name+'\n'
                                                       for name in sorted(DEVICE_INPUTS)))
            changed = stage/'different-device-driver.sh'
            changed.write_bytes((stage/'native-device.sh').read_bytes()+b'\n# changed driver\n')
            bad = subprocess.run(['sh', str(changed), str(stage)], capture_output=True, timeout=10)
            self.assertNotEqual(bad.returncode, 0)
            self.assertNotEqual(bad.returncode, 67)
            self.assertFalse((stage/'settings-loaded').exists())
            good = subprocess.run(['sh', str(stage/'native-device.sh'), str(stage)],
                                  capture_output=True, timeout=10)
            self.assertEqual(good.returncode, 67, good.stderr)
            self.assertTrue((stage/'settings-loaded').exists())

    def test_cli_exit_status_rejects_resource_failure(self):
        command = [sys.executable, str(self.root/'analyze_native_checkpoint.py'), str(self.root)]
        good = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.write(self.device, 'device-state.json', {**self.state, 'deadline_exceeded': True})
        bad = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == '__main__':
    unittest.main()
