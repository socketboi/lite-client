import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from analyze_checkpoint import (INPUTS, SCENARIOS, SCHEMA, analyze, checkpoint_criteria,
                                compare, make_plan, validate_rows)
from analyze_network import EvidenceError, OPENING_SETTINGS


def fixture(scenario='bigbody', role='ref', sample=1):
    rows = []
    target = {'bigbody': '/bb', 'gzbody': '/gz', 'latebig': '/late'}
    for n in range(5):
        paths = ['/' if n == 0 else '/h0'] if scenario == 'closeafter' else ['/', target[scenario]]
        frames = [OPENING_SETTINGS, '[4] WINDOW_UPDATE stream=0 +1073741824',
                  '[10] HEADERS stream=1 end=true']
        if scenario != 'closeafter':
            frames.append('[10] HEADERS stream=3 end=true')
        rows.append(dict(role=role, scenario=scenario, sample=sample, bytes=100,
                         prefaces=1, invalid=False, cancel=0, clock='io-return-v2',
                         first_request_us=100, paths=paths, frames=frames))
    return rows


class CheckpointTest(unittest.TestCase):
    def test_root_remains_legal_after_a_harvested_path(self):
        rows = fixture('closeafter')
        rows[3]['paths'] = ['/']
        validate_rows(rows, 'closeafter', 1)

    def test_old_host_schema_is_not_silently_reinterpreted(self):
        for schema in ('host-g2-checkpoint-v1', 'host-g2-checkpoint-v2', 'host-g2-checkpoint-v3'):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'plan.json').write_text(json.dumps(dict(schema=schema)))
                with self.assertRaisesRegex(EvidenceError, 'unsupported checkpoint design'):
                    analyze(root)

    def test_faster_candidate_is_not_a_latency_regression(self):
        rows = [row for n in (1, 2, 3) for sc in SCENARIOS
                for role in ('ref', 'lc') for row in fixture(sc, role, n)]
        for row in rows:
            row['first_request_us'] = 100 if row['role'] == 'lc' else 5000
        for result in compare(rows):
            self.assertTrue(result['criteria_met'])
            self.assertEqual(result['timing_median_gap_us'], 4900)
            self.assertEqual(result['timing_median_delta_us'], -4900)
            self.assertEqual(result['timing_regression_us'], 0)

    def test_latency_regression_budget_keeps_its_boundary(self):
        rows = [row for n in (1, 2, 3) for sc in SCENARIOS
                for role in ('ref', 'lc') for row in fixture(sc, role, n)]
        for delta, accepted in ((100, True), (101, False)):
            for row in rows:
                row['first_request_us'] = 100 + delta if row['role'] == 'lc' else 100
            self.assertTrue(all(r['criteria_met'] == accepted for r in compare(rows)))

    def test_all_four_scenarios_validate(self):
        for sc in SCENARIOS:
            validate_rows(fixture(sc), sc, 1)

    def test_incomplete_or_malformed_groups_fail(self):
        rows = fixture()
        changes = [rows[:-1], rows + [rows[0]],
                   [{**r, 'clock': None} for r in rows],
                   [{**r, 'sample': 2} for r in rows],
                   [{**r, 'frames': [OPENING_SETTINGS]} for r in rows],
                   [{**r, 'frames': r['frames'][:2]} for r in rows],
                   [{**r, 'paths': ['/']} for r in rows],
                   [{**r, 'cancel': 2} for r in rows],
                   [{**r, 'invalid': True} for r in rows]]
        for changed in changes:
            with self.subTest(changed=changed):
                with self.assertRaises(EvidenceError):
                    validate_rows(changed, 'bigbody', 1)
        rows = fixture('closeafter')
        rows[0]['paths'] = ['/h20']
        with self.assertRaises(EvidenceError):
            validate_rows(rows, 'closeafter', 1)

    def test_criteria_failures_are_distinct_from_invalid_evidence(self):
        rows = [row for n in (1, 2, 3) for sc in SCENARIOS
                for role in ('ref', 'lc') for row in fixture(sc, role, n)]
        self.assertTrue(all(r['criteria_met'] for r in compare(rows)))
        slow = copy.deepcopy(rows)
        for row in slow:
            if row['role'] == 'lc':
                row['first_request_us'] = 201
        self.assertTrue(all(not r['criteria_met'] for r in compare(slow)))
        cancels = copy.deepcopy(rows)
        changed = 0
        for row in cancels:
            if row['role'] == 'lc' and row['scenario'] == 'bigbody' and changed < 2:
                row['cancel'] = 1
                changed += 1
        self.assertTrue(compare(cancels)[0]['criteria_met'])
        self.assertAlmostEqual(compare(cancels)[0]['cancellation_gap_pp'], 200 / 15)
        lost = copy.deepcopy(rows)
        for row in lost:
            if row['role'] == 'lc' and row['scenario'] == 'closeafter':
                row['paths'] = ['/']
        self.assertTrue(compare(lost)[3]['criteria_met'])
        self.assertEqual(compare(lost)[3]['harvesting_gap_pp'], 80)

    def test_even_extreme_scheduler_rates_remain_diagnostic(self):
        rows = [row for n in (1, 2, 3) for sc in SCENARIOS
                for role in ('ref', 'lc') for row in fixture(sc, role, n)]
        for row in rows:
            row['cancel'] = int(row['role'] == 'lc')
            if row['scenario'] == 'closeafter':
                row['paths'] = ['/h0' if row['role'] == 'lc' else '/']
        results = compare(rows)
        self.assertTrue(all(row['criteria_met'] for row in results))
        self.assertTrue(all(row['cancellation_gap_pp'] == 100 for row in results))
        self.assertEqual(results[3]['harvesting_gap_pp'], 100)


class CheckpointEvidenceTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in INPUTS:
            (self.root / name).write_text('fixture-' + name)
        self.plan = make_plan({name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                               for name in INPUTS})
        phases = self.plan['phases']
        self.write('plan.json', self.plan)
        self.write('run-state.json', dict(exit_code=0, cleanup_exit=0, rounds_completed=3,
                                         phases_completed=24))
        self.write('stand-state.json', dict(server_sha256=self.plan['inputs']['reference.host'],
                   dest_sha256=self.plan['inputs']['dest.host'], alive_after_phases=True,
                   server_exit=0, dest_exit=-15))
        progress, captures = [], []
        for phase in phases:
            key = f"{phase['round']}-{phase['role']}-{phase['scenario']}"
            progress += [dict(phase=phase, stage='start'),
                         dict(phase=phase, stage='complete', alive=True)]
            binary = 'lc-tunnel.host' if phase['role'] == 'lc' else 'reference.host'
            self.write(key + '.json', dict(phase=phase, binary_sha256=self.plan['inputs'][binary],
                       alive_before_probe=True, alive_after_probe=True, probe_exit=52,
                       stop_signal=15, client_exit=-15 if phase['role'] == 'lc' else 0))
            (self.root / (key + '.probe-exit')).write_text('52\n')
            for row in fixture(phase['scenario'], phase['role'], phase['round']):
                captures.append(f"{row['role']} {row['scenario']} | 100 bytes\n"
                                f"  sample {row['sample']}\n  PREFACE #1\n  {OPENING_SETTINGS}\n"
                                '  [4] WINDOW_UPDATE stream=0 +1073741824\n')
                for stream, target in zip((1, 3), row['paths']):
                    captures.append(f'  [10] HEADERS stream={stream} end=true order=:path\n'
                                    f'    :path: {target}\n')
                captures.append('  timing clock=io-return-v2\n  timing r+100 HEADERS1e capture+1\n')
        (self.root / 'progress.jsonl').write_text(''.join(json.dumps(p) + '\n' for p in progress))
        (self.root / 'dest.log').write_text(''.join(captures))

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def test_complete_evidence_keeps_acceptance_separate(self):
        result = analyze(self.root)
        self.assertTrue(result['checkpoint_criteria_met'])
        self.assertEqual(result['acceptance_scope'], 'checkpoint')
        self.assertEqual(result['schema'], SCHEMA)
        self.assertNotIn('G2Closed', result)

    def test_every_actual_input_is_hashed(self):
        for name in INPUTS:
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                try:
                    path.write_bytes(original + b'changed')
                    with self.assertRaisesRegex(EvidenceError, 'checkpoint input changed'):
                        analyze(self.root)
                finally:
                    path.write_bytes(original)

    def test_missing_client_receipt_is_rejected(self):
        (self.root / '1-ref-bigbody.json').unlink()
        with self.assertRaisesRegex(EvidenceError, 'missing checkpoint client receipt'):
            analyze(self.root)

    def test_client_receipt_fields_are_checked(self):
        name = '1-ref-bigbody.json'
        original = json.loads((self.root / name).read_text())
        changes = dict(phase={}, binary_sha256='0' * 64, alive_before_probe=False,
                       alive_after_probe=False, probe_exit=56, stop_signal=9, client_exit=-9)
        for field, value in changes.items():
            with self.subTest(field=field):
                self.write(name, {**original, field: value})
                with self.assertRaisesRegex(EvidenceError, 'checkpoint client identity'):
                    analyze(self.root)
        self.write(name, original)
        name = '1-lc-bigbody.json'
        original = json.loads((self.root / name).read_text())
        self.write(name, {**original, 'client_exit': 0})
        with self.assertRaisesRegex(EvidenceError, 'checkpoint client identity'):
            analyze(self.root)

    def test_stand_receipt_fields_are_checked(self):
        name = 'stand-state.json'
        original = json.loads((self.root / name).read_text())
        changes = dict(server_sha256='0' * 64, dest_sha256='0' * 64,
                       alive_after_phases=False, server_exit=-9, dest_exit=0)
        for field, value in changes.items():
            with self.subTest(field=field):
                self.write(name, {**original, field: value})
                with self.assertRaisesRegex(EvidenceError, 'checkpoint stand identity'):
                    analyze(self.root)
        (self.root / name).unlink()
        with self.assertRaisesRegex(EvidenceError, 'missing checkpoint stand receipt'):
            analyze(self.root)

    def test_phase_count_and_legacy_schema_are_rejected(self):
        self.write('run-state.json', dict(exit_code=0, cleanup_exit=0, rounds_completed=3,
                                         phases_completed=23))
        with self.assertRaisesRegex(EvidenceError, 'checkpoint driver or cleanup failed'):
            analyze(self.root)
        self.write('plan.json', {**self.plan, 'schema': 'host-g2-checkpoint-v2'})
        with self.assertRaisesRegex(EvidenceError, 'unsupported checkpoint design'):
            analyze(self.root)

    def test_manifest_and_frozen_policy_cannot_be_omitted(self):
        for field in ('criteria_frozen', 'acceptance_scope'):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.plan)
                del changed[field]
                self.write('plan.json', changed)
                with self.assertRaisesRegex(EvidenceError, 'unsupported checkpoint design'):
                    analyze(self.root)
        for name in ('leaf.key', 'server.json', 'analyze_network.py'):
            with self.subTest(name=name):
                changed = copy.deepcopy(self.plan)
                del changed['inputs'][name]
                self.write('plan.json', changed)
                with self.assertRaisesRegex(EvidenceError, 'incomplete checkpoint input manifest'):
                    analyze(self.root)

    def test_previous_rate_policy_cannot_be_attached_to_a_new_plan(self):
        for changed in ({**self.plan, 'criteria': dict(rate_gap_pp=10, timing_regression_us=100)},
                        {**self.plan, 'G2Closed': False},
                        {**self.plan, 'acceptance_scope': 'release'}):
            self.write('plan.json', changed)
            with self.assertRaisesRegex(EvidenceError, 'unsupported checkpoint design'):
                analyze(self.root)

    def test_prepare_plan_freezes_inputs_without_overwriting_evidence(self):
        plan_file = self.root / 'plan.json'
        plan_file.unlink()
        command = [sys.executable, str(Path(__file__).with_name('analyze_checkpoint.py')),
                   str(self.root), '--prepare-plan']
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(plan_file.read_text()), self.plan)
        frozen = plan_file.read_bytes()
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(plan_file.read_bytes(), frozen)

    def test_command_exit_status_follows_the_actual_checkpoint_result(self):
        command = [sys.executable, str(Path(__file__).with_name('analyze_checkpoint.py')),
                   str(self.root)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['checkpoint_criteria_met'])
        path = self.root / 'dest.log'
        sections = re.split(r'(?=(?:ref|lc) (?:bigbody|gzbody|latebig|closeafter) \|)',
                            path.read_text())
        path.write_text(''.join(section.replace('r+100 ', 'r+201 ')
                               if section.startswith('lc ') else section for section in sections))
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(json.loads(result.stdout)['checkpoint_criteria_met'])

    def test_plan_builder_rejects_missing_or_malformed_hashes(self):
        inputs = self.plan['inputs']
        for changed in ({}, {**inputs, 'server.json': 'invalid'},
                        {**inputs, '../server.json': '0' * 64}):
            with self.assertRaisesRegex(EvidenceError, 'invalid checkpoint input manifest'):
                make_plan(changed)
        changed = checkpoint_criteria()
        changed['timing_regression_us'] = 0
        self.assertEqual(checkpoint_criteria()['timing_regression_us'], 100)

    def test_timeout_probe_and_failed_cleanup_are_not_accepted(self):
        (self.root / '1-ref-bigbody.probe-exit').write_text('28\n')
        with self.assertRaisesRegex(EvidenceError, 'invalid wrong-key checkpoint probe'):
            analyze(self.root)
        (self.root / '1-ref-bigbody.probe-exit').write_text('52\n')
        self.write('run-state.json', dict(exit_code=0, cleanup_exit=1, rounds_completed=3,
                                         phases_completed=24))
        with self.assertRaisesRegex(EvidenceError, 'checkpoint driver or cleanup failed'):
            analyze(self.root)


if __name__ == '__main__':
    unittest.main()
