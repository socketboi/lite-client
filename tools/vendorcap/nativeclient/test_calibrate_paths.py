import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest

from analyze_checkpoint import compare_scenario
from analyze_network import EvidenceError, OPENING_SETTINGS
from calibrate_paths import INPUTS, analyze, compare_control, make_plan, validate_plan
from test_analyze_checkpoint import fixture


class PathCalibrationTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in INPUTS:
            (self.root / name).write_text('fixture-' + name)
        self.plan = make_plan()
        self.plan['inputs'] = {name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                               for name in INPUTS}
        (self.root / 'plan.json').write_text(json.dumps(self.plan))
        (self.root / 'run-state.json').write_text(json.dumps(dict(
            exit_code=0, cleanup_exit=0, phases_completed=72, blocks_completed=12)))
        progress = []
        for phase in self.plan['phases']:
            progress += [dict(phase=phase, stage='start'), dict(phase=phase, stage='complete')]
            key = f"{phase['block']:02d}-{phase['round']}-{phase['role']}"
            receipt = dict(phase=phase, binary_sha256=self.plan['inputs']['xray'],
                           alive_before_probe=True, alive_after_probe=True,
                           probe_exit=52, stop_signal=15, client_exit=0)
            (self.root / (key + '.json')).write_text(json.dumps(receipt))
        (self.root / 'progress.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in progress))
        for block in range(1, 13):
            directory = self.root / f'block-{block:02d}'
            directory.mkdir()
            state = dict(server_sha256=self.plan['inputs']['xray'], dest_sha256=self.plan['inputs']['dest'],
                         alive_after_phases=True, server_exit=0, dest_exit=-15)
            (directory / 'stand-state.json').write_text(json.dumps(state))
            captures = []
            for phase in [p for p in self.plan['phases'] if p['block'] == block]:
                for index in range(5):
                    path = '/' if index == 0 else '/h0'
                    captures.append(f"{phase['role']} closeafter | 100 bytes\n  sample {phase['round']}\n"
                                    '  PREFACE #1\n  ' + OPENING_SETTINGS + '\n'
                                    '  [4] WINDOW_UPDATE stream=0 +1073741824\n'
                                    '  [10] HEADERS stream=1 end=true order=:path\n'
                                    f'    :path: {path}\n'
                                    '  timing clock=io-return-v2\n  timing r+100 HEADERS1e capture+1\n')
            (directory / 'dest.log').write_text(''.join(captures))

    def test_complete_control_never_grants_acceptance(self):
        result = analyze(self.root)
        self.assertFalse(result['acceptance'])
        self.assertFalse(result['G2Closed'])
        self.assertEqual(result['path_rate_rejections'], 0)
        self.assertEqual(len(result['blocks']), 12)

    def test_legal_root_choices_can_fail_the_unchanged_rate_check(self):
        path = self.root / 'block-01/dest.log'
        text = path.read_text()
        # Only the first round of the lc label gets two further legal root draws.
        start = text.index('lc closeafter')
        text = text[:start] + text[start:].replace(':path: /h0', ':path: /', 2)
        path.write_text(text)
        result = analyze(self.root)
        self.assertEqual(result['path_rate_rejections'], 1)
        self.assertEqual(result['blocks'][0]['clients']['lc']['harvested'], 10)
        self.assertEqual(result['blocks'][0]['clients']['ref']['harvested'], 12)
        self.assertAlmostEqual(result['blocks'][0]['harvesting_gap_pp'], 100 * 2 / 15)
        self.assertFalse(result['blocks'][0]['path_rate_criterion_met'])

    def test_frozen_plan_rejects_changed_counts_thresholds_and_order(self):
        changes = []
        for field, value in (('blocks', 11), ('max_seconds', 1800), ('acceptance', True)):
            changed = copy.deepcopy(self.plan)
            changed[field] = value
            changes.append(changed)
        changed = copy.deepcopy(self.plan)
        changed['criteria']['rate_gap_pp'] = 20
        changes.append(changed)
        changed = copy.deepcopy(self.plan)
        changed['implementations']['lc'] = 'lite-client'
        changes.append(changed)
        changed = copy.deepcopy(self.plan)
        changed['phases'][0], changed['phases'][1] = changed['phases'][1], changed['phases'][0]
        changes.append(changed)
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(EvidenceError):
                validate_plan(changed)

    def test_bad_executed_identity_probe_liveness_and_exit_fail(self):
        path = self.root / '01-1-ref.json'
        saved = path.read_bytes()
        for field, value in (('binary_sha256', '0' * 64), ('probe_exit', 28),
                             ('alive_before_probe', False), ('alive_after_probe', False), ('client_exit', -15)):
            changed = json.loads(saved)
            changed[field] = value
            path.write_text(json.dumps(changed))
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                analyze(self.root)
            path.write_bytes(saved)

    def test_input_wire_progress_and_cleanup_changes_fail(self):
        changes = (
            ('xray', lambda data: data + b'changed'),
            ('block-01/dest.log', lambda data: data.replace(b'[24] SETTINGS', b'[18] SETTINGS', 1)),
            ('progress.jsonl', lambda data: b'\n'.join(data.splitlines()[1:]) + b'\n'),
            ('progress.jsonl', lambda data: b'\n'.join(data.splitlines()[:-1]) + b'\n'),
            ('block-01/stand-state.json', lambda data: data.replace(b'"dest_exit": -15', b'"dest_exit": 0')),
            ('run-state.json', lambda data: data.replace(b'"cleanup_exit": 0', b'"cleanup_exit": 1')),
        )
        for name, mutate in changes:
            path = self.root / name
            saved = path.read_bytes()
            path.write_bytes(mutate(saved))
            with self.subTest(name=name), self.assertRaises(EvidenceError):
                analyze(self.root)
            path.write_bytes(saved)

    def test_path_rejections_are_distinct_from_latency_failures(self):
        path = self.root / 'block-01/dest.log'
        sections = re.split(r'(?=ref closeafter |lc closeafter )', path.read_text())
        path.write_text(''.join(section.replace('r+100 ', 'r+201 ') if section.startswith('lc ')
                               else section for section in sections))
        result = analyze(self.root)
        self.assertEqual(result['path_rate_rejections'], 0)
        self.assertFalse(result['blocks'][0]['criteria_met'])
        self.assertEqual(result['blocks'][0]['timing_regression_us'], 101)

    def test_single_scenario_comparison_preserves_the_rate_boundary(self):
        rows = [r for n in (1, 2, 3) for role in ('ref', 'lc')
                for r in fixture('closeafter', role, n)]
        candidate = [row for row in rows if row['role'] == 'lc' and row['paths'] == ['/h0']]
        candidate[0]['paths'] = ['/']
        self.assertTrue(compare_control(rows)['criteria_met'])
        candidate[1]['paths'] = ['/']
        self.assertFalse(compare_control(rows)['criteria_met'])
        with self.assertRaises(EvidenceError):
            compare_scenario(rows, 'unknown')


if __name__ == '__main__':
    unittest.main()
