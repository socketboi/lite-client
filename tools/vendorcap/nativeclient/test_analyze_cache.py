import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from analyze_cache import FULL_MASK, INPUTS, OBSERVERS, ORIGINALS, analyze, classify_cache, parse_cache
from analyze_network import EvidenceError, OPENING_SETTINGS
from test_analyze_checkpoint import fixture


def observations(paths=('/', '/h0', '/', '/h8', '/h19')):
    rows = []
    for i, path in enumerate(paths):
        rows.append(dict(index=len(rows), kind='draw', before=0,
                         count=1 if i == 0 else 21, mask=1 if i == 0 else FULL_MASK, path=path))
        rows.append(dict(index=len(rows), kind='commit', before=1 if i == 0 else 21,
                         count=21, mask=FULL_MASK, path='-'))
    wire = fixture('closeafter')
    for row, path in zip(wire, paths):
        row['paths'] = [path]
    return rows, wire


class CacheTest(unittest.TestCase):
    def test_root_after_commit_is_not_a_cache_failure(self):
        events, wire = observations()
        result = classify_cache(events, wire, 'fixture')
        self.assertEqual(result['root_draws_after_commit'], [4])
        self.assertEqual(result['commits'], 5)
        self.assertEqual(result['final_mask'], FULL_MASK)

    def test_no_root_after_commit_is_required(self):
        events, wire = observations(('/', '/h0', '/h1', '/h8', '/h19'))
        self.assertEqual(classify_cache(events, wire, 'fixture')['root_draws_after_commit'], [])

    def test_phase_matching_does_not_invent_socket_order(self):
        events, wire = observations()
        classify_cache(events, list(reversed(wire)), 'fixture')

    def test_cache_loss_duplicate_or_missing_commit_is_rejected(self):
        original, wire = observations()
        changes = []
        for index, field, value in ((1, 'mask', FULL_MASK ^ 2), (2, 'count', 1),
                                     (3, 'before', 1), (4, 'mask', FULL_MASK ^ 1),
                                     (4, 'path', '/h20'), (9, 'mask', FULL_MASK ^ 2)):
            events = copy.deepcopy(original)
            events[index][field] = value
            changes.append(events)
        changes += [original[:-1], original + [original[-1]]]
        for events in changes:
            with self.subTest(events=events):
                with self.assertRaises(EvidenceError):
                    classify_cache(events, wire, 'fixture')

    def test_different_wire_path_is_rejected(self):
        events, wire = observations()
        wire[1]['paths'] = ['/h1']
        with self.assertRaises(EvidenceError):
            classify_cache(events, wire, 'fixture')

    def test_dump_requires_complete_unique_nonoverflowing_events(self):
        text = 'CACHE_BEGIN 2 0\nCACHE 0 draw 0 1 1 /\nCACHE 1 commit 1 21 2097151 -\nCACHE_END 2\n'
        self.assertEqual(len(parse_cache(text, 'fixture')), 2)
        for bad in (text.replace('BEGIN 2 0', 'BEGIN 2 1'), text + text,
                    text.replace('CACHE_END 2', ''), text.replace('CACHE 1 commit', 'CACHE 2 commit'),
                    text.replace('CACHE 1 commit', 'CACHE 1 unknown')):
            with self.subTest(bad=bad):
                with self.assertRaises(EvidenceError):
                    parse_cache(bad, 'fixture')


class CacheEvidenceTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in INPUTS:
            (self.root / name).write_text('fixture-' + name)
        digest = lambda name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
        original = {name: hashlib.sha256(('original-' + name).encode()).hexdigest() for name in ORIGINALS}
        (self.root / 'source.sha256').write_text(''.join(f'{value}  {name}\n' for name, value in original.items()))
        observer = dict(schema='spider-cache-observers-v1', originals=original,
                        observers={name: digest(name) for name in OBSERVERS})
        (self.root / 'observer-inputs.json').write_text(json.dumps(observer))
        phases = [dict(round=n, role=role) for n, roles in
                  ((1, ('ref', 'lc')), (2, ('lc', 'ref'))) for role in roles]
        plan = dict(schema='host-cache-retention-trace-v1', rounds=2, scenario='closeafter',
                    connections_per_phase=5, acceptance=False, phases=phases,
                    inputs={name: digest(name) for name in INPUTS})
        (self.root / 'plan.json').write_text(json.dumps(plan))
        (self.root / 'run-state.json').write_text(json.dumps(dict(exit_code=0, cleanup_exit=0, phases_completed=4)))
        captures = []
        for phase in phases:
            key = f"{phase['round']}-{phase['role']}"
            events, wire = observations()
            trace = f'CACHE_BEGIN {len(events)} 0\n'
            for row in events:
                trace += f"CACHE {row['index']} {row['kind']} {row['before']} {row['count']} {row['mask']} {row['path']}\n"
            (self.root / (key + '.log')).write_text(trace + f'CACHE_END {len(events)}\n')
            binary = 'lc.trace' if phase['role'] == 'lc' else 'xray.trace'
            receipt = dict(phase=phase, alive_before_probe=True, alive_after_probe=True,
                           binary_sha256=plan['inputs'][binary], probe_exit=52, stop_signal=15,
                           client_exit=-15 if phase['role'] == 'lc' else 0)
            (self.root / (key + '.json')).write_text(json.dumps(receipt))
            for row in wire:
                captures.append(f"{phase['role']} closeafter | 100 bytes\n  sample {phase['round']}\n"
                                '  PREFACE #1\n  ' + OPENING_SETTINGS + '\n'
                                '  [4] WINDOW_UPDATE stream=0 +1073741824\n'
                                '  [10] HEADERS stream=1 end=true order=:path\n'
                                f"    :path: {row['paths'][0]}\n"
                                '  timing clock=io-return-v2\n  timing r+2000 HEADERS1e capture+1\n')
        (self.root / 'dest.log').write_text(''.join(captures))

    def test_complete_diagnostic_is_not_acceptance(self):
        result = analyze(self.root)
        self.assertEqual(result['connections'], 20)
        self.assertFalse(result['G2Closed'])
        self.assertFalse(result['acceptance'])

    def test_bad_probe_liveness_exit_and_cleanup_fail(self):
        receipt = self.root / '1-lc.json'
        saved = receipt.read_bytes()
        for field, bad in (('probe_exit', 28), ('alive_after_probe', False), ('client_exit', 0)):
            record = json.loads(saved)
            record[field] = bad
            receipt.write_text(json.dumps(record))
            with self.assertRaises(EvidenceError):
                analyze(self.root)
            receipt.write_bytes(saved)
        state = self.root / 'run-state.json'
        state.write_text(json.dumps(dict(exit_code=0, cleanup_exit=1, phases_completed=4)))
        with self.assertRaises(EvidenceError):
            analyze(self.root)

    def test_changed_binary_and_partial_wire_are_rejected(self):
        binary = self.root / 'lc.trace'
        saved = binary.read_bytes()
        binary.write_bytes(saved + b'changed')
        with self.assertRaises(EvidenceError):
            analyze(self.root)
        binary.write_bytes(saved)
        log = self.root / 'dest.log'
        log.write_text(log.read_text().replace('ref closeafter | 100 bytes', 'ref closeafter | 0 bytes', 1))
        with self.assertRaises(EvidenceError):
            analyze(self.root)

    def test_rehashed_observer_still_must_match_original_source(self):
        path = self.root / 'observer-inputs.json'
        observer = json.loads(path.read_text())
        observer['originals']['src/reality/paths.c'] = '0' * 64
        path.write_text(json.dumps(observer))
        plan_path = self.root / 'plan.json'
        plan = json.loads(plan_path.read_text())
        plan['inputs'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        plan_path.write_text(json.dumps(plan))
        with self.assertRaisesRegex(EvidenceError, 'observer source identity'):
            analyze(self.root)


if __name__ == '__main__':
    unittest.main()
