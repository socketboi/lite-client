import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from analyze_cache import NATIVE_INPUTS, NATIVE_OBSERVERS, NATIVE_ORIGINALS, analyze
from analyze_network import EvidenceError
from prepare_cache_trace import prepare
import test_analyze_cache


class NativeCacheTest(unittest.TestCase):
    def setUp(self):
        host = test_analyze_cache.CacheEvidenceTest()
        host.setUp()
        self.addCleanup(host.doCleanups)
        self.root = host.root
        for name in NATIVE_INPUTS:
            if not (self.root / name).exists():
                (self.root / name).write_text('fixture-' + name)
        original = {name: hashlib.sha256(name.encode()).hexdigest() for name in NATIVE_ORIGINALS}
        (self.root / 'source.sha256').write_text(''.join(f'{v}  {k}\n' for k, v in original.items()))
        digest = lambda name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
        observer = dict(schema='spider-cache-observers-native-v1', originals=original,
                        observers={name: digest(name) for name in NATIVE_OBSERVERS})
        (self.root / 'observer-inputs.json').write_text(json.dumps(observer))
        self.plan = json.loads((self.root / 'plan.json').read_text())
        self.plan.update(schema='native-cache-retention-trace-v1', architecture='mipsel',
                         guard_memavailable_kib=4096, max_device_seconds=240,
                         inputs={name: digest(name) for name in NATIVE_INPUTS})
        (self.root / 'plan.json').write_text(json.dumps(self.plan))
        for phase in self.plan['phases']:
            if phase['role'] == 'lc':
                path = self.root / f"{phase['round']}-lc.json"
                receipt = json.loads(path.read_text())
                receipt['client_exit'] = 143
                path.write_text(json.dumps(receipt))
        self.state = dict(exit_code=0, monitor_exit=0, boot_unchanged=True,
                          config_unchanged=True, interfaces_unchanged=True)
        (self.root / 'device-state.json').write_text(json.dumps(self.state))
        labels = ['staging'] + [f"{p['round']}-{p['role']}" for p in self.plan['phases']] + ['cleanup']
        self.samples = ''.join(f'{i * 8 + j} {label} 8192\n'
                               for i, label in enumerate(labels) for j in range(8))
        (self.root / 'memory.tsv').write_text(self.samples)

    def test_native_diagnostic_keeps_acceptance_open(self):
        result = analyze(self.root, native=True)
        self.assertFalse(result['acceptance'])
        self.assertFalse(result['G2Closed'])
        self.assertEqual(result['minimum_sampled_memavailable_kib'], 8192)
        with self.assertRaises(EvidenceError):
            analyze(self.root)

    def test_guards_and_restoration_cannot_be_weakened(self):
        for field in self.state:
            state = copy.deepcopy(self.state)
            state[field] = 1 if field.endswith('exit') or field == 'exit_code' else False
            (self.root / 'device-state.json').write_text(json.dumps(state))
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                analyze(self.root, native=True)
        (self.root / 'device-state.json').write_text(json.dumps(self.state))
        self.plan['guard_memavailable_kib'] = 2048
        (self.root / 'plan.json').write_text(json.dumps(self.plan))
        with self.assertRaises(EvidenceError):
            analyze(self.root, native=True)

    def test_memory_requires_staging_continuity_and_each_phase(self):
        for bad in (self.samples.replace('8192', '4095', 1),
                    self.samples.replace('staging', '1-ref'),
                    self.samples.replace('16 1-lc 8192\n', ''),
                    self.samples.replace('16 1-lc', '160 1-lc'),
                    self.samples.replace('cleanup', 'staging')):
            (self.root / 'memory.tsv').write_text(bad)
            with self.subTest(bad=bad), self.assertRaises(EvidenceError):
                analyze(self.root, native=True)


class PrepareCacheTest(unittest.TestCase):
    def test_native_overlay_preserves_originals_and_uses_runner(self):
        root = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'observers'
            before = {name: (root / name).read_bytes() for name in NATIVE_ORIGINALS}
            receipt = prepare(root, output, native_reference=True)
            self.assertEqual(set(receipt['originals']), NATIVE_ORIGINALS)
            self.assertEqual(set(receipt['observers']), NATIVE_OBSERVERS)
            overlay = json.loads((output / 'go-overlay.json').read_text())['Replace']
            self.assertIn(str(root / 'tools/vendorcap/nativeclient/runner/main.go'), overlay)
            self.assertNotIn(str(root / 'vendor/Xray-core/main/run.go'), overlay)
            self.assertEqual(before, {name: (root / name).read_bytes() for name in NATIVE_ORIGINALS})

    def test_changed_anchor_creates_no_partial_output(self):
        root = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'source', Path(directory) / 'output'
            for name in NATIVE_ORIGINALS:
                dest = source / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / name, dest)
            runner = source / 'tools/vendorcap/nativeclient/runner/main.go'
            runner.write_bytes(runner.read_bytes().replace(b'defer server.Close()', b'defer server.Stop()'))
            with self.assertRaises(ValueError):
                prepare(source, output, native_reference=True)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
