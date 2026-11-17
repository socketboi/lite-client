import hashlib
from pathlib import Path
import tempfile
import unittest
from module_inputs import collect


class ModuleInputsTests(unittest.TestCase):
    def test_nested_and_alternate_manifests_survive_without_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'tools'
            for name in ['fp/go.mod', 'fp/go.sum', 'fp/hysteria.mod', 'fp/hysteria.sum',
                         'vendorcap/dest/go.mod', 'vendorcap/dest/main.go']:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            collect(source, root / 'output')
            names = sorted(str(path.relative_to(root / 'output')) for path in (root / 'output').rglob('*') if path.is_file())
            self.assertEqual(names, ['fp/go.mod', 'fp/go.sum', 'fp/hysteria.mod', 'fp/hysteria.sum', 'vendorcap/dest/go.mod'])

    def test_source_edits_do_not_change_module_inputs_but_pin_edits_do(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'tools/example'
            source.mkdir(parents=True)
            (source / 'go.mod').write_text('module example\ngo 1.26\n')
            def digest(output):
                collect(root / 'tools', output)
                return hashlib.sha256((output / 'example/go.mod').read_bytes()).hexdigest()
            first = digest(root / 'first')
            (source / 'main.go').write_text('package main\n')
            self.assertEqual(digest(root / 'second'), first)
            (source / 'go.mod').write_text('module example\ngo 1.27\n')
            self.assertNotEqual(digest(root / 'third'), first)

    def test_manifest_links_and_existing_output_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'tools'
            source.mkdir()
            target = root / 'external.mod'
            target.write_text('external')
            (source / 'go.mod').symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'Regular module'):
                collect(source, root / 'linked')
            with self.assertRaisesRegex(ValueError, 'fresh'):
                collect(source, root / 'linked')


if __name__ == '__main__':
    unittest.main()
