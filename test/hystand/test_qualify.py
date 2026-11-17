import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

import qualify


class Ownership(unittest.TestCase):
    def test_optimized_python_cannot_disable_qualification(self):
        result=subprocess.run([sys.executable, '-O', str(Path(qualify.__file__)), '--help'],
                              capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('qualification requires assertions enabled',result.stderr)

    def test_listener_must_belong_to_the_live_process_in_either_address_family(self):
        for family in ('AF_INET', 'AF_INET6'):
            with self.subTest(family=family):
                source = ('import socket,sys; s=socket.socket(socket.' + family + '); '
                          's.bind(("' + ('127.0.0.1' if family == 'AF_INET' else '::1') + '",0)); '
                          's.listen(); print(s.getsockname()[1],flush=True); sys.stdin.read()')
                child = subprocess.Popen([sys.executable, '-c', source], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, text=True)
                try:
                    port = int(child.stdout.readline())
                    self.assertTrue(qualify.owns_listener(child, port, 'tcp'))
                    self.assertFalse(qualify.owns_listener(child, port, 'udp'))
                    foreign = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'], stdin=subprocess.PIPE)
                    try:
                        self.assertFalse(qualify.owns_listener(foreign, port, 'tcp'))
                    finally:
                        foreign.communicate(timeout=5)
                finally:
                    child.communicate(timeout=5)
                self.assertFalse(qualify.owns_listener(child, port, 'tcp'))

    def test_failed_evidence_cannot_be_replayed_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'result.json').write_text(json.dumps({'schema': 'hysteria-local-qualification-v1',
                'completed': False, 'errors': ['fixture failure']}))
            with self.assertRaises(AssertionError):
                qualify.analyze(root)


if __name__ == '__main__':
    unittest.main()
