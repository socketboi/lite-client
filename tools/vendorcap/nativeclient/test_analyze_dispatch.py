import unittest

from analyze_dispatch import dispatch_timeline
from analyze_network import EvidenceError


def fixture(position=3, error=0, reset=True):
    rows = []
    for cc in range(1, 6):
        kinds = ['headers_send', 'cleanup_enter', 'reset_send', 'reset_take',
                 'reset_socket', 'reset_complete', 'cleanup_postwrite', 'forget', 'done']
        if not reset:
            kinds = [kind for kind in kinds if not kind.startswith('reset_')]
        kinds.insert(position, 'data')
        for kind in kinds:
            value, extra = (3, 13) if kind == 'reset_take' else (
                (0 if error else 35), error) if kind == 'reset_socket' else (0, 0)
            rows.append(dict(index=len(rows), cc=f'0x{cc:x}', kind=kind,
                             stream=1, value=value, extra=extra))
    return rows


class DispatchTraceTest(unittest.TestCase):
    def test_distinguishes_owner_and_socket_boundaries(self):
        for position, expected in [(1, 'before_reset_send'),
                                   (3, 'queued_before_tls_take'),
                                   (4, 'after_take_before_socket_result'),
                                   (5, 'after_socket_result_before_completion'),
                                   (6, 'after_completion')]:
            with self.subTest(position=position):
                result = dispatch_timeline(fixture(position), 'test')
                self.assertEqual(result['first_data_positions'], {expected: 5})
                self.assertEqual(result['socket_errno'], {'0': 5})

    def test_eagain_eintr_and_no_reset_are_explicit(self):
        for error in (4, 11):
            result = dispatch_timeline(fixture(error=error), 'test')
            self.assertEqual(result['socket_errno'], {str(error): 5})
        result = dispatch_timeline(fixture(position=1, reset=False), 'test')
        self.assertEqual(result['first_data_positions'], {'no_reset': 5})
        self.assertEqual(result['socket_errno'], {})

    def test_incomplete_or_invalid_dispatch_is_rejected(self):
        rows = fixture()
        mutants = [
            [r for r in rows if r['kind'] != 'reset_take'],
            rows + [r.copy() for r in rows if r['kind'] == 'reset_take'],
            [r for r in rows if r['kind'] != 'reset_socket'],
            [{**r, 'index': -1} if r['kind'] == 'reset_take' else r for r in rows],
            [{**r, 'index': -1} if r['kind'] == 'reset_socket' else r for r in rows],
            [{**r, 'value': 0} if r['kind'] == 'reset_take' else r for r in rows],
            [{**r, 'extra': 1} if r['kind'] == 'reset_take' else r for r in rows],
            [{**r, 'value': 0} if r['kind'] == 'reset_socket' else r for r in rows],
            [{**r, 'extra': 111} if r['kind'] == 'reset_socket' else r for r in rows],
        ]
        for changed in mutants:
            with self.subTest(changed=changed):
                with self.assertRaises(EvidenceError):
                    dispatch_timeline(changed, 'test')


if __name__ == '__main__':
    unittest.main()
