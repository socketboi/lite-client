import unittest

from analyze_network import EvidenceError
from analyze_refunds import classify, parse_trace


def fixture(kind='close_refund', credit=5000):
    lines = []
    for cc in range(1, 6):
        for name, value in [('close_unread', credit if kind == 'close_refund' else 0), (kind, credit)]:
            lines.append(f'TRACE {len(lines)} 1793193000000000000 0x{cc:x} 1 {name} {value} {credit}')
    return f'TRACE_BEGIN {len(lines)}\n' + '\n'.join(lines) + f'\nTRACE_END {len(lines)}\n'


def captures(credit=5000):
    return [dict(frames=['[4] WINDOW_UPDATE stream=0 +1073741824',
                         f'[4] WINDOW_UPDATE stream=0 +{credit}']) for _ in range(5)]


class RefundTraceTest(unittest.TestCase):
    def test_do_handoff_events_preserve_credit_accounting(self):
        names = ('do_notify', 'do_ready', 'do_step', 'request_queue')
        for name in names:
            original = fixture()
            changed = original.replace('TRACE_BEGIN 10', 'TRACE_BEGIN 11').replace(
                'TRACE_END 10', f'TRACE 10 1793193000000000001 0x1 3 {name} 0 0\nTRACE_END 11')
            rows = parse_trace(changed, 'test')
            self.assertEqual(rows[-1]['kind'], name)
            self.assertEqual(classify(rows, captures(), 'test')['credit_bytes_by_source'],
                             {'close_refund': 25000})

    def test_distinguishes_accounting_sources(self):
        for kind in ['close_refund', 'late_refund', 'data_refund', 'read_refund']:
            with self.subTest(kind=kind):
                result = classify(parse_trace(fixture(kind), 'test'), captures(), 'test')
                self.assertEqual(result['credit_bytes_by_source'], {kind: 25000})
                self.assertEqual(result['unread_at_redirect_close'], {5000 if kind == 'close_refund' else 0: 5})

    def test_incomplete_or_invalid_trace_is_rejected(self):
        original = fixture()
        mutants = [original.replace('TRACE_END 10', 'TRACE_END 9'),
                   original + 'TRACE_END 10\n', original.replace('TRACE 0 ', 'TRACE 2 ', 1),
                   original.replace('TRACE 0 ', 'TRACE missing ', 1),
                   original.replace('close_unread', 'unknown_event', 1),
                   original.replace('0x1', '0x0'), original.replace(' 1 close_unread', ' 2 close_unread'),
                   original.replace('TRACE_BEGIN 10', 'TRACE_BEGIN 2049')]
        for mutant in mutants:
            with self.subTest(mutant=mutant):
                with self.assertRaises(EvidenceError):
                    parse_trace(mutant, 'test')

    def test_missing_close_and_wire_disagreement_are_rejected(self):
        rows = parse_trace(fixture(), 'test')
        for changed in [rows[1:], rows[:-2],
                        [{**r, 'value': 4999} if r['kind'] == 'close_refund' else r for r in rows],
                        [{**r, 'value': 10000 if r['cc'] == '0x1' else 0} if r['kind'] == 'close_refund'
                         and r['cc'] in ('0x1', '0x2') else r for r in rows]]:
            with self.subTest(changed=changed):
                with self.assertRaises(EvidenceError):
                    classify(changed, captures(), 'test')


if __name__ == '__main__':
    unittest.main()
