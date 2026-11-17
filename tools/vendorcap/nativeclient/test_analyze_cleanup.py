import unittest

from analyze_cleanup import cleanup_timeline
from analyze_network import EvidenceError


def fixture(position=1, consumer_before_done=False):
    rows = []
    for cc in range(1, 6):
        events = [('headers_send', 1), ('cleanup_enter', 1), ('reset_send', 1),
                  ('reset_complete', 1), ('cleanup_postwrite', 1), ('forget', 1),
                  ('done', 1), ('headers_send', 3)]
        if consumer_before_done:
            events[-2:] = [events[-1], events[-2]]
        events.insert(position, ('data', 1))
        for kind, stream in events:
            rows.append(dict(cc=f'0x{cc:x}', index=len(rows), stream=stream,
                             kind=kind, value=0, extra=0))
    return rows


def captures():
    return [dict(frames=['[4] RST_STREAM stream=1 CANCEL']) for _ in range(5)]


class CleanupTraceTest(unittest.TestCase):
    def test_clean_completion_and_fragmented_data_need_no_reset(self):
        rows = []
        for cc in range(1, 6):
            for kind, stream in [('headers_send', 1), ('data', 1), ('data', 1),
                                 ('cleanup_enter', 1), ('cleanup_postwrite', 1),
                                 ('forget', 1), ('done', 1), ('headers_send', 3)]:
                rows.append(dict(cc=f'0x{cc:x}', index=len(rows), stream=stream,
                                 kind=kind, value=0, extra=0))
        result = cleanup_timeline(rows, [dict(frames=[]) for _ in range(5)], 'test')
        self.assertEqual(result['first_data_positions'], {'no_reset_data_before_forget': 5})

    def test_first_data_is_not_replaced_by_a_later_fragment(self):
        original = fixture(4)
        rows = []
        for cc in range(1, 6):
            group = [r for r in original if r['cc'] == f'0x{cc:x}']
            group.append(dict(cc=f'0x{cc:x}', kind='data', stream=1, value=0, extra=0))
            for row in group:
                rows.append({**row, 'index': len(rows)})
        result = cleanup_timeline(rows, captures(), 'test')
        self.assertEqual(result['first_data_positions'], {'after_reset_complete_before_forget': 5})

    def test_distinguishes_continuation_windows(self):
        for position, expected in [(1, 'before_cleanup_entry'),
                                   (2, 'after_entry_before_reset_send'),
                                   (3, 'during_reset_write'),
                                   (4, 'after_reset_complete_before_forget'),
                                   (6, 'after_forget')]:
            with self.subTest(position=position):
                result = cleanup_timeline(fixture(position), captures(), 'test')
                self.assertEqual(result['first_data_positions'], {expected: 5})

    def test_done_trace_is_not_a_consumer_barrier(self):
        result = cleanup_timeline(fixture(6, consumer_before_done=True), captures(), 'test')
        self.assertEqual(result['first_data_positions'], {'after_forget': 5})

    def test_removed_stream_data_can_precede_or_follow_redirect(self):
        for position, consumer_first, expected in [
                (6, False, 'before_redirect_headers'),
                (8, False, 'after_redirect_headers'),
                (7, True, 'after_redirect_headers')]:
            with self.subTest(position=position, consumer_first=consumer_first):
                result = cleanup_timeline(fixture(position, consumer_first), captures(), 'test')
                self.assertEqual(result['first_data_positions'], {'after_forget': 5})
                self.assertEqual(result['first_data_vs_redirect'], {expected: 5})
                self.assertTrue(all(row['first_data_vs_redirect'] == expected
                                    for row in result['connections']))

    def test_missing_failed_or_reordered_transitions_are_rejected(self):
        rows = fixture()
        mutants = [[r for r in rows if r['kind'] != 'forget'],
                   [r for r in rows if r['kind'] != 'reset_complete'],
                   [{**r, 'value': 1} if r['kind'] == 'reset_complete' else r for r in rows],
                   [{**r, 'index': -1} if r['kind'] == 'cleanup_postwrite' else r for r in rows],
                   [{**r, 'index': -1} if r['kind'] == 'headers_send' and r['stream'] == 3 else r for r in rows]]
        for changed in mutants:
            with self.subTest(changed=changed):
                with self.assertRaises(EvidenceError):
                    cleanup_timeline(changed, captures(), 'test')
        with self.assertRaisesRegex(EvidenceError, 'reset counts differ'):
            cleanup_timeline(rows, [dict(frames=[]) for _ in range(5)], 'test')


if __name__ == '__main__':
    unittest.main()
