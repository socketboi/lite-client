#!/usr/bin/env python3
"""Summarize diagnostic SPIDER_PROFILE samples, never G2 acceptance."""

import argparse
import json
from pathlib import Path
import re
from statistics import median

FIELDS = ('fd', 'base', 'logged', 'allocated', 'transferred', 'handoff',
          'fetch', 'create', 'created', 'entry', 'request_entry', 'wake',
          'opening', 'request')
INTERVALS = {
    'refusal_logging': (None, 'logged'),
    'session_allocation': ('logged', 'allocated'),
    'state_transfer': ('allocated', 'transferred'),
    'loop_registration': ('transferred', 'handoff'),
    'fetch_creation': ('handoff', 'fetch'),
    'worker_creation_calls': ('create', 'created'),
    'do_entry_after_create': ('create', 'entry'),
    'request_entry_after_create': ('create', 'request_entry'),
    'handoff_to_first_headers': ('handoff', 'request'),
    'total_to_first_headers': (None, 'request'),
}


def parse(text):
    rows = []
    for line in text.splitlines():
        if not line.startswith('SPIDER_PROFILE'):
            continue
        parts = line.split()
        if parts[0] != 'SPIDER_PROFILE' or len(parts) != len(FIELDS) + 1:
            raise ValueError('Incomplete startup profile')
        row = {}
        for key, part in zip(FIELDS, parts[1:]):
            match = re.fullmatch(re.escape(key) + r'=([0-9]+)', part)
            if match is None:
                raise ValueError('Malformed startup profile field: ' + key)
            row[key] = int(match[1])
        ordered = ('logged', 'allocated', 'transferred', 'handoff', 'fetch',
                   'create', 'created', 'request')
        if row['base'] == 0 or any(row[a] > row[b] for a, b in zip(ordered, ordered[1:])):
            raise ValueError('Invalid startup chronology')
        if not all(row['create'] <= row[k] <= row['request'] for k in ('entry', 'request_entry')):
            raise ValueError('Invalid worker entry time')
        if not row['handoff'] <= row['opening'] <= row['request'] or row['wake'] > row['request']:
            raise ValueError('Invalid opening or wake time')
        rows.append(row)
    if len({r['base'] for r in rows}) != len(rows):
        raise ValueError('Duplicate startup sample')
    return rows


def summarize(rows, expected_count):
    if expected_count < 1 or len(rows) != expected_count:
        raise ValueError('Unexpected startup sample count')
    stats = {}
    for name, (begin, end) in INTERVALS.items():
        values = [(r[end] - (r[begin] if begin else 0)) / 1000 for r in rows]
        stats[name] = dict(min_us=min(values), median_us=median(values), max_us=max(values))
    return dict(samples=len(rows), intervals=stats, G2Closed=False,
                limitation='Instrumented diagnostic timings are not ordinary-client acceptance.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-count', type=int, required=True)
    parser.add_argument('logs', nargs='+', type=Path)
    args = parser.parse_args()
    rows = parse('\n'.join(p.read_text() for p in args.logs))
    print(json.dumps(summarize(rows, args.expected_count), indent=2))
