"""Attribute instrumented HTTP/2 credits; never infer performance or acceptance."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import tarfile

from analyze_network import analyze, parse_records, require


CREDIT_KINDS = {'data_refund', 'late_refund', 'read_refund', 'close_refund'}
KINDS = CREDIT_KINDS | {'data', 'close_unread', 'cleanup_enter', 'reset_send',
                        'reset_complete', 'reset_take', 'reset_socket',
                        'cleanup_postwrite', 'forget', 'done', 'headers_send',
                        'do_notify', 'do_ready', 'do_step', 'request_queue'}


def parse_trace(text, context):
    begins = re.findall(r'^TRACE_BEGIN ([0-9]+)$', text, re.M)
    ends = re.findall(r'^TRACE_END ([0-9]+)$', text, re.M)
    require(len(begins) == 1 and begins == ends and 0 < int(begins[0]) <= 2048,
            context + ': missing, repeated or overflowing trace dump')
    rows = []
    for line in text.splitlines():
        if not line.startswith('TRACE '):
            continue
        match = re.fullmatch(r'TRACE ([0-9]+) ([0-9]+) (0x[0-9a-f]+) ([0-9]+) (\w+) ([0-9]+) ([0-9]+)', line)
        require(match is not None, context + ': malformed trace event')
        index, stamp, cc, stream, kind, value, extra = match.groups()
        require(int(stamp) > 0 and int(cc, 16) > 0 and int(stream) in (1, 3) and kind in KINDS,
                context + ': unexpected trace event')
        rows.append(dict(index=int(index), stamp=int(stamp), cc=cc, stream=int(stream),
                         kind=kind, value=int(value), extra=int(extra)))
    require([r['index'] for r in rows] == list(range(int(begins[0]))),
            context + ': incomplete or reordered trace dump')
    return rows


def classify(rows, captures, context):
    groups = defaultdict(list)
    for row in rows:
        groups[row['cc']].append(row)
    require(len(groups) == len(captures) == 5, context + ': trace connection coverage')
    wire_credits = []
    for capture in captures:
        values = [int(m[1]) for frame in capture['frames']
                  if (m := re.search(r'WINDOW_UPDATE stream=0 \+([0-9]+)$', frame))]
        require(values and values[0] == 1073741824, context + ': missing opening credit')
        wire_credits.append(tuple(values[1:]))
    traced_credits, unread, credits, sources = [], Counter(), Counter(), Counter()
    for events in groups.values():
        closes = [r for r in events if r['kind'] == 'close_unread' and r['stream'] == 1]
        require(len(closes) == 1, context + ': missing or repeated redirect Close observation')
        unread[closes[0]['value']] += 1
        positive = [r for r in events if r['kind'] in CREDIT_KINDS and r['value'] > 0]
        # Different producers can race for cc.wmu after accounting their credit.
        # Compare the values per connection, not an invented trace-to-wire order.
        traced_credits.append(tuple(sorted(r['value'] for r in positive)))
        for event in positive:
            credits[event['kind']] += event['value']
            sources[event['kind']] += 1
    require(Counter(traced_credits) == Counter(tuple(sorted(v)) for v in wire_credits),
            context + ': credited values do not match the wire connections')
    return dict(connections=len(groups), unread_at_redirect_close=dict(sorted(unread.items())),
                credit_bytes_by_source=dict(credits), credit_events_by_source=dict(sources))


def analyze_refunds(root):
    baseline = analyze(root)
    records = parse_records((root / 'dest.log').read_text())
    with tarfile.open(root / 'device.tar.gz') as archive:
        files = {m.name.removeprefix('./'): archive.extractfile(m).read()
                 for m in archive.getmembers() if m.isfile()}
    require(files.get('monitor.exit', b'').strip() == b'0', 'trace monitor did not finish successfully')
    phases = []
    for result in baseline['phases']:
        phase = result['phase']
        key = f"{phase['id']}-{phase['condition']}-{phase['role']}-{phase['scenario']}-{phase['sample']}"
        require(key + '.log' in files, key + ': missing client log')
        events = parse_trace(files[key + '.log'].decode(), key)
        captures = [r for r in records if (r['role'], r['scenario'], r['sample']) ==
                    (phase['role'], phase['scenario'], phase['sample'])]
        phases.append(dict(phase=phase, trace_events=len(events), **classify(events, captures, key)))
    return dict(G2Closed=False, phases=phases,
                limitations=['Instrumentation changes execution; do not infer CPU, timing or acceptance.',
                             'Close unread is observed after breaking the pipe, not at function entry.',
                             'Trace connection pointers are local; credit multisets are matched per phase, not by network identity.',
                             'Accounting traces do not establish competing writers acquisition order.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = analyze_refunds(args.directory)
    (args.directory / 'refund-analysis.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
