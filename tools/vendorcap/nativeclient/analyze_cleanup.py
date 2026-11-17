"""Validate instrumented cleanup milestones, without prescribing a scheduler."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import tarfile

from analyze_network import parse_records, require
from analyze_refunds import analyze_refunds, parse_trace


def cleanup_timeline(rows, captures, context):
    groups = defaultdict(list)
    for row in rows:
        groups[row['cc']].append(row)
    require(len(groups) == len(captures) == 5, context + ': cleanup connection coverage')
    timelines, resets = [], []
    for events in groups.values():
        initial = [r for r in events if r['stream'] == 1]

        def one(kind):
            matches = [r for r in initial if r['kind'] == kind]
            require(len(matches) == 1, context + ': missing or repeated ' + kind)
            return matches[0]['index']

        enter, post, forget, done = [one(k) for k in
                                    ('cleanup_enter', 'cleanup_postwrite', 'forget', 'done')]
        require(enter < post < forget < done, context + ': invalid cleanup producer order')
        redirect = [r['index'] for r in events if r['stream'] == 3 and r['kind'] == 'headers_send']
        require(len(redirect) == 1 and forget < redirect[0],
                context + ': redirect precedes stream removal')
        # Go's done marker follows close(donec). Do may run before that marker;
        # unlike forgetStreamID, it cannot bound the redirected HEADERS event.
        sends = [r for r in initial if r['kind'] == 'reset_send']
        completes = [r for r in initial if r['kind'] == 'reset_complete']
        require(len(sends) == len(completes) and len(sends) <= 1,
                context + ': incomplete or repeated reset Write')
        resets.append(len(sends))
        data = [r for r in initial if r['kind'] == 'data']
        require(data and one('headers_send') < data[0]['index'],
                context + ': missing initial DATA or HEADERS')
        first = data[0]['index']
        if sends:
            send, complete = sends[0]['index'], completes[0]['index']
            require(enter < send < complete < post and completes[0]['value'] == 0,
                    context + ': reset did not complete before cleanup continuation')
            if first < enter:
                where = 'before_cleanup_entry'
            elif first < send:
                where = 'after_entry_before_reset_send'
            elif first < complete:
                where = 'during_reset_write'
            elif first < forget:
                where = 'after_reset_complete_before_forget'
            else:
                where = 'after_forget'
        else:
            where = 'no_reset_data_before_forget' if first < forget else 'no_reset_data_after_forget'
        timelines.append(dict(first_data=where,
                              first_data_vs_redirect=('before_redirect_headers' if first < redirect[0]
                                                      else 'after_redirect_headers'),
                              data_has_active_stream=data[0]['extra'] == 0,
                              initial_cleanup=[r['kind'] for r in initial if r['kind'] in
                                               ('cleanup_enter', 'reset_send', 'reset_complete',
                                                'cleanup_postwrite', 'forget', 'done', 'data')]))
    wire_resets = [sum(bool(re.search(r'RST_STREAM stream=1 ', f)) for f in r['frames'])
                   for r in captures]
    require(Counter(resets) == Counter(wire_resets), context + ': reset counts differ from wire')
    return dict(first_data_positions=dict(Counter(r['first_data'] for r in timelines)),
                first_data_vs_redirect=dict(Counter(r['first_data_vs_redirect'] for r in timelines)),
                connections=timelines)


def analyze_cleanup(root):
    refunds = analyze_refunds(root)
    records = parse_records((root / 'dest.log').read_text())
    with tarfile.open(root / 'device.tar.gz') as archive:
        files = {m.name.removeprefix('./'): archive.extractfile(m).read()
                 for m in archive.getmembers() if m.isfile()}
    result = []
    for item in refunds['phases']:
        phase = item['phase']
        key = f"{phase['id']}-{phase['condition']}-{phase['role']}-{phase['scenario']}-{phase['sample']}"
        rows = parse_trace(files[key + '.log'].decode(), key)
        captures = [r for r in records if (r['role'], r['scenario'], r['sample']) ==
                    (phase['role'], phase['scenario'], phase['sample'])]
        result.append(dict(phase=phase, **cleanup_timeline(rows, captures, key)))
    return dict(G2Closed=False, phases=result,
                limitations=refunds['limitations'] +
                ['Reset completion marks local Flush return, not a peer acknowledgment.',
                 'Reset-send precedes Flush and does not identify socket Write entry or prove backpressure.',
                 'Redirect ordering uses the local headers-send marker, not peer receipt.',
                 'A Go consumer can observe donec before the following producer trace marker.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = analyze_cleanup(args.directory)
    (args.directory / 'cleanup-analysis.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
