"""Locate C DATA against TLS-owner reset dispatch; never grant acceptance."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import tarfile

from analyze_cleanup import analyze_cleanup
from analyze_network import require
from analyze_refunds import parse_trace


def dispatch_timeline(rows, context):
    groups = defaultdict(list)
    for row in rows:
        groups[row['cc']].append(row)
    require(len(groups) == 5, context + ': dispatch connection coverage')
    timelines = []
    for events in groups.values():
        initial = [r for r in events if r['stream'] == 1]
        data = [r for r in initial if r['kind'] == 'data']
        require(data, context + ': missing dispatch DATA')
        first = data[0]['index']
        sends, takes, sockets, completes = [[r for r in initial if r['kind'] == kind]
                                            for kind in ('reset_send', 'reset_take',
                                                         'reset_socket', 'reset_complete')]
        require(len(sends) <= 1 and len(sends) == len(takes) == len(completes),
                context + ': missing or repeated reset dispatch')
        if not sends:
            require(not sockets, context + ': socket event without reset')
            timelines.append(dict(first_data='no_reset', socket_results=[]))
            continue
        send, take, complete = sends[0], takes[0], completes[0]
        require(send['index'] < take['index'] < complete['index'] and
                take['value'] > 0 and take['extra'] in (13, 30) and complete['value'] == 0,
                context + ': invalid reset take/completion')
        require(sockets and all(take['index'] < r['index'] < complete['index'] for r in sockets),
                context + ': missing or misplaced socket result')
        require(all((r['value'] > 0 and r['extra'] == 0) or
                    (r['value'] == 0 and r['extra'] in (4, 11)) for r in sockets),
                context + ': invalid socket result')
        if first < send['index']:
            where = 'before_reset_send'
        elif first < take['index']:
            where = 'queued_before_tls_take'
        elif first < sockets[0]['index']:
            where = 'after_take_before_socket_result'
        elif first < complete['index']:
            where = 'after_socket_result_before_completion'
        else:
            where = 'after_completion'
        timelines.append(dict(first_data=where,
                              socket_results=[dict(bytes=r['value'], errno=r['extra'])
                                              for r in sockets]))
    return dict(first_data_positions=dict(Counter(r['first_data'] for r in timelines)),
                socket_errno=dict(Counter(str(s['errno']) for r in timelines
                                          for s in r['socket_results'])),
                connections=timelines)


def analyze_dispatch(root):
    cleanup = analyze_cleanup(root)
    with tarfile.open(root / 'device.tar.gz') as archive:
        files = {m.name.removeprefix('./'): archive.extractfile(m).read()
                 for m in archive.getmembers() if m.isfile()}
    result = []
    for item in cleanup['phases']:
        phase = item['phase']
        if phase['role'] != 'lc':
            continue
        key = f"{phase['id']}-{phase['condition']}-{phase['role']}-{phase['scenario']}-{phase['sample']}"
        rows = parse_trace(files[key + '.log'].decode(), key)
        result.append(dict(phase=phase, **dispatch_timeline(rows, key)))
    return dict(G2Closed=False, phases=result,
                limitations=cleanup['limitations'] +
                ['TLS-owner take does not itself submit ciphertext to the socket.',
                 'Socket markers follow conn_write syscall results; queued q_flush retries are not traced.',
                 'No socket backpressure or timing claim follows from DATA preceding TLS-owner take.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = analyze_dispatch(args.directory)
    (args.directory / 'dispatch-analysis.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
