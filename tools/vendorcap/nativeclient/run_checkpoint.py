"""Run one frozen host v4 checkpoint on container-local storage."""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import sys
import time

from analyze_checkpoint import INPUTS, analyze, make_plan
from analyze_network import require
from checkpoint_process import Processes, digest, termination_guard


def write(root, name, value):
    (root/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')


def run(root):
    with termination_guard():
        return run_guarded(root)


def run_guarded(root):
    root = root.resolve()
    require(not (root/'run-state.json').exists(), 'checkpoint evidence already exists')
    plan = json.loads((root/'plan.json').read_text())
    require(plan == make_plan(plan['inputs']), 'unsupported host runner plan')
    for name in INPUTS:
        require(digest(root/name) == plan['inputs'][name], 'frozen input changed: '+name)
    require(digest(__file__) == plan['inputs']['driver.py'], 'runner differs from frozen driver')
    for module in ('analyze_checkpoint', 'analyze_network', 'checkpoint_process'):
        require(digest(sys.modules[module].__file__) == plan['inputs'][module+'.py'],
                'executed helper differs from frozen input: '+module)
    plan_hash = digest(root/'plan.json')
    config = json.loads((root/'client.json').read_text())
    outbound = config['outbounds'][0]
    settings = outbound['streamSettings']['realitySettings']
    peer = outbound['settings']['vnext'][0]
    require(peer['address'] == '127.0.0.1' and peer['port'] == 14480,
            'host stand must use its isolated loopback endpoint')
    state = dict(exit_code=1, cleanup_exit=1, rounds_completed=0, phases_completed=0)
    processes = Processes(root)
    started = time.monotonic()
    try:
        (root/'scenario').write_text('warm none\n')
        dest = processes.start(['./dest.host', 'leaf.pem', 'leaf.key', 'scenario'],
                               'dest.log', 18444, plan['inputs']['dest.host'])
        server = processes.start(['./reference.host', 'run', '-c', 'server.json'],
                                 'server.log', 14480, plan['inputs']['reference.host'])
        for phase in plan['phases']:
            require(time.monotonic()-started < 900, 'host checkpoint deadline exceeded')
            processes.alive(server, dest)
            key = f"{phase['round']}-{phase['role']}-{phase['scenario']}"
            with (root/'progress.jsonl').open('a') as progress:
                progress.write(json.dumps(dict(phase=phase, stage='start'))+'\n')
            (root/'scenario').write_text(f"{phase['role']} {phase['scenario']} {phase['round']}\n")
            binary = 'lc-tunnel.host' if phase['role'] == 'lc' else 'reference.host'
            port = 19991 if phase['role'] == 'lc' else 19990
            args = (['./lc-tunnel.host', 'fingerprint.fpt', peer['address'], str(peer['port']),
                     settings['serverName'], settings['publicKey'], settings['shortId'],
                     peer['users'][0]['id'], str(port), '-t', '127.0.0.1:18080',
                     '-f', 'xtls-rprx-vision', '-w', '1'] if phase['role'] == 'lc' else
                    ['./reference.host', 'run', '-c', 'client.json'])
            child = processes.start(args, key+'.log', port, plan['inputs'][binary])
            time.sleep(2)
            processes.alive(child, server, dest)
            with (root/(key+'.probe.log')).open('w') as log:
                probe = subprocess.run(['curl', '-sS', '--noproxy', '*', '--connect-timeout', '3',
                                        '--max-time', '30', f'http://127.0.0.1:{port}/'],
                                       stdout=log, stderr=log, timeout=35)
            (root/(key+'.probe-exit')).write_text(str(probe.returncode)+'\n')
            require(probe.returncode in (52, 56), 'wrong-key probe did not fail as expected')
            time.sleep(6)
            processes.alive(child, server, dest)
            status = processes.stop(child)
            require(status == (-signal.SIGTERM if phase['role'] == 'lc' else 0),
                    'client stop result differs')
            write(root, key+'.json', dict(phase=phase, binary_sha256=plan['inputs'][binary],
                  alive_before_probe=True, alive_after_probe=True, probe_exit=probe.returncode,
                  stop_signal=15, client_exit=status))
            with (root/'progress.jsonl').open('a') as progress:
                progress.write(json.dumps(dict(phase=phase, stage='complete', alive=True))+'\n')
            state['phases_completed'] += 1
            state['rounds_completed'] = state['phases_completed']//8
            print('CHECKPOINT_PHASE_COMPLETE', key, flush=True)
        processes.alive(server, dest)
        server_exit, dest_exit = processes.stop(server), processes.stop(dest)
        write(root, 'stand-state.json', dict(server_sha256=plan['inputs']['reference.host'],
              dest_sha256=plan['inputs']['dest.host'], alive_after_phases=True,
              server_exit=server_exit, dest_exit=dest_exit))
        require(server_exit == 0 and dest_exit == -signal.SIGTERM, 'stand stop failed')
        require(digest(root/'plan.json') == plan_hash, 'frozen plan changed during workload')
        state['exit_code'] = 0
    finally:
        state['cleanup_exit'] = processes.close()
        write(root, 'run-state.json', state)
    result = analyze(root)
    write(root, 'analysis.json', result)
    require(result['checkpoint_criteria_met'], 'host checkpoint comparison failed')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.directory), indent=2))
