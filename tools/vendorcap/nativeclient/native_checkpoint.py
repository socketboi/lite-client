"""Freeze and serve a native v4 checkpoint; export evidence only after cleanup."""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import shutil
import sys
import time

from analyze_network import require
from analyze_native_checkpoint import validate_inputs
from checkpoint_process import Processes, digest, termination_guard
from native_checkpoint_plan import (make_plan, NATIVE_INPUTS, DEVICE_INPUTS,
                                    phase_table, device_settings)


def write(root, name, data):
    (root/name).write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')


def freeze(root):
    require(not (root/'plan.json').exists(), 'native plan already exists')
    plan = make_plan()
    config = json.loads((root/'settings.json').read_text())
    identity = json.loads((root/'device.json').read_text())
    client = json.loads((root/'client.json').read_text())
    require(len(config['control_token']) == 64 and all(c in '0123456789abcdef'
            for c in config['control_token']), 'expected a fresh 256-bit test control token')
    for name in NATIVE_INPUTS:
        if name.endswith('.py') or name == 'native-device.sh':
            source = Path(__file__).with_name(name)
            if source.resolve() != (root/name).resolve():
                shutil.copyfile(source, root/name)
    (root/'settings.sh').write_text(device_settings(config, identity, client))
    (root/'phases.tsv').write_text(phase_table(plan))
    for name in ('lc-tunnel.native', 'reference.native'):
        data = (root/name).read_bytes()[:20]
        machine = int.from_bytes(data[18:20], 'little')
        require(data[:4] == b'\x7fELF' and data[5] == 1 and
                ((identity['architecture'] == 'mipsel' and data[4] == 1 and machine == 8) or
                 (identity['architecture'] == 'aarch64' and data[4] == 2 and machine == 183)),
                'native executable architecture differs from device')
    plan['inputs'] = {name: digest(root/name) for name in sorted(NATIVE_INPUTS)}
    with (root/'plan.json').open('x', encoding='utf-8') as output:
        output.write(json.dumps(plan, indent=2)+'\n')
    validate_inputs(root, plan)
    stage = root/'device-stage'
    stage.mkdir()
    for name in DEVICE_INPUTS:
        shutil.copyfile(root/name, stage/name)
    (stage/'device.sha256').write_text(''.join(plan['inputs'][name]+'  '+name+'\n'
                                            for name in sorted(DEVICE_INPUTS)))
    (stage/'plan.sha256').write_text(digest(root/'plan.json')+'\n')
    return plan


def serve(root):
    with termination_guard():
        return serve_guarded(root)


def serve_guarded(root):
    require(not (root/'progress.jsonl').exists() and not (root/'stand-state.json').exists(),
            'native stand evidence already exists')
    plan = json.loads((root/'plan.json').read_text())
    validate_inputs(root, plan)
    require(digest(__file__) == plan['inputs']['native_checkpoint.py'],
            'runner differs from frozen native driver')
    for module in ('analyze_native_checkpoint', 'native_checkpoint_plan',
                   'analyze_checkpoint', 'analyze_network', 'checkpoint_process'):
        require(digest(sys.modules[module].__file__) == plan['inputs'][module+'.py'],
                'executed helper differs from frozen input: '+module)
    config = json.loads((root/'settings.json').read_text())
    plan_hash = digest(root/'plan.json')
    processes = Processes(root)
    state = dict(completed=0, pending=None, finished=False, aborted=False)
    started = time.monotonic()
    server = dest = None
    listener = None
    receipt = dict(server_sha256=plan['inputs']['reference.host'],
        dest_sha256=plan['inputs']['dest.host'], phases_completed=0,
        alive_after_phases=False, server_exit=None, dest_exit=None, cleanup_exit=1)

    class Control(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            if not hmac.compare_digest(self.headers.get('Authorization', ''),
                                       'Bearer '+config['control_token']):
                self.send_error(403)
                return
            try:
                require(int(self.headers.get('Content-Length', '0')) == 0, 'unexpected control body')
                processes.alive(server, dest)
                require(digest(root/'plan.json') == plan_hash, 'native plan changed')
                if self.path == '/ready':
                    pass
                elif self.path == '/abort':
                    state['aborted'] = True
                    state['finished'] = True
                elif self.path == '/finish':
                    require(state['completed'] == 24 and state['pending'] is None, 'incomplete native run')
                    state['finished'] = True
                else:
                    parts = self.path.strip('/').split('/')
                    require(len(parts) == 3 and parts[0] == 'phase' and parts[1].isdecimal(),
                            'invalid phase request')
                    phase_id = int(parts[1])
                    require(phase_id == state['completed'] and phase_id < 24, 'phase out of order')
                    phase = plan['phases'][phase_id]
                    if parts[2] == 'start':
                        require(state['pending'] is None, 'phase already started')
                        (root/'scenario').write_text(f"{phase['role']} {phase['scenario']} {phase['round']}\n")
                        entry = dict(phase=phase, stage='start')
                        state['pending'] = phase_id
                    else:
                        require(parts[2] == 'complete' and state['pending'] == phase_id,
                                'phase not started')
                        entry = dict(phase=phase, stage='complete', alive=True)
                        state['pending'] = None
                        state['completed'] += 1
                    with (root/'progress.jsonl').open('a') as progress:
                        progress.write(json.dumps(entry)+'\n')
                    print('NATIVE_PHASE', phase_id, parts[2], flush=True)
                self.send_response(200)
                self.send_header('Content-Length', '6')
                self.end_headers()
                self.wfile.write(b'READY\n')
            except (ValueError, OSError, KeyError) as error:
                (root/'control-error.log').write_text(str(error)+'\n')
                self.send_error(409)

    try:
        (root/'scenario').write_text('warm none\n')
        dest = processes.start(['./dest.host', 'leaf.pem', 'leaf.key', 'scenario'],
                               'dest.log', 18444, plan['inputs']['dest.host'])
        server = processes.start(['./reference.host', 'run', '-c', 'server.json'],
                                 'server.log', 14480, plan['inputs']['reference.host'])
        class BoundedServer(HTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(2)
                return connection, address

        listener = BoundedServer((config['control_listen'], config['control_port']), Control)
        listener.timeout = 1
        print('NATIVE_STAND_READY', flush=True)
        while not state['finished']:
            require(time.monotonic()-started < 1200, 'native stand deadline exceeded')
            processes.alive(server, dest)
            listener.handle_request()
        require(not state['aborted'] and state['completed'] == 24, 'native device aborted the run')
        receipt['alive_after_phases'] = True
        receipt['server_exit'] = processes.stop(server)
        receipt['dest_exit'] = processes.stop(dest)
        require(receipt['server_exit'] == 0 and receipt['dest_exit'] == -15, 'native stand stop failed')
    finally:
        if listener is not None:
            listener.server_close()
        receipt['phases_completed'] = state['completed']
        receipt['cleanup_exit'] = processes.close()
        write(root, 'stand-state.json', receipt)
    require(receipt['cleanup_exit'] == 0, 'native stand cleanup failed')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('freeze', 'serve'))
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps((freeze if args.operation == 'freeze' else serve)(args.directory.resolve()), indent=2))
