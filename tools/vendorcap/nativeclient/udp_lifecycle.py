"""Compare real Xray/LC UDP recovery in an isolated Linux loopback namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time

import checkpoint_process
import analyze_network
from checkpoint_process import Processes, digest, termination_guard

ROLES = ('ref', 'lc1', 'lc4')
FAULTS = ('none', 'fin', 'reset')
INPUTS = frozenset({'lc-tunnel', 'xray', 'fingerprint.fpt', 'driver.py', 'checkpoint_process.py',
                    'analyze_network.py', 'prepare.log', 'key.pem', 'cert.pem', 'server.json', 'client.json'})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wait_udp(processes, child, port, expected):
    until = time.monotonic() + 10
    while time.monotonic() < until:
        processes.alive(child)
        inodes = set()
        for name in ('udp', 'udp6'):
            for line in Path('/proc/net', name).read_text().splitlines()[1:]:
                fields = line.split()
                if int(fields[1].split(':')[1], 16) == port:
                    inodes.add('socket:['+fields[9]+']')
        owned = set()
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal(): continue
            try:
                if os.getpgid(int(entry.name)) == child.pid:
                    owned.update(os.readlink(fd) for fd in (entry/'fd').iterdir())
            except (FileNotFoundError,ProcessLookupError): pass
        if len(owned & inodes) == expected:
            return
        time.sleep(.02)
    raise ValueError('owned UDP listener did not become ready')


def packets(path):
    """Read this driver's complete Ethernet/IPv4 PCAP; retain wire timestamps."""
    with path.open('rb') as source:
        require(source.read(24) == struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1),
                'unsupported capture header')
        while header := source.read(16):
            require(len(header) == 16, 'truncated packet header')
            seconds, micros, size, original = struct.unpack('<IIII', header)
            require(0 < size == original <= 65535 and micros < 1000000, 'truncated packet')
            data = source.read(size)
            require(len(data) == size, 'missing packet bytes')
            if len(data) < 34 or data[12:14] != b'\x08\x00':
                continue
            offset = 14 + (data[14] & 15) * 4
            require(data[14] >> 4 == 4 and offset >= 34, 'invalid IPv4 header')
            end = 14 + int.from_bytes(data[16:18], 'big')
            require(offset <= end <= len(data), 'invalid IPv4 length')
            require(int.from_bytes(data[20:22], 'big') & 0x3fff == 0, 'fragmented fixture packet')
            protocol = data[23]
            if protocol not in (6, 17):
                continue
            need = 20 if protocol == 6 else 8
            require(end >= offset + need, 'short transport header')
            sport, dport = struct.unpack('!HH', data[offset:offset + 4])
            row = dict(time_ns=seconds * 1000000000 + micros * 1000,
                       protocol=protocol, source=socket.inet_ntoa(data[26:30]),
                       destination=socket.inet_ntoa(data[30:34]), sport=sport, dport=dport)
            if protocol == 17:
                length = int.from_bytes(data[offset + 4:offset + 6], 'big')
                require(8 <= length == end - offset, 'invalid UDP length')
                row['sha256'] = hashlib.sha256(data[offset + 8:end]).hexdigest()
                payload = data[offset + 8:end]
                if len(payload) == 46 and payload[:6] == b'LCUDP1':
                    row['sequence'] = int.from_bytes(payload[6:14], 'big')
            else:
                require(20 <= (data[offset + 12] >> 4) * 4 <= end - offset, 'invalid TCP length')
                row['flags'] = data[offset + 13]
            yield row


def analyze(root):
    plan = json.loads((root / 'plan.json').read_text())
    result = json.loads((root / 'result.json').read_text())
    require(plan['schema'] == 'udp-lifecycle-v1' and 1 <= plan['rounds'] <= 10, 'unsupported plan')
    require(plan['healthy_reply_seconds'] == 5 and plan['quiet_recovery_seconds'] == 3,
            'changed recovery guards')
    require(result['plan_sha256'] == digest(root/'plan.json'), 'frozen plan changed')
    require(set(plan['inputs']) == INPUTS, 'incomplete input manifest')
    require(all(digest(root / name) == value for name, value in plan['inputs'].items()), 'input changed')
    require(result['completed'] and result['cleanup_exit'] == 0 and not result['capture_errors'] and
            result['capture']['dropped'] == 0 and result['capture']['packets'] > 0, 'run/capture failed')
    require(result['server_exit'] == 0 and result['server_sha256'] == plan['inputs']['xray'] and
            result['alive_after_cases'], 'server receipt failed')
    expected = {(n, fault, role) for n in range(1, plan['rounds'] + 1) for fault in FAULTS for role in ROLES}
    cases = result['cases']
    require(len(cases) == len(expected) and
            {(c['round'], c['fault'], c['role']) for c in cases} == expected, 'incomplete case coverage')
    wire = list(packets(root / 'wire.pcap'))
    require(all(p['source'] == p['destination'] == '127.0.0.1' for p in wire), 'non-loopback traffic')
    udp = {}
    for packet in wire:
        if packet['protocol'] == 17:
            udp.setdefault(packet['sha256'], set()).add((packet['sport'], packet['dport'],packet.get('sequence')))
    sequences, hashes, outcomes = set(), set(), []
    for case in cases:
        require(case['client_exit'] == (0 if case['role'] == 'ref' else -15), 'client stop failed')
        require(case['alive_after_requests'] and case['binary_sha256'] ==
                plan['inputs']['xray' if case['role'] == 'ref' else 'lc-tunnel'], 'client identity failed')
        if case['role'] == 'lc4':
            log = (root / f"{case['round']}-{case['fault']}-lc4.log").read_text()
            require({int(n) for n in re.findall(r'worker ([1-4]) of 4, pid [0-9]+', log)} == {1,2,3,4},
                    'four-worker startup not observed')
        if case['fault'] != 'none':
            injected = case['injection']
            require(injected['peer'][0] == '127.0.0.1', 'invalid controlled peer')
            flag = 1 if case['fault'] == 'fin' else 4
            require(any(p['protocol'] == 6 and p['sport'] == 29601 and
                        p['dport'] == injected['peer'][1] and p['flags'] & flag and
                        injected['before_ns'] - 1000000 <= p['time_ns'] <= injected['after_ns'] + 2000000000
                        for p in wire), 'injected close not observed on wire')
        rows = case['requests']
        require([r['stage'] for r in rows] == ['seed', 'after_injection', 'recovered', 'recovered',
                                              'recovered', 'source_rebound', 'fresh_source'], 'missing recovery stage')
        require(len({r['source_port'] for r in rows[:-1]}) == 1 and
                rows[-1]['source_port'] != rows[0]['source_port'], 'invalid source reuse')
        require(rows[2]['start_ns'] - rows[1]['end_ns'] >= 2990000000, 'missing quiet recovery interval')
        for row in rows:
            require(row['sequence'] not in sequences and row['sha256'] not in hashes, 'reused nonce')
            sequences.add(row['sequence']); hashes.add(row['sha256'])
            required = row['stage'] != 'after_injection' or case['fault'] == 'none'
            require(row['required'] == required and row['outcome'] in ('echo', 'timeout'), 'invalid outcome')
            require(row['outcome'] == 'echo' or not required, 'ordinary/recovered UDP failed')
            require(0 < row['end_ns'] - row['start_ns'] < 6000000000, 'reply guard not enforced')
            if row['outcome'] == 'timeout':
                require(row['end_ns'] - row['start_ns'] >= 4990000000, 'premature timeout')
            listener = 19600 if case['role'] == 'ref' else 19601
            directions = udp.get(row['sha256'], set())
            require((row['source_port'], listener, row['sequence']) in directions, 'request missing on wire')
            if row['outcome'] == 'echo':
                require((listener, row['source_port'], row['sequence']) in directions and
                        any(b == 29623 and seq == row['sequence'] for a, b, seq in directions) and
                        any(a == 29623 and seq == row['sequence'] for a, b, seq in directions),
                        'echo lacks end-to-end wire evidence')
        outcomes.append(dict(round=case['round'], fault=case['fault'], role=case['role'],
                             first_after_close=rows[1]['outcome']))
    return dict(validated=True,scope='controlled host UDP lifecycle',cases=len(cases),
                requests=len(sequences),echoes=sum(r['outcome']=='echo' for c in cases for r in c['requests']),
                capture_drops=0,after_close=outcomes,
                limitation='Injected-fault loss is diagnostic; every baseline/recovery/rebind echo is mandatory.')


class ThreadServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class Capture:
    def __init__(self, root):
        self.errors = []
        self.stop_event = threading.Event()
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.socket.bind(('lo', 0))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        self.socket.settimeout(.1)
        self.thread = threading.Thread(target=self.record, args=(root / 'wire.pcap',))
        self.thread.start()

    def record(self, path):
        try:
            with path.open('wb') as output:
                output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
                while True:
                    try:
                        data = self.socket.recv(65535)
                    except socket.timeout:
                        if self.stop_event.is_set(): break
                        continue
                    stamp = time.time_ns()
                    output.write(struct.pack('<IIII', stamp // 1000000000, stamp % 1000000000 // 1000,
                                             len(data), len(data)))
                    output.write(data)
        except BaseException as error:
            self.errors.append(repr(error))

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=3)
        require(not self.thread.is_alive(), 'capture did not stop')
        packets, dropped = struct.unpack('II', self.socket.getsockopt(263, 6, 8))
        self.socket.close()
        return dict(packets=packets, dropped=dropped)


def prepare(args):
    require(set(p.name for p in Path('/sys/class/net').iterdir()) == {'lo'}, 'use Docker --network none')
    root = args.directory.resolve()
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(root, 0o700)
    for source, name in ((args.lc, 'lc-tunnel'), (args.reference, 'xray'), (args.fingerprint, 'fingerprint.fpt'),
                         (Path(__file__), 'driver.py'), (Path(checkpoint_process.__file__), 'checkpoint_process.py'),
                         (Path(analyze_network.__file__), 'analyze_network.py')):
        shutil.copyfile(source, root / name)
    for name in ('lc-tunnel', 'xray'): (root / name).chmod(0o700)
    version = subprocess.check_output([str(root / 'xray'), 'version'], text=True)
    values = dict(line.split(': ', 1) for line in subprocess.check_output(
        [str(root / 'xray'), 'x25519'], text=True).splitlines() if ': ' in line)
    with (root / 'prepare.log').open('w') as log:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                        '-subj', '/CN=udp.test', '-addext', 'subjectAltName=DNS:udp.test',
                        '-keyout', 'key.pem', '-out', 'cert.pem'], cwd=root, check=True, stdout=log, stderr=log)
    uid = '00000000-0000-4000-8000-000000000001'
    security = dict(serverName='udp.test', fingerprint='firefox', password=values['Password (PublicKey)'], shortId='0123abcd')
    server = dict(log=dict(loglevel='warning'), inbounds=[dict(listen='127.0.0.1', port=29600, protocol='vless',
        settings=dict(clients=[dict(id=uid, flow='xtls-rprx-vision')], decryption='none'), streamSettings=dict(
            network='raw', security='reality', realitySettings=dict(target='127.0.0.1:29622', serverNames=['udp.test'],
                privateKey=values['PrivateKey'], shortIds=['0123abcd'])))], outbounds=[dict(protocol='freedom',
                    settings=dict(finalRules=[dict(action='allow', ip=['127.0.0.0/8'])]))])
    client = dict(log=dict(loglevel='warning'), inbounds=[dict(listen='127.0.0.1', port=p, protocol='dokodemo-door',
        settings=dict(address='127.0.0.1', port=target, network=network)) for p,target,network in
        ((19970,29622,'tcp'),(19600,29623,'udp'))], outbounds=[dict(protocol='vless', settings=dict(vnext=[
            dict(address='127.0.0.1',port=29601,users=[dict(id=uid,flow='xtls-rprx-vision',encryption='none')])]),
            streamSettings=dict(network='raw',security='reality',realitySettings=security))])
    for name,value in (('server.json',server),('client.json',client)):
        (root / name).write_text(json.dumps(value,indent=2)+'\n')
    plan = dict(schema='udp-lifecycle-v1',rounds=args.rounds,healthy_reply_seconds=5,quiet_recovery_seconds=3,
        reference_version=version,inputs={p.name:digest(p) for p in root.iterdir() if p.is_file()})
    (root / 'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    return root, plan, uid, security


def run(args):
    root, plan, uid, security = prepare(args)
    result = dict(completed=False,cleanup_exit=1,cases=[],capture_errors=[],plan_sha256=digest(root/'plan.json'))
    stop = threading.Event()
    active, errors, events = {}, [], []
    lock = threading.Lock()
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            data, connection = self.request
            connection.sendto(data,self.client_address)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2','http/1.1'])
    context.load_cert_chain(root/'cert.pem',root/'key.pem')
    class Donor(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(5)
                with context.wrap_socket(self.request,server_side=True) as connection: connection.recv(1)
            except OSError: pass
    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with socket.create_connection(('127.0.0.1',29600),timeout=5) as upstream:
                    self.request.settimeout(.1); upstream.settimeout(.1)
                    with lock: active[self.client_address]=(self.request,upstream)
                    def copy(source,target):
                        try:
                            while not stop.is_set():
                                try: data=source.recv(65535)
                                except socket.timeout: continue
                                if not data: break
                                target.sendall(data)
                        except OSError: pass
                        finally:
                            try: target.shutdown(socket.SHUT_WR)
                            except OSError: pass
                    reader=threading.Thread(target=copy,args=(upstream,self.request))
                    reader.start()
                    copy(self.request,upstream)
                    reader.join(timeout=6)
                    if reader.is_alive(): errors.append('relay reader did not stop')
            except OSError as error:
                if not stop.is_set(): errors.append(repr(error))
            finally:
                with lock: active.pop(self.client_address,None)
    listeners = [ThreadServer(('127.0.0.1',29622),Donor),
                 socketserver.ThreadingUDPServer(('127.0.0.1',29623),Echo),ThreadServer(('127.0.0.1',29601),Relay)]
    capture = Capture(root)
    for listener in listeners: threading.Thread(target=listener.serve_forever,daemon=True).start()
    processes = Processes(root)
    sequence, known = 0, set()
    def request(sender, port, stage, required):
        nonlocal sequence
        sequence += 1
        payload=b'LCUDP1'+struct.pack('!Q',sequence)+os.urandom(32)
        sha=hashlib.sha256(payload).hexdigest(); known.add(sha)
        began=time.monotonic_ns(); deadline=time.monotonic()+5
        sender.sendto(payload,('127.0.0.1',port))
        outcome='timeout'
        while time.monotonic()<deadline:
            remaining=deadline-time.monotonic()
            if remaining<=0: break
            sender.settimeout(remaining)
            try: received,_=sender.recvfrom(65535)
            except socket.timeout: break
            observed=hashlib.sha256(received).hexdigest()
            require(observed in known,'unknown/corrupt UDP payload')
            if received==payload: outcome='echo'; break
        row=dict(stage=stage,sequence=sequence,source_port=sender.getsockname()[1],sha256=sha,
                 required=required,outcome=outcome,start_ns=began,end_ns=time.monotonic_ns())
        events.append(row)
        require(not required or outcome=='echo','mandatory UDP reply failed: '+str(row))
        return row
    began=time.monotonic()
    try:
        with termination_guard():
            server=processes.start(['./xray','run','-c','server.json'],'server.log',29600,plan['inputs']['xray'])
            for n in range(1,args.rounds+1):
                for fault in FAULTS:
                    roles=ROLES if (n+FAULTS.index(fault))%2 else tuple(reversed(ROLES))
                    for role in roles:
                        require(time.monotonic()-began < args.rounds*150,'experiment deadline')
                        case=dict(round=n,role=role,fault=fault,requests=[])
                        port=19970 if role=='ref' else 19971
                        udp_port=19600 if role=='ref' else 19601
                        command=['./xray','run','-c','client.json'] if role=='ref' else [
                            './lc-tunnel','fingerprint.fpt','127.0.0.1','29601','udp.test',security['password'],
                            security['shortId'],uid,str(port),'-t','127.0.0.1:29622','-u',f'{udp_port}@127.0.0.1:29623',
                            '-f','xtls-rprx-vision','-w','4' if role=='lc4' else '1']
                        child=processes.start(command,f'{n}-{fault}-{role}.log',port,
                                              plan['inputs']['xray' if role=='ref' else 'lc-tunnel'])
                        wait_udp(processes,child,udp_port,4 if role=='lc4' else 1)
                        def send(sender,stage,required=True):
                            case['requests'].append(request(sender,udp_port,stage,required))
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
                            sender.bind(('127.0.0.1',0))
                            send(sender,'seed'); source_port=sender.getsockname()[1]
                            with lock: targets=list(active.items())
                            require(len(targets)==1,'unexpected controlled transport count')
                            peer,(client,upstream)=targets[0]
                            if fault!='none':
                                injection=dict(peer=peer,before_ns=time.time_ns())
                                if fault=='fin': client.shutdown(socket.SHUT_WR)
                                else:
                                    for connection in (client,upstream):
                                        connection.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
                                        connection.close()
                                injection['after_ns']=time.time_ns(); case['injection']=injection
                            time.sleep(.05)
                            send(sender,'after_injection',fault=='none')
                            time.sleep(3)
                            for _ in range(3): send(sender,'recovered')
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
                            sender.bind(('127.0.0.1',source_port)); send(sender,'source_rebound')
                            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as fresh:
                                fresh.bind(('127.0.0.1',0)); send(fresh,'fresh_source')
                        processes.alive(child,server)
                        case['alive_after_requests']=True
                        case['binary_sha256']=digest(f'/proc/{child.pid}/exe')
                        case['client_exit']=processes.stop(child)
                        for entry in Path('/proc').iterdir():
                            if entry.name.isdecimal():
                                try:
                                    require(os.getpgid(int(entry.name)) != child.pid, 'client process group survived stop')
                                except ProcessLookupError: pass
                        result['cases'].append(case)
                        print('UDP_CASE',n,fault,role,case['requests'][1]['outcome'],flush=True)
                        until=time.monotonic()+6
                        while active and time.monotonic()<until: time.sleep(.02)
                        require(not active and not errors,'relay cleanup failed: '+str(errors))
            processes.alive(server)
            result['alive_after_cases']=True
            result['server_sha256']=digest(f'/proc/{server.pid}/exe')
            result['server_exit']=processes.stop(server)
            require(result['server_exit']==0,'server stop failed')
            result['completed']=True
    finally:
        result['cleanup_exit']=processes.close()
        stop.set()
        for listener in listeners: listener.shutdown(); listener.server_close()
        result['capture']=capture.close()
        result['capture_errors']=capture.errors+errors
        result['events']=events
        (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    analysis=analyze(root)
    (root/'analysis.json').write_text(json.dumps(analysis,indent=2)+'\n')
    return analysis


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--analyze',action='store_true')
    parser.add_argument('--lc',type=Path)
    parser.add_argument('--reference',type=Path)
    parser.add_argument('--fingerprint',type=Path)
    parser.add_argument('--rounds',type=int,default=3,choices=range(1,11))
    args=parser.parse_args()
    if not args.analyze:
        require(all((args.lc,args.reference,args.fingerprint)),'binary and fingerprint inputs required')
    print(json.dumps(analyze(args.directory) if args.analyze else run(args),indent=2))
