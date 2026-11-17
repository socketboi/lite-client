"""Keep independent UDP/plain/TLS streams alive across one upstream UDP close."""
import argparse
from collections import Counter
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
import threading
import time

import udp_lifecycle as base
from checkpoint_process import Processes, digest, termination_guard

require = base.require
INPUTS = base.INPUTS | {'udp_lifecycle.py'}
CHANNELS = ('udp', 'plain', 'tls')


def exact(connection, length, deadline=None):
    data = bytearray()
    if deadline is None: deadline = time.monotonic() + 5
    while len(data) < length:
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'stream reply deadline')
        connection.settimeout(remaining)
        part = connection.recv(length - len(data))
        require(part, 'unexpected stream EOF')
        data.extend(part)
    return bytes(data)


def analyze(root):
    plan = json.loads((root/'plan.json').read_text())
    result = json.loads((root/'result.json').read_text())
    require(plan['schema'] == 'flow-isolation-v1' and 1 <= plan['rounds'] <= 10, 'unsupported plan')
    require(plan['healthy_reply_seconds'] == 5 and plan['quiet_recovery_seconds'] == 3, 'changed guards')
    require(set(plan['inputs']) == INPUTS and result['plan_sha256'] == digest(root/'plan.json'), 'manifest failed')
    require(all(digest(root/n) == sha for n,sha in plan['inputs'].items()), 'frozen input changed')
    require(result['completed'] and result['cleanup_exit'] == 0 and not result['errors'] and
            result['capture']['dropped'] == 0 and result['capture']['packets'] > 0, 'run/capture failed')
    require(result['server_exit'] == 0 and result['server_sha256'] == plan['inputs']['xray'], 'server identity failed')
    cases = result['cases']
    expected = {(n,f,r) for n in range(1,plan['rounds']+1) for f in base.FAULTS for r in base.ROLES}
    require(len(cases) == len(expected) and {(c['round'],c['fault'],c['role']) for c in cases} == expected,
            'incomplete case coverage')
    wire = list(base.packets(root/'wire.pcap'))
    require(all(p['source'] == p['destination'] == '127.0.0.1' for p in wire), 'non-loopback traffic')
    udp = {}
    for p in wire:
        if p['protocol'] == 17:
            udp.setdefault(p['sha256'],set()).add((p['sport'],p['dport'],p.get('sequence')))
    journal = {}
    for row in result['journal']:
        journal.setdefault(row['sha256'],[]).append(row)
    seen, sequences, count = set(), set(), Counter()
    for case in cases:
        require(case['alive'] and case['client_exit'] == (0 if case['role']=='ref' else -15) and
                case['binary_sha256'] == plan['inputs']['xray' if case['role']=='ref' else 'lc-tunnel'],
                'client identity/cleanup failed')
        if case['role']=='lc4':
            log=(root/f"{case['round']}-{case['fault']}-lc4.log").read_text()
            require(set(re.findall(r'worker ([1-4]) of 4, pid [0-9]+',log)) == {'1','2','3','4'},
                    'missing worker startup')
        peers=case['peers']
        require(set(peers)=={'victim',*CHANNELS} and len(set(peers.values()))==4, 'streams not independent')
        require(case['neighbors_alive'] and not case['pump_errors'], 'neighbor failed')
        start,end=case['injection_ns'],case['observation_end_ns']
        require(start < end, 'invalid observation window')
        for p in wire:
            if p['protocol']==6 and p['sport']==29601 and p['dport'] in [peers[c] for c in CHANNELS]:
                require(not (start <= p['time_ns'] < end and p['flags'] & 5), 'neighbor transport closed')
        if case['fault']!='none':
            flag=1 if case['fault']=='fin' else 4
            require(any(p['protocol']==6 and p['sport']==29601 and p['dport']==peers['victim'] and
                        start-1000000 <= p['time_ns'] <= case['injection_end_ns']+2000000000 and
                        p['flags'] & flag for p in wire), 'injected close absent')
        victim=case['victim']
        require([r['stage'] for r in victim]==['seed','after','recovered'], 'missing victim stage')
        require(all(r['channel']=='victim' for r in victim), 'invalid victim channel')
        require(victim[2]['start_mono_ns']-victim[1]['end_mono_ns'] >= 2990000000, 'victim not quiet')
        require(len({r['source_port'] for r in victim})==1, 'victim source changed')
        rows=victim+case['background']
        for channel in CHANNELS:
            stream=[r for r in case['background'] if r['channel']==channel]
            require(stream and stream[0]['stage']=='seed' and
                    all(r['stage']=='pump' for r in stream[1:]) and
                    any(r['stage']=='pump' and r['end_ns'] < start for r in stream) and
                    any(r['stage']=='pump' and r['start_ns'] > start for r in stream), 'missing neighbor progress')
            require(len({r['source_port'] for r in stream})==1, 'neighbor socket changed')
            if channel!='udp':
                receipts=[journal.get(r['sha256'],[]) for r in stream]
                require(all(len(v)==1 and v[0]['channel']==channel for v in receipts), 'backend receipt missing')
                require(len({v[0]['connection'] for v in receipts})==1, 'neighbor reconnected')
        for row in rows:
            require(row['channel'] in ('victim',*CHANNELS) and row['start_ns'] < row['end_ns'],
                    'invalid channel/timestamps')
            require(row['sha256'] not in seen and row['sequence'] not in sequences, 'reused nonce')
            seen.add(row['sha256']); sequences.add(row['sequence'])
            optional=row['channel']=='victim' and row['stage']=='after' and case['fault']!='none'
            require(row['outcome']=='echo' or optional and row['outcome']=='timeout', 'mandatory reply failed')
            elapsed=row['end_mono_ns']-row['start_mono_ns']
            require(0 < elapsed < 6000000000 and (row['outcome']!='timeout' or elapsed>=4990000000), 'bad reply deadline')
            if row['channel'] in ('udp','victim'):
                listener=19600 if case['role']=='ref' else 19601
                directions=udp.get(row['sha256'],set()); seq=row['sequence']; port=row['source_port']
                require((port,listener,seq) in directions, 'UDP send absent')
                if row['outcome']=='echo':
                    require((listener,port,seq) in directions and any(b==29623 and s==seq for a,b,s in directions)
                            and any(a==29623 and s==seq for a,b,s in directions), 'UDP echo evidence missing')
                    require(any(v['channel']=='udp' for v in journal.get(row['sha256'],[])), 'UDP backend receipt absent')
            count[row['channel']]+=1
    require(set(journal) <= seen, 'unknown backend payload')
    return dict(validated=True,cases=len(cases),requests=dict(count),capture_drops=0,
                victim_timeouts=sum(r['outcome']=='timeout' for c in cases for r in c['victim']),
                scope='host loopback independent streams; no reconnects or reply retries')


def run(args):
    root,plan,uid,security=base.prepare(args)
    shutil.copyfile(base.__file__,root/'udp_lifecycle.py')
    shutil.copyfile(__file__,root/'driver.py')
    plan['schema']='flow-isolation-v1'
    plan['inputs']={n:digest(root/n) for n in INPUTS}
    (root/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    result=dict(completed=False,cleanup_exit=1,cases=[],journal=[],errors=[],plan_sha256=digest(root/'plan.json'))
    active,errors={},[]
    lock=threading.Lock(); stop=threading.Event()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2','http/1.1']); context.load_cert_chain(root/'cert.pem',root/'key.pem')
    connection_id=0
    class Target(socketserver.BaseRequestHandler):
        def handle(self):
            nonlocal connection_id
            with lock:
                connection_id+=1; identity=connection_id
            connection=self.request
            try:
                connection.settimeout(5)
                tls=connection.recv(1,socket.MSG_PEEK)==b'\x16'
                if tls: connection=context.wrap_socket(connection,server_side=True)
                while True:
                    size=int.from_bytes(exact(connection,4),'big')
                    require(size==46,'invalid target frame')
                    data=exact(connection,size)
                    require(data[:6]==b'LCISO1','unknown target payload')
                    connection.sendall(struct.pack('!I',size)+data)
                    with lock: result['journal'].append(dict(channel='tls' if tls else 'plain',connection=identity,
                                                              sha256=hashlib.sha256(data).hexdigest()))
            except (OSError,ValueError): pass  # Cover handshakes and ordinary client EOF carry no frame.
            finally: connection.close()
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            data,connection=self.request
            with lock: result['journal'].append(dict(channel='udp',sha256=hashlib.sha256(data).hexdigest()))
            connection.sendto(data,self.client_address)
    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with socket.create_connection(('127.0.0.1',29600),timeout=5) as upstream:
                    self.request.settimeout(.1); upstream.settimeout(.1)
                    with lock: active[self.client_address[1]]=(self.request,upstream)
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
                    reader=threading.Thread(target=copy,args=(upstream,self.request)); reader.start()
                    copy(self.request,upstream); reader.join(timeout=6)
                    if reader.is_alive(): errors.append('relay reader survived')
            except OSError as error:
                if not stop.is_set(): errors.append(repr(error))
            finally:
                with lock: active.pop(self.client_address[1],None)
    listeners=[base.ThreadServer(('127.0.0.1',29622),Target),
               socketserver.ThreadingUDPServer(('127.0.0.1',29623),Echo),
               base.ThreadServer(('127.0.0.1',29601),Relay)]
    capture=base.Capture(root); processes=Processes(root); sequence=0
    for listener in listeners: threading.Thread(target=listener.serve_forever,daemon=True).start()
    def exchange(connection,channel,stage,port,optional=False):
        nonlocal sequence
        with lock: sequence+=1; seq=sequence
        udp=channel in ('udp','victim')
        data=(b'LCUDP1' if udp else b'LCISO1')+struct.pack('!Q',seq)+os.urandom(32)
        row=dict(channel=channel,stage=stage,sequence=seq,sha256=hashlib.sha256(data).hexdigest(),
                 source_port=connection.getsockname()[1],start_ns=time.time_ns(),start_mono_ns=time.monotonic_ns())
        deadline=time.monotonic()+5
        connection.settimeout(5)
        try:
            if udp:
                connection.sendto(data,('127.0.0.1',port))
                connection.settimeout(max(.000001,deadline-time.monotonic()))
                reply,peer=connection.recvfrom(65535)
                require(peer==('127.0.0.1',port),'unexpected UDP sender')
            else:
                connection.sendall(struct.pack('!I',46)+data)
                require(exact(connection,4,deadline)==struct.pack('!I',46),'invalid reply frame')
                reply=exact(connection,46,deadline)
            require(reply==data,'corrupt or stale reply'); row['outcome']='echo'
        except socket.timeout:
            if not optional: raise
            row['outcome']='timeout'
        row.update(end_ns=time.time_ns(),end_mono_ns=time.monotonic_ns())
        return row
    try:
        with termination_guard():
            server=processes.start(['./xray','run','-c','server.json'],'server.log',29600,plan['inputs']['xray'])
            for n in range(1,args.rounds+1):
                for fault in base.FAULTS:
                    for role in (base.ROLES if n%2 else tuple(reversed(base.ROLES))):
                        case=dict(round=n,fault=fault,role=role,peers={},victim=[],background=[],pump_errors=[])
                        port=19970 if role=='ref' else 19971; udp_port=19600 if role=='ref' else 19601
                        command=['./xray','run','-c','client.json'] if role=='ref' else [
                            './lc-tunnel','fingerprint.fpt','127.0.0.1','29601','udp.test',security['password'],
                            security['shortId'],uid,str(port),'-t','127.0.0.1:29622','-u',f'{udp_port}@127.0.0.1:29623',
                            '-f','xtls-rprx-vision','-w','4' if role=='lc4' else '1']
                        child=processes.start(command,f'{n}-{fault}-{role}.log',port,
                                              plan['inputs']['xray' if role=='ref' else 'lc-tunnel'])
                        base.wait_udp(processes,child,udp_port,4 if role=='lc4' else 1)
                        sockets={}; pumps=[]; finished=threading.Event()
                        try:
                            for channel in ('victim',*CHANNELS):
                                with lock: before=set(active)
                                if channel in ('victim','udp'):
                                    connection=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                                    connection.bind(('127.0.0.1',0))
                                else:
                                    connection=socket.create_connection(('127.0.0.1',port),timeout=5)
                                sockets[channel]=connection
                                if channel=='tls':
                                    ctx=ssl.create_default_context(cafile=str(root/'cert.pem'))
                                    ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
                                    connection=ctx.wrap_socket(connection,server_hostname='udp.test'); sockets[channel]=connection
                                row=exchange(connection,channel,'seed',udp_port)
                                case['victim' if channel=='victim' else 'background'].append(row)
                                with lock: new=set(active)-before
                                require(len(new)==1,'channel did not obtain a distinct upstream')
                                case['peers'][channel]=new.pop()
                            def pump(channel):
                                try:
                                    while not finished.is_set():
                                        row=exchange(sockets[channel],channel,'pump',udp_port)
                                        with lock: case['background'].append(row)
                                        finished.wait(.05)
                                except Exception as error: case['pump_errors'].append(channel+': '+repr(error))
                            for channel in CHANNELS:
                                thread=threading.Thread(target=pump,args=(channel,)); thread.start(); pumps.append(thread)
                            time.sleep(.3)
                            case['injection_ns']=time.time_ns()
                            with lock: targets=active[case['peers']['victim']]
                            if fault=='fin': targets[0].shutdown(socket.SHUT_WR)
                            elif fault=='reset':
                                for connection in targets:
                                    connection.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
                                    connection.close()
                            case['injection_end_ns']=time.time_ns()
                            case['victim'].append(exchange(sockets['victim'],'victim','after',udp_port,fault!='none'))
                            time.sleep(3)
                            case['victim'].append(exchange(sockets['victim'],'victim','recovered',udp_port))
                            with lock: case['neighbors_alive']=all(case['peers'][c] in active for c in CHANNELS)
                            case['observation_end_ns']=time.time_ns()
                        finally:
                            finished.set()
                            for thread in pumps: thread.join(timeout=6)
                            for connection in sockets.values(): connection.close()
                            require(all(not t.is_alive() for t in pumps),'pump survived')
                        require(not case['pump_errors'],'neighbor failed: '+str(case['pump_errors']))
                        processes.alive(child,server); case['alive']=True
                        case['binary_sha256']=digest(f'/proc/{child.pid}/exe')
                        case['client_exit']=processes.stop(child)
                        for entry in Path('/proc').iterdir():
                            if entry.name.isdecimal():
                                try: require(os.getpgid(int(entry.name))!=child.pid,'client group survived')
                                except ProcessLookupError: pass
                        result['cases'].append(case)
                        print('ISOLATION_CASE',n,fault,role,len(case['background']),flush=True)
                        deadline=time.monotonic()+6
                        while active and time.monotonic()<deadline: time.sleep(.02)
                        require(not active and not errors,'relay cleanup failed')
            processes.alive(server); result['server_sha256']=digest(f'/proc/{server.pid}/exe')
            result['server_exit']=processes.stop(server); result['completed']=True
    finally:
        result['cleanup_exit']=processes.close(); stop.set()
        for listener in listeners: listener.shutdown(); listener.server_close()
        result['capture']=capture.close(); result['errors']=errors+capture.errors
        (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    analysis=analyze(root)
    (root/'analysis.json').write_text(json.dumps(analysis,indent=2)+'\n')
    return analysis


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--analyze',action='store_true')
    for name in ('lc','reference','fingerprint'): parser.add_argument('--'+name,type=Path)
    parser.add_argument('--rounds',type=int,choices=range(1,11),default=3)
    args=parser.parse_args()
    if not args.analyze: require(all((args.lc,args.reference,args.fingerprint)),'binary inputs required')
    print(json.dumps(analyze(args.directory) if args.analyze else run(args),indent=2))
