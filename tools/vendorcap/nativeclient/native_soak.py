"""Prepare, serve and replay a bounded native mixed-load/reclamation test."""
import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import socketserver
import ssl
import subprocess
import threading
import time
from urllib.parse import parse_qs, urlparse

import analyze_network
import checkpoint_process
from checkpoint_process import Processes, digest, termination_guard

DEVICE_INPUTS = frozenset({'client','probe','fingerprint.fpt','cert.pem','uuid','settings.sh','native-soak.sh'})
INPUTS = DEVICE_INPUTS | frozenset({'driver.py','checkpoint_process.py','analyze_network.py','xray',
                                  'server.json','key.pem','device.json','source.sha256','prepare.log'})
BODY = bytes(range(256))*4096
BODY_SHA = hashlib.sha256(BODY).hexdigest()
PROFILES = {'short': (60, 6, 1200), 'long': (1800, 180, 8400)}


def require(value, message):
    if not value: raise ValueError(message)


def write(root,name,value):
    (root/name).write_text(json.dumps(value,indent=2)+'\n')


def require_mips(path):
    header=path.read_bytes()[:20]
    require(len(header)==20 and header[:4]==b'\x7fELF' and header[4:6]==bytes([1,1]) and
            int.from_bytes(header[18:20],'little')==8,'expected a 32-bit little-endian MIPS executable: '+path.name)


def prepare(args):
    profile=getattr(args,'profile','short')
    require(profile in PROFILES,'unsupported soak profile')
    active,bursts,maximum=PROFILES[profile]
    root=args.directory.resolve()
    root.mkdir(parents=True,mode=0o700,exist_ok=False)
    here=Path(__file__).resolve().parent
    for source,name in ((args.lc,'client'),(args.probe,'probe'),(args.reference,'xray'),
        (args.device_json,'device.json'),(here/'native-soak.sh','native-soak.sh'),
        (Path(__file__),'driver.py'),(Path(checkpoint_process.__file__),'checkpoint_process.py'),
        (Path(analyze_network.__file__),'analyze_network.py'),
        (args.source_root/'package/files/fingerprint.fpt','fingerprint.fpt')):
        shutil.copyfile(source,root/name)
    for name in ('client','probe','xray'): (root/name).chmod(0o700)
    for name in ('client','probe'): require_mips(root/name)
    identity=json.loads((root/'device.json').read_text())
    require(identity['architecture']=='mipsel','this plan targets the authorized MIPS test device')
    values=dict(line.split(': ',1) for line in subprocess.check_output(
        [str(root/'xray'),'x25519'],text=True).splitlines() if ': ' in line)
    version=subprocess.check_output([str(root/'xray'),'version'],text=True)
    with (root/'prepare.log').open('w') as log:
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
            '-subj','/CN=soak.test','-addext','subjectAltName=DNS:soak.test',
            '-keyout','key.pem','-out','cert.pem'],cwd=root,check=True,stdout=log,stderr=log)
    uid='00000000-0000-4000-8000-000000000001'
    (root/'uuid').write_text(uid+'\n')
    (root/'uuid').chmod(0o600)
    server=dict(log=dict(loglevel='warning'),inbounds=[dict(listen=args.advertised_host,port=29600,
        protocol='vless',settings=dict(clients=[dict(id=uid,flow='xtls-rprx-vision')],decryption='none'),
        streamSettings=dict(network='raw',security='reality',realitySettings=dict(
            target='127.0.0.1:29622',serverNames=['soak.test'],privateKey=values['PrivateKey'],
            shortIds=['0123abcd'])))],outbounds=[dict(protocol='freedom',
                settings=dict(finalRules=[dict(action='allow',ip=['127.0.0.0/8'])]))])
    write(root,'server.json',server)
    settings=dict(EXPECTED_BOARD=identity['board_name'],EXPECTED_BOOT=identity['boot_id'],
        SERVER_ADDRESS=args.advertised_host,PUBLIC_KEY=values['Password (PublicKey)'],SHORT_ID='0123abcd',
        CLIENT_SHA256=digest(root/'client'),PAYLOAD_SHA256=BODY_SHA,
        ACTIVE_SECONDS=active,BURSTS_PER_EPOCH=bursts,MAXIMUM_SECONDS=maximum)
    (root/'settings.sh').write_text(''.join(k+'='+shlex.quote(str(v))+'\n' for k,v in settings.items()))
    sources=[]
    for source in sorted((args.source_root/'src').rglob('*')):
        if source.suffix in ('.c','.h'):
            sources.append(digest(source)+'  '+source.relative_to(args.source_root).as_posix()+'\n')
    for name in ('Makefile','docker/Dockerfile','tools/vendorcap/nativeclient/soak_probe.c',
                 'tools/vendorcap/nativeclient/native-soak.sh','tools/vendorcap/nativeclient/native_soak.py',
                 'vendor/Xray-core/go.mod','vendor/Xray-core/go.sum'):
        sources.append(digest(args.source_root/name)+'  '+name+'\n')
    (root/'source.sha256').write_text(''.join(sources))
    plan=dict(schema='native-mixed-soak-v1' if profile=='short' else 'native-mixed-soak-v2',
        workers=[1,4],epochs=2,bursts_per_epoch=bursts,
        active_seconds=active,idle_seconds=190,maximum_seconds=maximum,body_bytes=len(BODY),body_sha256=BODY_SHA,
        resource_policy='flash-only',ram_limits=None,scope='bounded native correctness and socket reclamation',
        performance_comparison=False,reference_version=version,advertised_host=args.advertised_host,
        control_port=args.control_port,control_token=secrets.token_hex(32),
        inputs={name:digest(root/name) for name in sorted(INPUTS)})
    if profile=='long':
        plan['profile']='long'
        plan['scope']='two hours of native mixed load plus four idle reclamation windows'
    write(root,'plan.json',plan)
    stage=root/'device-stage'; stage.mkdir(mode=0o700)
    for name in DEVICE_INPUTS:
        shutil.copyfile(root/name,stage/name)
        (stage/name).chmod(0o600)
    (stage/'plan.sha256').write_text(digest(root/'plan.json')+'\n')
    (stage/'device.sha256').write_text(''.join(digest(stage/name)+'  '+name+'\n'
        for name in sorted(DEVICE_INPUTS | {'plan.sha256'})))
    return dict(schema=plan['schema'],plan_sha256=digest(root/'plan.json'))


def validate_inputs(root):
    plan=json.loads((root/'plan.json').read_text())
    profile='short' if plan['schema']=='native-mixed-soak-v1' else 'long'
    active,bursts,maximum=PROFILES[profile]
    require((profile=='short' or plan['schema']=='native-mixed-soak-v2' and plan.get('profile')=='long') and
        plan['workers']==[1,4] and plan['epochs']==2 and plan['bursts_per_epoch']==bursts and
        plan['active_seconds']==active and plan['idle_seconds']==190 and
        plan['maximum_seconds']==maximum and plan['body_bytes']==len(BODY) and plan['body_sha256']==BODY_SHA,
        'unsupported native soak plan')
    require(plan['resource_policy']=='flash-only' and plan['ram_limits'] is None and
            plan['performance_comparison'] is False,'changed resource/scope policy')
    require(set(plan['inputs'])==INPUTS and all(digest(root/name)==sha for name,sha in plan['inputs'].items()),
            'frozen input changed')
    return plan


def http_backend(plan, tls, journal):
    class Backend(socketserver.BaseRequestHandler):
        def handle(self):
            connection=self.request
            try:
                connection.settimeout(10)
                encrypted=connection.recv(1,socket.MSG_PEEK)==b'\x16'
                if encrypted: connection=tls.wrap_socket(connection,server_side=True)
                source=connection.makefile('rb')
                first=source.readline(4096).decode('ascii')
                if not first: return
                method,url,version=first.strip().split(' ')
                require(method=='GET' and version=='HTTP/1.1','unexpected loader request')
                case=parse_qs(urlparse(url).query)['case'][0]
                require(re.fullmatch(r'lc[14]\.[12]\.(0|[1-9][0-9]*)\.[1-4]',case) and
                        int(case.split('.')[2])<plan['bursts_per_epoch'],'invalid case label')
                while line:=source.readline(4096):
                    if line==b'\r\n': break
                # A successful response must never hide an unwritable receipt.
                journal('http.jsonl',dict(case=case,tls13=encrypted,bytes=len(BODY),sha256=BODY_SHA))
                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n'+BODY)
            except (OSError,ValueError,KeyError): pass
            finally: connection.close()
    return Backend


def udp_backend(journal):
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            data,connection=self.request
            if len(data)!=128 or not data.startswith(b'LCSOAK1'): return
            journal('udp.jsonl',dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data)))
            count=connection.sendto(data,self.client_address)
            require(count==len(data),'short peer UDP response')
    return Echo


def serve(root):
    plan=validate_inputs(root)
    require(digest(__file__)==plan['inputs']['driver.py'],'executed stand driver is not frozen')
    for module,name in ((checkpoint_process,'checkpoint_process.py'),(analyze_network,'analyze_network.py')):
        require(digest(module.__file__)==plan['inputs'][name],'executed helper is not frozen')
    require(not (root/'stand-state.json').exists(),'stand evidence already exists')
    lock=threading.Lock(); received=threading.Event(); journal_failed=threading.Event()
    def journal(name,value):
        try:
            with lock:
                with (root/name).open('a') as log: log.write(json.dumps(value)+'\n')
        except OSError:
            journal_failed.set()
            raise
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version=tls.maximum_version=ssl.TLSVersion.TLSv1_3
    tls.set_alpn_protocols(['h2','http/1.1']); tls.load_cert_chain(root/'cert.pem',root/'key.pem')
    class TCP(socketserver.ThreadingTCPServer): allow_reuse_address=True
    backend=TCP(('127.0.0.1',29622),http_backend(plan,tls,journal))
    udp=socketserver.ThreadingUDPServer(('127.0.0.1',29623),udp_backend(journal))
    for listener in (backend,udp): threading.Thread(target=listener.serve_forever,daemon=True).start()
    class Control(BaseHTTPRequestHandler):
        def do_PUT(self):
            if self.path!='/results' or not hmac.compare_digest(self.headers.get('Authorization',''),
                    'Bearer '+plan['control_token']): self.send_error(403); return
            count=int(self.headers.get('Content-Length','0'))
            if not 0<count<=32*1024*1024: self.send_error(413); return
            data=self.rfile.read(count)
            if len(data)!=count or hashlib.sha256(data).hexdigest()!=self.headers.get('X-Archive-SHA256'):
                self.send_error(400); return
            (root/'device-results.tgz').write_bytes(data)
            self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'OK')
            received.set()
    control=HTTPServer((plan['advertised_host'],plan['control_port']),Control); control.timeout=1
    processes=Processes(root)
    state=dict(finished=False,server_exit=None,cleanup_exit=1)
    try:
        with termination_guard():
            server=processes.start(['./xray','run','-c','server.json'],'server.log',29600,plan['inputs']['xray'])
            print('NATIVE_SOAK_STAND_READY',flush=True)
            began=time.monotonic()
            while not received.is_set():
                require(not journal_failed.is_set(),'peer receipt write failed')
                require(time.monotonic()-began<plan['maximum_seconds']+600,'stand deadline')
                processes.alive(server)
                control.handle_request()
            require(not journal_failed.is_set(),'peer receipt write failed')
            state['server_exit']=processes.stop(server)
            require(state['server_exit']==0,'reference server stop failed')
            state['finished']=True
    finally:
        control.server_close()
        for listener in (backend,udp): listener.shutdown(); listener.server_close()
        state['cleanup_exit']=processes.close()
        if journal_failed.is_set(): state['receipt_write_failed']=True
        write(root,'stand-state.json',state)
    return state


def analyze(root):
    plan=validate_inputs(root)
    state=json.loads((root/'stand-state.json').read_text())
    require(state==dict(finished=True,server_exit=0,cleanup_exit=0),'stand did not complete/clean up')
    device=root/'device-results'
    require(device.is_dir(),'unpack device results before analysis')
    status=json.loads((device/'device-state.json').read_text())
    require(status['exit_code']==status['cleanup_exit']==0 and status['roles_completed']==2 and
            4*(plan['active_seconds']+plan['idle_seconds'])<=status['elapsed_seconds']<plan['maximum_seconds'],
            'device did not complete')
    require((device/'plan.sha256').read_text().strip()==digest(root/'plan.json'),'device used another plan')
    for name in DEVICE_INPUTS:
        require(digest(device/name)==plan['inputs'][name],'device input changed: '+name)
    for prefix in ('boot','configuration','interfaces'):
        require((device/(prefix+'-before')).read_bytes()==(device/(prefix+'-after')).read_bytes(),
                'device state changed: '+prefix)
    identity=json.loads((root/'device.json').read_text())
    require((device/'board-name').read_text().strip()==identity['board_name'] and
            (device/'boot-before').read_text().strip()==identity['boot_id'],'wrong device identity')
    records=[json.loads(line) for line in (device/'bursts.jsonl').read_text().splitlines()]
    expected={(role,epoch,burst) for role in ('lc1','lc4') for epoch in (1,2) for burst in range(plan['bursts_per_epoch'])}
    tcp_count=len(expected)*4; udp_count=len(expected)*64
    require(len(records)==len(expected) and {(r['role'],r['epoch'],r['burst']) for r in records}==expected,
            'incomplete bursts')
    require([(r['role'],r['epoch'],r['burst']) for r in records]==sorted(expected), 'burst order changed')
    require(all(r['tcp_cases']==4 and r['tcp_bytes']==4*len(BODY) and r['udp_echoes']==64
                for r in records), 'burst counters differ')
    payloads=[line.split() for line in (device/'payloads.sha256').read_text().splitlines()]
    labels={f'{role}.{epoch}.{burst}.{stream}' for role,epoch,burst in expected for stream in range(1,5)}
    require(len(payloads)==tcp_count and {name.removesuffix('.body') for sha,name in payloads}==labels and
            all(sha==BODY_SHA for sha,name in payloads),'incomplete/wrong payload hashes')
    http=[json.loads(line) for line in (root/'http.jsonl').read_text().splitlines()]
    require(len(http)==tcp_count and {r['case'] for r in http}==labels and all(r['bytes']==len(BODY) and
        r['sha256']==BODY_SHA and r['tls13']==(int(r['case'].split('.')[-1])%2==0) for r in http),'backend HTTP coverage')
    udp=[json.loads(line) for line in (root/'udp.jsonl').read_text().splitlines()]
    require(len(udp)==udp_count and len({r['sha256'] for r in udp})==udp_count and
            all(r['bytes']==128 for r in udp),'backend UDP coverage')
    for role,epoch,burst in expected:
        value=json.loads((device/f'{role}.{epoch}.{burst}.udp.json').read_text())
        require(value==dict(echoes=64,bytes=8192),'native UDP check failed')
    metrics=[json.loads(line) for line in (device/'resources.jsonl').read_text().splitlines()]
    require(metrics and all(r['role'] in ('lc1','lc4') and
        (r['epoch'],r['stage']) in ((0,'ready'),(1,'active'),(1,'idle'),(2,'active'),(2,'idle')) and
        type(r['elapsed']) is int and 0<=r['elapsed']<=status['elapsed_seconds'] for r in metrics),
        'invalid monitor labels/timestamps')
    require(all(a['elapsed']<=b['elapsed'] for a,b in zip(metrics,metrics[1:])), 'monitor time reversed')
    idle_start={tuple(line.split()[:2]):int(line.split()[2]) for line in (device/'idle-started.tsv').read_text().splitlines()}
    idle_end={tuple(line.split()[:2]):int(line.split()[2]) for line in (device/'idle-finished.tsv').read_text().splitlines()}
    reports=[]
    for role,count in (('lc1',1),('lc4',5)):
        receipt=json.loads((device/f'{role}.receipt.json').read_text())
        require(receipt==dict(role=role,binary_sha256=plan['inputs']['client'],client_exit=143,monitor_exit=143),
                'client receipt failed')
        ready=json.loads((device/f'{role}.ready.json').read_text())
        identities={(p['pid'],p['born']) for p in ready['tasks']}
        require(len(identities)==count,'worker count differs')
        rows=[r for r in metrics if r['role']==role]
        require(rows and all(0<=b['elapsed']-a['elapsed']<=3 for a,b in zip(rows,rows[1:])),'monitor gap')
        phases=[]
        for row in rows:
            phase=(row['epoch'],row['stage'])
            if not phases or phases[-1]!=phase: phases.append(phase)
        require(phases==[(0,'ready'),(1,'active'),(1,'idle'),(2,'active'),(2,'idle')],
                'monitor phase order changed')
        for row in rows:
            sample=row['sample']
            require({(p['pid'],p['born']) for p in sample['tasks']}==identities,'process restart/identity changed')
            require(row['memavailable_kib']>=0 and all(p['fds']>0 and p['threads']>0 and p['rss_kib']>=0
                for p in sample['tasks']),'invalid resource sample')
        for epoch in (1,2):
            for stage,duration in (('active',plan['active_seconds']),('idle',190)):
                window=[r for r in rows if r['epoch']==epoch and r['stage']==stage]
                require(window and window[-1]['elapsed']-window[0]['elapsed']>=duration-3,'monitor window incomplete')
                if stage=='active':
                    # Same device uptime clock; phase observations can lag by the existing three-second gap.
                    for burst in (r for r in records if r['role']==role and r['epoch']==epoch):
                        require(type(burst['elapsed']) is int and
                            window[0]['elapsed']+burst['burst']*10-3<=burst['elapsed']<=window[-1]['elapsed']+3,
                            'burst outside active schedule')
            key=(role,str(epoch))
            require(190<=idle_end[key]-idle_start[key]<=193,'idle duration changed')
            quiet=json.loads((device/f'{role}.{epoch}.quiescent.json').read_text())
            require({(p['pid'],p['born']) for p in quiet['tasks']}==identities and
                quiet['tcp_listener_fds']==count and quiet['udp_listener_fds']==(1 if count==1 else 4) and
                quiet['other_socket_fds']==0,'session sockets not reclaimed')
        reports.append(dict(role=role,samples=len(rows),identities=len(identities),
            minimum_memavailable_kib=min(r['memavailable_kib'] for r in rows),
            peak_sampled_rss_kib=max(sum(p['rss_kib'] for p in r['sample']['tasks']) for r in rows)))
    return dict(validated=True,scope=plan['scope'],elapsed_seconds=status['elapsed_seconds'],
        tcp_cases=tcp_count,tcp_bytes=tcp_count*len(BODY),udp_echoes=udp_count,roles=reports,ram_acceptance_limit=None)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('prepare','serve','analyze'))
    parser.add_argument('directory',type=Path)
    for name in ('lc','probe','reference','device-json','source-root'): parser.add_argument('--'+name,type=Path)
    parser.add_argument('--advertised-host'); parser.add_argument('--control-port',type=int,default=19892)
    parser.add_argument('--profile',choices=tuple(PROFILES),default='short')
    args=parser.parse_args()
    if args.mode=='prepare':
        require(all((args.lc,args.probe,args.reference,args.device_json,args.source_root,args.advertised_host)),
                'all preparation inputs required')
        answer=prepare(args)
    elif args.mode=='serve': answer=serve(args.directory)
    else: answer=analyze(args.directory)
    print(json.dumps(answer,indent=2))
