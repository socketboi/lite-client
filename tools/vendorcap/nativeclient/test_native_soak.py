import copy
import json
import os
import socket
import socketserver
import sys
import threading
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from checkpoint_process import digest
from native_soak import BODY_SHA, DEVICE_INPUTS, INPUTS, analyze, prepare, require_mips, http_backend, udp_backend


class ReceiptFailureTests(unittest.TestCase):
    def journal(self, fail, rows):
        def record(name, value):
            if fail:
                # Real write/flush failure, without filling a shared filesystem.
                with open('/dev/full', 'w') as output:
                    output.write(json.dumps(value) + '\n')
            rows.append((name, value))
        return record

    def test_http_ack_requires_a_written_receipt(self):
        for fail in (False, True):
            with self.subTest(full_disk=fail):
                rows = []
                handler = http_backend(dict(bursts_per_epoch=6), None, self.journal(fail, rows))
                with socketserver.ThreadingTCPServer(('127.0.0.1', 0), handler) as server:
                    thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=.01))
                    thread.start()
                    try:
                        with socket.create_connection(server.server_address, timeout=2) as connection:
                            connection.sendall(b'GET /?case=lc1.1.0.1 HTTP/1.1\r\nHost: fixture\r\n\r\n')
                            response = bytearray()
                            while data := connection.recv(65536):
                                response.extend(data)
                        if fail:
                            self.assertEqual(response, b'')
                            self.assertEqual(rows, [])
                        else:
                            self.assertTrue(response.startswith(b'HTTP/1.1 200 OK\r\n'))
                            self.assertEqual(len(response.split(b'\r\n\r\n', 1)[1]), 1048576)
                            self.assertEqual(rows[0][1]['case'], 'lc1.1.0.1')
                    finally:
                        server.shutdown()
                        thread.join()

    def test_udp_ack_requires_a_written_receipt(self):
        class Server(socketserver.ThreadingUDPServer):
            def handle_error(self, request, address):
                errors.append(sys.exc_info()[1])
        for fail in (False, True):
            with self.subTest(full_disk=fail):
                rows = []; errors = []
                with Server(('127.0.0.1', 0), udp_backend(self.journal(fail, rows))) as server:
                    thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=.01))
                    thread.start()
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                            connection.settimeout(.2)
                            payload = b'LCSOAK1' + b'x' * 121
                            connection.sendto(payload, server.server_address)
                            if fail:
                                with self.assertRaises(socket.timeout): connection.recv(1024)
                            else:
                                self.assertEqual(connection.recv(1024), payload)
                                self.assertEqual(rows[0][1]['bytes'], 128)
                    finally:
                        server.shutdown()
                        thread.join()
                if fail:
                    self.assertEqual(rows, [])
                    self.assertEqual(len(errors), 1)
                    self.assertIsInstance(errors[0], OSError)


class NativeSoakEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root=Path(directory.name)
        self.device=self.root/'device-results'; self.device.mkdir()
        for name in INPUTS: (self.root/name).write_text('fixture-'+name)
        self.write(self.root,'device.json',dict(board_name='fixture-board',boot_id='fixture-boot',architecture='mipsel'))
        for name in DEVICE_INPUTS: (self.device/name).write_bytes((self.root/name).read_bytes())
        long=getattr(self,'long_profile',False)
        active,bursts,maximum=(1800,180,8400) if long else (60,6,1200)
        self.plan=dict(schema='native-mixed-soak-v2' if long else 'native-mixed-soak-v1',
            workers=[1,4],epochs=2,bursts_per_epoch=bursts,
            active_seconds=active,idle_seconds=190,maximum_seconds=maximum,body_bytes=1048576,body_sha256=BODY_SHA,
            resource_policy='flash-only',ram_limits=None,performance_comparison=False,
            scope='bounded native correctness and socket reclamation',inputs={n:digest(self.root/n) for n in INPUTS})
        if long: self.plan['profile']='long'
        self.write(self.root,'plan.json',self.plan)
        (self.device/'plan.sha256').write_text(digest(self.root/'plan.json')+'\n')
        self.write(self.root,'stand-state.json',dict(finished=True,server_exit=0,cleanup_exit=0))
        self.write(self.device,'device-state.json',dict(exit_code=0,cleanup_exit=0,roles_completed=2,
                                                      elapsed_seconds=4*(active+190)+5))
        for prefix in ('boot','configuration','interfaces'):
            for side in ('before','after'):
                (self.device/f'{prefix}-{side}').write_text('fixture-boot\n' if prefix=='boot' else 'unchanged\n')
        (self.device/'board-name').write_text('fixture-board\n')
        self.bursts=[]; self.http=[]; self.metrics=[]; hashes=[]; start=[]; end=[]
        for role,count,offset in (('lc1',1,0),('lc4',5,2*(active+190)+2)):
            tasks=[dict(pid=100+offset+i,born=10000+offset+i,cpu=1,rss_kib=1,threads=1,
                        fds=6,sockets=2) for i in range(count)]
            ready=dict(tasks=tasks,tcp_listener_fds=count,udp_listener_fds=1 if count==1 else 4,other_socket_fds=0)
            self.write(self.device,f'{role}.ready.json',ready)
            self.write(self.device,f'{role}.receipt.json',dict(role=role,binary_sha256=self.plan['inputs']['client'],
                                                            client_exit=143,monitor_exit=143))
            self.metrics.append(dict(role=role,epoch=0,stage='ready',elapsed=offset,memavailable_kib=0,sample=ready))
            for epoch in (1,2):
                base=offset+(epoch-1)*(active+191)
                for stage,first,last in (('active',0,active-1),('idle',active,active+190)):
                    for stamp in range(first,last+1):
                        self.metrics.append(dict(role=role,epoch=epoch,stage=stage,elapsed=base+stamp,
                                                 memavailable_kib=0,sample=copy.deepcopy(ready)))
                self.write(self.device,f'{role}.{epoch}.quiescent.json',ready)
                start.append(f'{role} {epoch} {base+active}')
                end.append(f'{role} {epoch} {base+active+190}')
                for burst in range(bursts):
                    self.bursts.append(dict(role=role,epoch=epoch,burst=burst,elapsed=base+burst*10,
                                           tcp_cases=4,tcp_bytes=4194304,udp_echoes=64))
                    self.write(self.device,f'{role}.{epoch}.{burst}.udp.json',dict(echoes=64,bytes=8192))
                    for stream in range(1,5):
                        label=f'{role}.{epoch}.{burst}.{stream}'
                        hashes.append(BODY_SHA+'  '+label+'.body')
                        self.http.append(dict(case=label,tls13=stream%2==0,bytes=1048576,sha256=BODY_SHA))
        self.lines(self.device,'bursts.jsonl',self.bursts)
        self.lines(self.device,'resources.jsonl',self.metrics)
        self.lines(self.root,'http.jsonl',self.http)
        self.lines(self.root,'udp.jsonl',[dict(sha256=f'{i:064x}',bytes=128) for i in range(4*bursts*64)])
        (self.device/'payloads.sha256').write_text('\n'.join(hashes)+'\n')
        (self.device/'idle-started.tsv').write_text('\n'.join(start)+'\n')
        (self.device/'idle-finished.tsv').write_text('\n'.join(end)+'\n')

    @staticmethod
    def write(root,name,value): (root/name).write_text(json.dumps(value)+'\n')

    @staticmethod
    def lines(root,name,values): (root/name).write_text(''.join(json.dumps(v)+'\n' for v in values))

    def test_complete_zero_memavailable_fixture_has_no_ram_gate(self):
        result=analyze(self.root)
        self.assertTrue(result['validated'])
        self.assertIsNone(result['ram_acceptance_limit'])
        self.assertEqual((result['tcp_cases'],result['udp_echoes']),(96,1536))

    def test_failed_device_is_not_an_accepted_soak(self):
        self.write(self.device,'device-state.json',dict(exit_code=1,cleanup_exit=0,roles_completed=2,elapsed_seconds=1005))
        with self.assertRaisesRegex(ValueError,'device did not complete'): analyze(self.root)

    def test_server_cleanup_must_complete(self):
        self.write(self.root,'stand-state.json',dict(finished=True,server_exit=0,cleanup_exit=1))
        with self.assertRaisesRegex(ValueError,'stand did not complete'): analyze(self.root)

    def test_resource_policy_cannot_gain_a_ram_floor(self):
        self.plan['ram_limits']=dict(minimum_memavailable_kib=1024)
        self.write(self.root,'plan.json',self.plan)
        with self.assertRaisesRegex(ValueError,'resource/scope policy'): analyze(self.root)

    def test_changed_helper_input_is_rejected(self):
        (self.root/'probe').write_text('changed')
        with self.assertRaisesRegex(ValueError,'frozen input changed'): analyze(self.root)

    def test_changed_staged_helper_is_rejected(self):
        (self.device/'probe').write_text('changed')
        with self.assertRaisesRegex(ValueError,'device input changed'): analyze(self.root)

    def test_wrong_device_plan_is_rejected(self):
        (self.device/'plan.sha256').write_text('0'*64)
        with self.assertRaisesRegex(ValueError,'another plan'): analyze(self.root)

    def test_missing_burst_is_rejected(self):
        self.lines(self.device,'bursts.jsonl',self.bursts[:-1])
        with self.assertRaisesRegex(ValueError,'incomplete bursts'): analyze(self.root)

    def test_wrong_burst_payload_counters_are_rejected(self):
        self.bursts[0]['tcp_bytes']=0
        self.lines(self.device,'bursts.jsonl',self.bursts)
        with self.assertRaisesRegex(ValueError,'burst counters'): analyze(self.root)

    def test_compressed_burst_schedule_is_rejected(self):
        for row in self.bursts[:6]: row['elapsed']=0
        self.lines(self.device,'bursts.jsonl',self.bursts)
        with self.assertRaisesRegex(ValueError,'burst outside active schedule'): analyze(self.root)

    def test_burst_outside_its_active_window_is_rejected(self):
        self.bursts[0]['elapsed']=950
        self.lines(self.device,'bursts.jsonl',self.bursts)
        with self.assertRaisesRegex(ValueError,'burst outside active schedule'): analyze(self.root)

    def test_reversed_burst_journal_is_rejected(self):
        self.lines(self.device,'bursts.jsonl',list(reversed(self.bursts)))
        with self.assertRaisesRegex(ValueError,'burst order'): analyze(self.root)

    def test_unknown_monitor_role_is_rejected(self):
        row=copy.deepcopy(self.metrics[-1]); row['role']='unknown'
        self.lines(self.device,'resources.jsonl',self.metrics+[row])
        with self.assertRaisesRegex(ValueError,'monitor labels'): analyze(self.root)

    def test_reentered_monitor_phase_is_rejected(self):
        next(r for r in self.metrics if r['role']=='lc1' and r['elapsed']==30)['stage']='idle'
        self.lines(self.device,'resources.jsonl',self.metrics)
        with self.assertRaisesRegex(ValueError,'monitor phase order'): analyze(self.root)

    def test_loader_tls_mode_must_match_its_label(self):
        self.http[0]['tls13']=True
        self.lines(self.root,'http.jsonl',self.http)
        with self.assertRaisesRegex(ValueError,'backend HTTP coverage'): analyze(self.root)

    def test_udp_receipt_count_is_checked(self):
        self.write(self.device,'lc1.1.0.udp.json',dict(echoes=63,bytes=8064))
        with self.assertRaisesRegex(ValueError,'native UDP check failed'): analyze(self.root)

    def test_missing_monitor_interval_is_rejected(self):
        self.lines(self.device,'resources.jsonl',[v for v in self.metrics
            if v['role']!='lc1' or not 20<=v['elapsed']<=30])
        with self.assertRaisesRegex(ValueError,'monitor gap'): analyze(self.root)

    def test_process_restart_is_rejected(self):
        self.metrics[1]['sample']['tasks'][0]['born']+=1
        self.lines(self.device,'resources.jsonl',self.metrics)
        with self.assertRaisesRegex(ValueError,'identity changed'): analyze(self.root)

    def test_open_session_socket_after_idle_is_rejected(self):
        value=json.loads((self.device/'lc4.2.quiescent.json').read_text())
        value['other_socket_fds']=1
        self.write(self.device,'lc4.2.quiescent.json',value)
        with self.assertRaisesRegex(ValueError,'not reclaimed'): analyze(self.root)

    def test_shortened_idle_is_rejected(self):
        path=self.device/'idle-finished.tsv'
        path.write_text(path.read_text().replace('lc1 1 250','lc1 1 249'))
        with self.assertRaisesRegex(ValueError,'idle duration changed'): analyze(self.root)

    def test_configuration_change_is_rejected(self):
        (self.device/'configuration-after').write_text('changed')
        with self.assertRaisesRegex(ValueError,'device state changed'): analyze(self.root)

    @unittest.skipUnless(os.name=='posix','device archive permission checks require POSIX')
    def test_prepare_stages_uuid_and_settings_with_owner_only_permissions(self):
        source=self.root/'source'
        for name in ('Makefile','docker/Dockerfile','package/files/fingerprint.fpt',
                     'tools/vendorcap/nativeclient/soak_probe.c','tools/vendorcap/nativeclient/native-soak.sh',
                     'tools/vendorcap/nativeclient/native_soak.py','vendor/Xray-core/go.mod','vendor/Xray-core/go.sum'):
            path=source/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text('fixture')
        target=self.root/'prepared'
        header=bytearray(20); header[:4]=b'\x7fELF'; header[4:6]=bytes([1,1]); header[18]=8
        for name in ('client','probe'): (self.root/name).write_bytes(header)
        def openssl(*_args,**kwargs):
            for name in ('key.pem','cert.pem'): (kwargs['cwd']/name).write_text('fixture-'+name)
        args=SimpleNamespace(directory=target,source_root=source,lc=self.root/'client',probe=self.root/'probe',
            reference=self.root/'xray',device_json=self.root/'device.json',advertised_host='127.0.0.1',control_port=19892)
        with patch('native_soak.subprocess.check_output',side_effect=[
                'PrivateKey: fixture-private\nPassword (PublicKey): fixture-public\n','Xray fixture\n']), \
                patch('native_soak.subprocess.run',side_effect=openssl):
            prepare(args)
        for name in DEVICE_INPUTS:
            self.assertEqual((target/'device-stage'/name).stat().st_mode & 0o777,0o600,name)

    def test_native_binary_guard_rejects_a_host_executable(self):
        path=self.root/'candidate'
        header=bytearray(20); header[:4]=b'\x7fELF'; header[4:6]=bytes([1,1]); header[18]=8
        path.write_bytes(header); require_mips(path)
        header[4]=2; header[18]=62; path.write_bytes(header)
        with self.assertRaisesRegex(ValueError,'MIPS executable'): require_mips(path)


class LongSoakEvidenceTests(unittest.TestCase):
    long_profile=True
    setUp=NativeSoakEvidenceTests.setUp
    write=staticmethod(NativeSoakEvidenceTests.write)
    lines=staticmethod(NativeSoakEvidenceTests.lines)

    def test_complete_long_profile(self):
        result=analyze(self.root)
        self.assertEqual((result['tcp_cases'],result['udp_echoes']),(2880,46080))
        self.assertIsNone(result['ram_acceptance_limit'])

    def test_short_run_cannot_pass_as_long(self):
        self.write(self.device,'device-state.json',dict(exit_code=0,cleanup_exit=0,roles_completed=2,elapsed_seconds=1005))
        with self.assertRaisesRegex(ValueError,'device did not complete'): analyze(self.root)

    def test_missing_late_burst(self):
        self.lines(self.device,'bursts.jsonl',self.bursts[:-1])
        with self.assertRaisesRegex(ValueError,'incomplete bursts'): analyze(self.root)

    def test_short_monitor_window(self):
        self.lines(self.device,'resources.jsonl',[v for v in self.metrics
            if v['stage']!='active' or v['elapsed']<100])
        with self.assertRaisesRegex(ValueError,'monitor gap|window incomplete'): analyze(self.root)


if __name__=='__main__': unittest.main()
