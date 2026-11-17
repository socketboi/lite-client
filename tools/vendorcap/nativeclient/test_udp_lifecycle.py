import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import signal
import time
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from checkpoint_process import Processes, digest
from udp_lifecycle import FAULTS, INPUTS, ROLES, analyze, prepare, wait_udp


class UdpLifecycleEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in INPUTS:
            (self.root/name).write_text('fixture-'+name)
        self.plan = dict(schema='udp-lifecycle-v1',rounds=1,healthy_reply_seconds=5,
                         quiet_recovery_seconds=3,inputs={n:digest(self.root/n) for n in INPUTS})
        self.result = dict(completed=True,cleanup_exit=0,capture_errors=[],capture=dict(packets=300,dropped=0),
            server_exit=0,server_sha256=self.plan['inputs']['xray'],alive_after_cases=True,cases=[])
        self.records = []
        sequence = 0
        for fault in FAULTS:
            for role in ROLES:
                index = len(self.result['cases'])
                source, fresh, peer = 33000+index, 34000+index, 41000+index
                case = dict(round=1,role=role,fault=fault,client_exit=0 if role=='ref' else -15,
                    alive_after_requests=True,binary_sha256=self.plan['inputs']['xray' if role=='ref' else 'lc-tunnel'],
                    requests=[])
                if role == 'lc4':
                    (self.root/f'1-{fault}-lc4.log').write_text(''.join(
                        f'worker {n} of 4, pid {100+n}\n' for n in range(1,5)))
                stamp = (100+index*10)*1000000000
                if fault != 'none':
                    case['injection'] = dict(peer=['127.0.0.1',peer],before_ns=stamp,after_ns=stamp+2000000)
                    tcp = struct.pack('!HHIIBBHHH',29601,peer,0,0,80,1 if fault=='fin' else 4,1024,0,0)
                    self.records.append((stamp+1000000,self.ip(6,tcp)))
                clock = 1000000000
                for stage in ('seed','after_injection','recovered','recovered','recovered','source_rebound','fresh_source'):
                    sequence += 1
                    if stage == 'recovered' and len(case['requests']) == 2:
                        clock += 3000000000
                    payload = b'LCUDP1'+struct.pack('!Q',sequence)+bytes([sequence])*32
                    port = fresh if stage=='fresh_source' else source
                    listener = 19600 if role=='ref' else 19601
                    case['requests'].append(dict(stage=stage,sequence=sequence,source_port=port,
                        sha256=hashlib.sha256(payload).hexdigest(),outcome='echo',
                        required=stage!='after_injection' or fault=='none',start_ns=clock,end_ns=clock+1000000))
                    clock += 2000000
                    for a,b in ((port,listener),(42000,29623),(29623,42000),(listener,port)):
                        udp = struct.pack('!HHHH',a,b,8+len(payload),0)+payload
                        self.records.append((stamp+3000000,self.ip(17,udp)))
                self.result['cases'].append(case)
        self.write()

    @staticmethod
    def ip(protocol, payload):
        address = bytes([127,0,0,1])
        header = struct.pack('!BBHHHBBH4s4s',69,0,20+len(payload),0,0,64,protocol,0,address,address)
        return bytes(12)+b'\x08\x00'+header+payload

    def write(self):
        (self.root/'plan.json').write_text(json.dumps(self.plan))
        self.result['plan_sha256'] = digest(self.root/'plan.json')
        (self.root/'result.json').write_text(json.dumps(self.result))
        with (self.root/'wire.pcap').open('wb') as output:
            output.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
            for stamp,data in self.records:
                output.write(struct.pack('<IIII',stamp//1000000000,stamp%1000000000//1000,len(data),len(data)))
                output.write(data)

    def rejected(self, message):
        self.write()
        with self.assertRaisesRegex(ValueError,message):
            analyze(self.root)

    def test_complete_control_accepts_end_to_end_wire_evidence(self):
        result = analyze(self.root)
        self.assertTrue(result['validated'])
        self.assertEqual((result['cases'],result['requests'],result['echoes']),(9,63,63))

    def test_retained_driver_replays_without_the_checkout(self):
        here = Path(__file__).resolve().parent
        for source,target in (('udp_lifecycle.py','driver.py'),('checkpoint_process.py','checkpoint_process.py'),
                              ('analyze_network.py','analyze_network.py')):
            (self.root/target).write_bytes((here/source).read_bytes())
            self.plan['inputs'][target] = digest(self.root/target)
        self.write()
        command = [sys.executable,str(self.root/'driver.py'),str(self.root),'--analyze']
        env = {**os.environ,'PYTHONPATH':''}
        good = subprocess.run(command,cwd=self.root,env=env,capture_output=True,text=True,timeout=10)
        self.assertEqual(good.returncode,0,good.stderr)
        self.assertTrue(json.loads(good.stdout)['validated'])
        helper = self.root/'analyze_network.py'
        helper.write_bytes(helper.read_bytes()+b'\n# changed helper\n')
        bad = subprocess.run(command,cwd=self.root,env=env,capture_output=True,text=True,timeout=10)
        self.assertNotEqual(bad.returncode,0)
        self.assertIn('input changed',bad.stderr)

    def test_capture_drops_cannot_be_treated_as_network_loss(self):
        self.result['capture']['dropped'] = 1
        self.rejected('run/capture failed')

    def test_input_manifest_cannot_omit_a_binary(self):
        self.plan['inputs'].pop('xray')
        self.rejected('incomplete input manifest')

    def test_changed_binary_is_rejected(self):
        (self.root/'lc-tunnel').write_text('changed')
        with self.assertRaisesRegex(ValueError,'input changed'):
            analyze(self.root)

    def test_changed_frozen_plan_is_rejected(self):
        (self.root/'plan.json').write_text(json.dumps(self.plan)+'\n')
        with self.assertRaisesRegex(ValueError,'frozen plan changed'):
            analyze(self.root)

    def test_false_executable_receipt_is_rejected(self):
        self.result['cases'][0]['binary_sha256'] = '0'*64
        self.rejected('client identity failed')

    def test_failed_server_stop_is_rejected(self):
        self.result['server_exit'] = -9
        self.rejected('server receipt failed')

    def test_missing_case_is_rejected(self):
        self.result['cases'].pop()
        self.rejected('incomplete case coverage')

    def test_recovery_timeout_is_rejected(self):
        self.result['cases'][3]['requests'][2]['outcome'] = 'timeout'
        self.rejected('ordinary/recovered UDP failed')

    def test_early_fault_timeout_is_rejected(self):
        row = self.result['cases'][3]['requests'][1]
        row.update(outcome='timeout',end_ns=row['start_ns']+1)
        self.rejected('premature timeout')

    def test_missing_wire_request_is_rejected(self):
        self.records.pop(0)
        self.rejected('request missing on wire')

    def test_missing_wire_echo_is_rejected(self):
        self.records.pop(3)
        self.rejected('echo lacks end-to-end wire evidence')

    def test_fault_must_be_visible_as_the_requested_tcp_flag(self):
        self.records = [(stamp,data) for stamp,data in self.records if data[23]!=6]
        self.rejected('injected close not observed on wire')

    def test_nonce_sequence_must_match_captured_bytes(self):
        self.result['cases'][0]['requests'][0]['sequence'] = 999
        self.rejected('request missing on wire')

    def test_non_loopback_capture_is_rejected(self):
        stamp,data = self.records[0]
        self.records[0] = (stamp,data[:26]+bytes([192,0,2,1])+data[30:])
        self.rejected('non-loopback traffic')

    def test_truncated_packet_is_rejected(self):
        path = self.root/'wire.pcap'
        path.write_bytes(path.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError,'missing packet bytes'):
            analyze(self.root)

    def test_worker_startup_evidence_is_mandatory(self):
        (self.root/'1-none-lc4.log').write_text('worker 1 of 4, pid 101\n')
        self.rejected('four-worker startup not observed')

    def test_quiet_interval_cannot_be_removed_from_evidence(self):
        rows = self.result['cases'][0]['requests']
        rows[2]['start_ns'] = rows[1]['end_ns']+1
        self.rejected('missing quiet recovery interval')

    def test_run_refuses_a_namespace_with_an_external_interface(self):
        target = self.root/'unexpected-output'
        with patch('udp_lifecycle.Path.iterdir',return_value=[SimpleNamespace(name='lo'),SimpleNamespace(name='eth0')]):
            with self.assertRaisesRegex(ValueError,'Docker --network none'):
                prepare(SimpleNamespace(directory=target))
        self.assertFalse(target.exists())

    @unittest.skipUnless(sys.platform=='linux','process-group UDP readiness requires Linux')
    def test_udp_readiness_checks_workers_instead_of_only_supervisor(self):
        port_file = self.root/'port'
        worker = ('import socket,sys,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
                  's.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1); '
                  's.bind(("127.0.0.1",int(sys.argv[1]))); time.sleep(30)')
        supervisor = '''import pathlib,signal,socket,subprocess,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('127.0.0.1',0)); port=s.getsockname()[1]; s.close()
children=[subprocess.Popen([sys.executable,'-c',sys.argv[2],str(port)]) for _ in range(2)]
def stop(*_): raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
try:
 ready = pathlib.Path(sys.argv[1]+'.tmp')
 ready.write_text(str(port))
 ready.replace(sys.argv[1])
 time.sleep(30)
finally:
 for child in children: child.terminate()
 for child in children: child.wait(timeout=5)
'''
        child = subprocess.Popen([sys.executable,'-c',supervisor,str(port_file),worker],start_new_session=True)
        try:
            until = time.monotonic()+5
            while not port_file.exists() and time.monotonic()<until: time.sleep(.01)
            self.assertTrue(port_file.exists())
            wait_udp(Processes(self.root),child,int(port_file.read_text()),2)
            self.assertIsNone(child.poll())
        finally:
            os.killpg(child.pid,signal.SIGTERM)
            child.wait(timeout=10)


if __name__ == '__main__':
    unittest.main()
