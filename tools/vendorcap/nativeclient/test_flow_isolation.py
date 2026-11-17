import hashlib
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import Mock, call, patch

import flow_isolation as flow
from checkpoint_process import digest


class IsolationEvidenceTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.root=Path(directory.name)
        for name in flow.INPUTS: (self.root/name).write_text('fixture '+name)
        self.plan=dict(schema='flow-isolation-v1',rounds=1,healthy_reply_seconds=5,quiet_recovery_seconds=3,
                       inputs={n:digest(self.root/n) for n in flow.INPUTS})
        self.result=dict(completed=True,cleanup_exit=0,errors=[],capture=dict(dropped=0,packets=500),
                         server_exit=0,server_sha256=self.plan['inputs']['xray'],cases=[],journal=[])
        self.wire=[]; seq=0
        for index,(fault,role) in enumerate((f,r) for f in flow.base.FAULTS for r in flow.base.ROLES):
            stamp=(100+index*20)*10**9
            peers=dict(zip(('victim',*flow.CHANNELS),range(40000+index*10,40004+index*10)))
            case=dict(round=1,fault=fault,role=role,peers=peers,alive=True,neighbors_alive=True,pump_errors=[],
                      client_exit=0 if role=='ref' else -15,
                      binary_sha256=self.plan['inputs']['xray' if role=='ref' else 'lc-tunnel'],
                      injection_ns=stamp,injection_end_ns=stamp+1000000,observation_end_ns=stamp+10*10**9,
                      victim=[],background=[])
            if role=='lc4':
                (self.root/f'1-{fault}-lc4.log').write_text(''.join(f'worker {n} of 4, pid {n+100}\n' for n in range(1,5)))
            for cindex,channel in enumerate(('victim',*flow.CHANNELS)):
                stages=('seed','after','recovered') if channel=='victim' else ('seed','pump','pump')
                offsets=(-2*10**9,10**8,4*10**9) if channel=='victim' else (-2*10**9,-10**9,10**9)
                for stage,offset in zip(stages,offsets):
                    seq+=1
                    data=(b'LCUDP1' if channel in ('victim','udp') else b'LCISO1')+struct.pack('!Q',seq)+bytes([seq])*32
                    sha=hashlib.sha256(data).hexdigest(); port=32000+index*10+cindex
                    row=dict(channel=channel,stage=stage,sequence=seq,sha256=sha,source_port=port,outcome='echo',
                             start_ns=stamp+offset,end_ns=stamp+offset+1000000,
                             start_mono_ns=stamp+offset,end_mono_ns=stamp+offset+1000000)
                    case['victim' if channel=='victim' else 'background'].append(row)
                    if channel in ('victim','udp'):
                        listener=19600 if role=='ref' else 19601
                        for a,b in ((port,listener),(41000,29623),(29623,41000),(listener,port)):
                            self.wire.append(dict(protocol=17,source='127.0.0.1',destination='127.0.0.1',
                                                  time_ns=row['start_ns'],sport=a,dport=b,sequence=seq,sha256=sha))
                        self.result['journal'].append(dict(channel='udp',sha256=sha))
                    else:
                        self.result['journal'].append(dict(channel=channel,sha256=sha,connection=index*10+cindex))
            if fault!='none':
                self.wire.append(dict(protocol=6,source='127.0.0.1',destination='127.0.0.1',time_ns=stamp+500000,
                                      sport=29601,dport=peers['victim'],flags=1 if fault=='fin' else 4))
            self.result['cases'].append(case)

    def analyze(self):
        (self.root/'plan.json').write_text(json.dumps(self.plan))
        self.result['plan_sha256']=digest(self.root/'plan.json')
        (self.root/'result.json').write_text(json.dumps(self.result))
        with patch.object(flow.base,'packets',return_value=iter(self.wire)):
            return flow.analyze(self.root)

    def test_complete_evidence(self):
        self.assertEqual(self.analyze()['cases'],9)

    def test_missing_progress(self):
        self.result['cases'][0]['background']=[r for r in self.result['cases'][0]['background']
                                               if not (r['channel']=='tls' and r['start_ns']>100*10**9)]
        with self.assertRaisesRegex(ValueError,'progress'): self.analyze()

    def test_reconnect(self):
        self.result['journal'][-1]['connection']=99999
        with self.assertRaisesRegex(ValueError,'reconnected'): self.analyze()

    def test_neighbor_reset(self):
        self.wire.append(dict(protocol=6,source='127.0.0.1',destination='127.0.0.1',sport=29601,
                              dport=self.result['cases'][0]['peers']['tls'],time_ns=101*10**9,flags=4))
        with self.assertRaisesRegex(ValueError,'neighbor transport'): self.analyze()

    def test_missing_injection(self):
        self.wire=[r for r in self.wire if r['protocol']!=6]
        with self.assertRaisesRegex(ValueError,'injected close'): self.analyze()

    def test_missing_wire_echo(self):
        self.wire.pop(3)
        with self.assertRaisesRegex(ValueError,'echo evidence'): self.analyze()

    def test_missing_backend(self):
        self.result['journal'].pop()
        with self.assertRaisesRegex(ValueError,'backend receipt'): self.analyze()

    def test_partial_run(self):
        self.result['cases'].pop()
        with self.assertRaisesRegex(ValueError,'coverage'): self.analyze()

    def test_capture_loss(self):
        self.result['capture']['dropped']=1
        with self.assertRaisesRegex(ValueError,'capture'): self.analyze()

    def test_changed_helper(self):
        (self.root/'udp_lifecycle.py').write_text('changed')
        with self.assertRaisesRegex(ValueError,'input changed'): self.analyze()

    def test_shared_transport(self):
        self.result['cases'][0]['peers']['tls']=self.result['cases'][0]['peers']['plain']
        with self.assertRaisesRegex(ValueError,'independent'): self.analyze()

    def test_premature_timeout(self):
        case=self.result['cases'][3]
        case['victim'][1]['outcome']='timeout'
        with self.assertRaisesRegex(ValueError,'deadline'): self.analyze()

    def test_neighbor_timeout(self):
        self.result['cases'][0]['background'][-1]['outcome']='timeout'
        with self.assertRaisesRegex(ValueError,'mandatory'): self.analyze()

    def test_missing_worker(self):
        (self.root/'1-none-lc4.log').write_text('worker 1 of 4, pid 100\n')
        with self.assertRaisesRegex(ValueError,'worker'): self.analyze()


class StreamReaderTests(unittest.TestCase):
    def test_shared_deadline(self):
        connection=Mock()
        connection.recv.side_effect=[b'a',b'bc']
        with patch.object(flow.time,'monotonic',side_effect=[2,4]):
            self.assertEqual(flow.exact(connection,3,deadline=5),b'abc')
        self.assertEqual(connection.settimeout.call_args_list,[call(3),call(1)])

    def test_expired_deadline(self):
        with patch.object(flow.time,'monotonic',return_value=6):
            with self.assertRaisesRegex(ValueError,'deadline'): flow.exact(Mock(),1,deadline=5)

    def test_partial_reads(self):
        left,right=socket.socketpair()
        with left,right:
            left.sendall(b'abc'); self.assertEqual(flow.exact(right,3),b'abc')

    def test_eof(self):
        left,right=socket.socketpair()
        with right:
            left.sendall(b'a'); left.close()
            with self.assertRaisesRegex(ValueError,'EOF'): flow.exact(right,2)


if __name__=='__main__': unittest.main()
