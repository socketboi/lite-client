"""Exercise real Linux socket-inode ownership and rc.common callback results."""
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.init=Path(os.environ.get('LC_INIT','package/files/lite-client.init')).resolve()
        self.executable=os.readlink(f'/proc/{os.getpid()}/exe')
        self.tcp=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        self.tcp.bind(('::1',0)); self.tcp.listen()
        self.udp=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); self.udp.bind(('::1',0))
        self.addCleanup(self.tcp.close); self.addCleanup(self.udp.close)
        self.poll=select.epoll(); self.addCleanup(self.poll.close)
        self.poll.register(self.tcp,select.EPOLLIN); self.poll.register(self.udp,select.EPOLLIN)

    def shell(self,body,expected,program=None):
        env=dict(os.environ,TEST_INIT=str(self.init),TEST_PROGRAM=program or self.executable)
        result=subprocess.run(['sh','-c','. "$TEST_INIT"; PROG=$TEST_PROGRAM; logger() { :; }; '+body],
                              env=env,capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,expected,result.stdout+result.stderr)

    def owned(self,pid,port,protocol,expected,program=None):
        self.shell(f'lc_listener_owned {pid} {port} {protocol}',expected,program)

    def child(self,body):
        child=subprocess.Popen([sys.executable,'-c',body],stdout=subprocess.PIPE,text=True)
        def cleanup():
            child.terminate(); child.wait(timeout=5); child.stdout.close()
        self.addCleanup(cleanup)
        return child

    def test_parent_tcp(self):
        self.owned(os.getpid(),self.tcp.getsockname()[1],'tcp',0)

    def test_parent_udp(self):
        self.owned(os.getpid(),self.udp.getsockname()[1],'udp',0)

    def test_wrong_executable(self):
        self.owned(os.getpid(),self.tcp.getsockname()[1],'tcp',1,'/unrelated/client')

    def test_same_executable_unrelated_pid(self):
        child=self.child('import time; print("ready",flush=True); time.sleep(30)')
        self.assertEqual(child.stdout.readline().strip(),'ready')
        self.owned(child.pid,self.tcp.getsockname()[1],'tcp',1)

    def test_direct_worker_owns_listeners(self):
        child=self.child('''import socket,json,time,select
t=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); t.bind(('::1',0)); t.listen()
u=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); u.bind(('::1',0))
p=select.epoll(); p.register(t,select.EPOLLIN); p.register(u,select.EPOLLIN)
print(json.dumps([t.getsockname()[1],u.getsockname()[1]]),flush=True)
time.sleep(30)
''')
        tcp,udp=json.loads(child.stdout.readline())
        self.owned(os.getpid(),tcp,'tcp',0)
        self.owned(os.getpid(),udp,'udp',0)

    def test_bound_tcp_is_not_listening(self):
        bound=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); self.addCleanup(bound.close)
        bound.bind(('::1',0))
        self.owned(os.getpid(),bound.getsockname()[1],'tcp',1)

    def test_unpolled_listener_is_not_ready(self):
        self.poll.unregister(self.tcp)
        self.owned(os.getpid(),self.tcp.getsockname()[1],'tcp',1)

    def test_unpolled_udp_is_not_ready(self):
        self.poll.unregister(self.udp)
        self.owned(os.getpid(),self.udp.getsockname()[1],'udp',1)

    def test_stopped_worker_is_not_ready_until_resumed(self):
        child=self.child('''import socket,time,select
t=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); t.bind(('::1',0)); t.listen()
p=select.epoll(); p.register(t,select.EPOLLIN)
print(t.getsockname()[1],flush=True); time.sleep(30)
''')
        port=int(child.stdout.readline())
        self.owned(os.getpid(),port,'tcp',0)
        os.kill(child.pid,signal.SIGSTOP)
        self.addCleanup(os.kill,child.pid,signal.SIGCONT)
        _,status=os.waitpid(child.pid,os.WUNTRACED)
        self.assertTrue(os.WIFSTOPPED(status))
        self.owned(os.getpid(),port,'tcp',1)
        os.kill(child.pid,signal.SIGCONT)
        self.owned(os.getpid(),port,'tcp',0)

    def test_all_native_workers_crash_without_false_readiness(self):
        binary=Path(os.environ['LC_TUNNEL_HY0']).resolve()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'crash.c'
            source.write_text('#include <signal.h>\n#include <unistd.h>\n'
                              'int epoll_create1(int flags) { (void)flags; kill(getpid(),SIGKILL); return -1; }\n')
            library=root/'crash.so'
            subprocess.run(['cc','-shared','-fPIC',str(source),'-o',str(library)],check=True,capture_output=True)
            port=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
            port.bind(('::1',0)); number=port.getsockname()[1]; port.close()
            command=[str(binary),str(Path('package/files/fingerprint.fpt').resolve()),
                     'offline.invalid','443','config.test','00'*32,'0123abcd',
                     '00000000-0000-4000-8000-000000000001',str(number),'-t','127.0.0.1:80','-w','4']
            with (root/'native.log').open('wb') as log:
                child=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,
                                       env=dict(os.environ,LD_PRELOAD=str(library),LC_EVENT_DIR=str(root)))
                try:
                    until=time.monotonic()+3
                    while time.monotonic()<until:
                        text=(root/'native.log').read_text()
                        if text.count('ended on a signal')==4:
                            break
                        time.sleep(0.01)
                    self.assertIsNone(child.poll(),text)
                    self.assertEqual(text.count('ended on a signal'),4,text)
                    records=[__import__('json').loads(path.read_text()) for path in root.glob('worker-*.json')]
                    self.assertEqual(len(records),4)
                    self.assertEqual(len({record['id'] for record in records}),4)
                    self.assertTrue(all(record['exitSignal']==signal.SIGKILL and record['exitCode']==0 for record in records))
                    self.assertTrue(all(record['version'] for record in records))
                    self.assertTrue(all(record['plane']=='reality' and record['clientId']==0 for record in records))
                    self.assertFalse(Path(f'/proc/{child.pid}/task/{child.pid}/children').read_text().strip())
                    self.owned(child.pid,number,'tcp',1,str(binary))
                finally:
                    if child.poll() is None:
                        os.killpg(child.pid,signal.SIGKILL)
                    child.wait(timeout=5)

    def test_start_refusal_survives_callback(self):
        self.shell('LC_START_RESULT=1; LC_WAIT_READY=0; service_started',1)

    def test_disabled_callback(self):
        self.shell('LC_START_RESULT=0; LC_WAIT_READY=0; service_started',0)

    def test_not_ready_preserves_interception(self):
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/'bad-cleanup'
            self.shell('LC_START_RESULT=0; LC_WAIT_READY=1; LC_READY_TCP=19099; LC_READY_UDP=19098; '
                       'lc_wait_ready() { return 1; }; lc_rules_down() { echo removed > "'+str(marker)+'"; }; service_started',1)
            self.assertFalse(marker.exists(),'readiness failure must keep fail-closed rules')


if __name__=='__main__': unittest.main()
