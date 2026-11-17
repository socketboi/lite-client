import json
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest


@unittest.skipUnless(sys.platform=='linux','native proc/group fixture requires Linux')
class SoakProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory()
        cls.probe=Path(cls.directory.name)/'probe'
        source=Path(__file__).with_name('soak_probe.c')
        subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(cls.probe)],check=True)

    @classmethod
    def tearDownClass(cls): cls.directory.cleanup()

    def setUp(self):
        script='''import socket,sys,threading
tcp=socket.socket(); tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); tcp.bind(('127.0.0.1',19971)); tcp.listen()
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.bind(('127.0.0.1',19601)); udp.settimeout(.1)
mode='echo'; extra=None; stop=threading.Event()
def echo():
 while not stop.is_set():
  try: data,peer=udp.recvfrom(65535)
  except socket.timeout: continue
  if mode=='drop': continue
  if mode=='bad': data=bytes([data[0]^1])+data[1:]
  udp.sendto(data,peer)
thread=threading.Thread(target=echo); thread.start(); print('READY',flush=True)
try:
 for line in sys.stdin:
  command=line.strip()
  if command=='stop': break
  if command=='extra': extra=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); extra.bind(('127.0.0.1',0))
  elif command=='close': extra.close(); extra=None
  else: mode=command
  print('OK',flush=True)
finally:
 stop.set(); thread.join(); udp.close(); tcp.close()
 if extra is not None: extra.close()
'''
        self.child=subprocess.Popen([sys.executable,'-u','-c',script],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
        self.addCleanup(self.close_child)
        self.assertEqual(self.child.stdout.readline().strip(),'READY')

    def close_child(self):
        try: self.child.communicate('stop\n',timeout=5)
        except subprocess.TimeoutExpired:
            self.child.kill(); self.child.communicate(); raise

    def command(self,text):
        self.child.stdin.write(text+'\n'); self.child.stdin.flush()
        self.assertEqual(self.child.stdout.readline().strip(),'OK')

    def test_quiescence_rejects_an_owned_session_socket_then_accepts_its_close(self):
        def check(): return subprocess.run([str(self.probe),'check',str(self.child.pid),'1'],capture_output=True,text=True)
        good=check(); self.assertEqual(good.returncode,0,good.stderr)
        self.command('extra')
        active=check(); self.assertEqual(active.returncode,1)
        self.assertEqual(json.loads(active.stdout)['other_socket_fds'],1)
        self.command('close'); self.assertEqual(check().returncode,0)

    def test_udp_echo_checks_all_64_payloads(self):
        result=subprocess.run([str(self.probe),'udp','19601'],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),dict(echoes=64,bytes=8192))

    def test_default_bind_stays_loopback_and_explicit_target_uses_route_selection(self):
        self.command('drop')
        for target, address in [([], '127.0.0.1'), (['127.0.0.1'], '0.0.0.0')]:
            with self.subTest(target=target):
                child = subprocess.Popen([str(self.probe), 'udp', '19601', *target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    bound = []
                    deadline = time.monotonic() + 2
                    while len(bound) != 4 and time.monotonic() < deadline:
                        inodes = set()
                        for fd in Path(f'/proc/{child.pid}/fd').iterdir():
                            try:
                                link = fd.readlink().as_posix()
                            except FileNotFoundError:
                                continue
                            if link.startswith('socket:['): inodes.add(link[8:-1])
                        bound = [line.split()[1].split(':')[0] for line in Path('/proc/net/udp').read_text().splitlines()[1:]
                                 if line.split()[9] in inodes]
                        if len(bound) != 4: time.sleep(.01)
                    expected = f'{int.from_bytes(socket.inet_aton(address), sys.byteorder):08X}'
                    self.assertEqual(bound, [expected] * 4)
                finally:
                    child.terminate()
                    child.communicate(timeout=3)

    def test_corrupted_echo_is_rejected(self):
        self.command('bad')
        result=subprocess.run([str(self.probe),'udp','19601'],capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)

    def test_explicit_nondefault_ipv4_target(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.2', 0))
            server.settimeout(2)
            errors = []
            def echo():
                try:
                    for _ in range(64):
                        data, peer = server.recvfrom(65535)
                        server.sendto(data, peer)
                except Exception as error:
                    errors.append(error)
            thread = threading.Thread(target=echo)
            thread.start()
            try:
                result = subprocess.run([str(self.probe), 'udp', str(server.getsockname()[1]), '127.0.0.2'],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), dict(echoes=64, bytes=8192))
            finally:
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

    def test_invalid_target_and_port_fail_before_network_io(self):
        for port, host in [('0', '127.0.0.1'), ('65536', '127.0.0.1'), ('1junk', '127.0.0.1'),
                           ('4294986897', '127.0.0.1'), ('19601', 'invalid'), ('19601', '::1')]:
            with self.subTest(port=port, host=host):
                result = subprocess.run([str(self.probe), 'udp', port, host], capture_output=True, timeout=2)
                self.assertEqual(result.returncode, 2)

    def test_missing_udp_reply_is_rejected(self):
        self.command('drop')
        result=subprocess.run([str(self.probe),'udp','19601'],capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)

    def test_explicit_timeout_is_applied_to_the_real_socket(self):
        self.command('drop')
        start = time.monotonic()
        result = subprocess.run([str(self.probe), 'udp', '19601', '127.0.0.1', '1'], capture_output=True, timeout=4)
        elapsed = time.monotonic() - start
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'step=receive echoes=0', result.stderr)
        self.assertGreaterEqual(elapsed, .8)
        self.assertLess(elapsed, 3)

    def test_invalid_timeout_fails_before_network_io(self):
        for value in ('0', '61', '1junk', '4294967297', '-1', ''):
            with self.subTest(value=value):
                result = subprocess.run([str(self.probe), 'udp', '19601', '127.0.0.1', value], capture_output=True, timeout=2)
                self.assertEqual(result.returncode, 2)


if __name__=='__main__': unittest.main()
