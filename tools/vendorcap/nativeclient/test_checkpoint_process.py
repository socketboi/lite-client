from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from analyze_network import EvidenceError
from checkpoint_process import Processes, digest


@unittest.skipUnless(sys.platform == 'linux', 'checkpoint processes require Linux /proc')
class OwnedProcessTests(unittest.TestCase):
    def group_shutdown(self, mode):
        helper=Path(__file__).resolve().parent
        script='''
import ctypes, os, signal, subprocess, sys, threading, time
from checkpoint_process import Processes
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)==0  # Isolated test subreaper, not runner policy.
code="""
import ctypes, os, signal, sys, time
r,w=os.pipe()
pid=os.fork()
if pid:
    os.close(w); assert os.read(r,1)==b'R'; os.close(r)
    print(pid,flush=True)
else:
    os.close(r)
    def finish(*_): time.sleep(.3); os._exit(0)
    signal.signal(signal.SIGTERM,finish if sys.argv[1]=='delay' else signal.SIG_IGN)
    assert ctypes.CDLL(None).prctl(1,signal.SIGTERM,0,0,0)==0
    os.write(w,b'R'); os.close(w)
while True: time.sleep(1)
"""
parent=subprocess.Popen([sys.executable,'-c',code,sys.argv[1]],stdout=subprocess.PIPE,
                        text=True,start_new_session=True)
worker=int(parent.stdout.readline())
done=threading.Event()
def reap():
    while not done.is_set():
        try:
            if os.waitpid(worker,os.WNOHANG)[0]==worker: done.set(); return
        except ChildProcessError: pass
        time.sleep(.005)
reaper=threading.Thread(target=reap); reaper.start()
processes=Processes('.')
processes.children.append(parent)
try:
    began=time.monotonic()
    try: result=processes.stop(parent)
    except RuntimeError:
        assert sys.argv[1]=='stubborn'
        assert processes.close()==1, 'forced kill must remain a cleanup failure'
    else:
        assert sys.argv[1]=='delay', 'live worker was accepted as cleaned up'
        assert result==-signal.SIGTERM
        assert time.monotonic()-began>=.25, 'returned before delayed worker exit'
        assert done.wait(1), 'worker was not reaped'
        assert processes.close()==0
    try: os.killpg(parent.pid,0)
    except ProcessLookupError: pass
    else: raise AssertionError('owned process group remains')
finally:
    try: os.killpg(parent.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    parent.wait(timeout=5)
    done.wait(3); done.set(); reaper.join(timeout=2); parent.stdout.close()
'''
        result=subprocess.run([sys.executable,'-c',script,mode],cwd=helper,
                              capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_stop_waits_for_delayed_orphan_worker_and_reaping(self):
        self.group_shutdown('delay')

    def test_surviving_worker_is_killed_and_cleanup_fails(self):
        self.group_shutdown('stubborn')

    def test_wrong_executable_is_rejected_and_owned_child_is_reaped(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
            reservation.close()
            processes = Processes(directory)
            code = ('import socket,time; s=socket.socket(); '
                    f's.bind(("127.0.0.1", {port})); s.listen(); time.sleep(30)')
            try:
                with self.assertRaisesRegex(EvidenceError, 'binary hash'):
                    processes.start([sys.executable, '-c', code], 'child.log', port, '0'*64)
            finally:
                self.assertEqual(processes.close(), 0)
            self.assertIsNotNone(processes.children[0].poll())

    def test_pre_ready_executable_observation_does_not_reject_the_ready_image(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as reservation:
            root = Path(directory)
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
            reservation.close()
            expected = digest(sys.executable)
            processes = Processes(root)
            code = ('import socket,time; from pathlib import Path; time.sleep(.2); '
                    'Path("image-ready").write_text("ready"); s=socket.socket(); '
                    f's.bind(("127.0.0.1", {port})); s.listen(); time.sleep(30)')
            observations = []

            def visible_image(path):
                ready = (root/'image-ready').exists()
                observations.append(ready)
                return digest(path) if ready else 'pre-ready-image'

            try:
                with patch('checkpoint_process.digest', side_effect=visible_image):
                    child = processes.start([sys.executable, '-c', code], 'child.log', port, expected)
                self.assertIsNone(child.poll())
                self.assertEqual(observations, [True])
            finally:
                self.assertEqual(processes.close(), 0)

    def test_unrelated_listener_is_not_readiness_and_survives_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            port = listener.getsockname()[1]
            processes = Processes(directory)
            with patch('checkpoint_process.time.monotonic', side_effect=[0, 0, 11]):
                with self.assertRaisesRegex(RuntimeError, 'owned checkpoint listener'):
                    processes.start([sys.executable, '-c', 'import time; time.sleep(30)'],
                                    'child.log', port, digest(sys.executable))
            self.assertEqual(processes.close(), 0)
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                pass

    def test_sigterm_unwinds_cleanup_and_leaves_no_child(self):
        helper = Path(__file__).with_name('checkpoint_process.py').parent
        script = '''
import os, signal, socket, sys, time
from pathlib import Path
from checkpoint_process import Processes, digest, termination_guard
root = Path(sys.argv[1])
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
processes = Processes(root)
with termination_guard():
    try:
        code = ('import socket,time; s=socket.socket(); '
                f's.bind(("127.0.0.1", {port})); s.listen(); time.sleep(30)')
        child = processes.start([sys.executable, '-c', code], 'child.log',
                                port, digest(sys.executable))
        ready = root/'ready.tmp'
        ready.write_text(str(child.pid))
        ready.replace(root/'ready')
        while True:
            time.sleep(1)
    finally:
        (root/'cleanup').write_text(str(processes.close()))
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = subprocess.Popen([sys.executable, '-c', script, directory], cwd=helper)
            try:
                until = time.monotonic()+10
                while not (root/'ready').exists() and runner.poll() is None and time.monotonic() < until:
                    time.sleep(0.02)
                self.assertTrue((root/'ready').exists(), 'runner failed to start its owned listener')
                child_pid = int((root/'ready').read_text())
                runner.send_signal(signal.SIGTERM)
                self.assertEqual(runner.wait(timeout=10), 143)
                self.assertEqual((root/'cleanup').read_text(), '0')
                self.assertFalse(Path(f'/proc/{child_pid}').exists())
            finally:
                if runner.poll() is None:
                    runner.terminate()
                    try:
                        runner.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        runner.kill()
                        runner.wait()


if __name__ == '__main__':
    unittest.main()
