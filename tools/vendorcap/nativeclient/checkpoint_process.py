"""Owned processes for disposable checkpoint stands; no system-wide cleanup."""
import hashlib
from contextlib import contextmanager
import os
from pathlib import Path
import signal
import subprocess
import time

from analyze_network import require


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@contextmanager
def termination_guard():
    """Unwind runner finally blocks on termination, then restore caller handlers."""
    def terminate(number, _frame):
        raise SystemExit(128 + number)

    previous = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGHUP)}
    try:
        for number in previous:
            signal.signal(number, terminate)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


class Processes:
    def __init__(self, root):
        self.root = Path(root)
        self.children = []
        self.logs = []
        self.stopped = set()
        self.cleanup_failed = False

    def alive(self, *children):
        require(all(child.poll() is None for child in children), 'checkpoint process exited early')

    def start(self, args, log, port, expected, extra_env=None):
        env = dict(os.environ, SSL_CERT_FILE=str(self.root/'ca.pem'), DEST_TIMING='1')
        env.update(extra_env or {})
        handle = (self.root/log).open('w')
        self.logs.append(handle)
        child = subprocess.Popen(args, cwd=self.root, stdout=handle, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
        self.children.append(child)
        until = time.monotonic() + 10
        while time.monotonic() < until:
            self.alive(child)
            inodes = set()
            for table in ('tcp', 'tcp6'):
                for row in Path('/proc/net', table).read_text().splitlines()[1:]:
                    fields = row.split()
                    if fields[3] == '0A' and int(fields[1].split(':')[1], 16) == port:
                        inodes.add('socket:['+fields[9]+']')
            try:
                sockets = {os.readlink(fd) for fd in Path(f'/proc/{child.pid}/fd').iterdir()}
            except FileNotFoundError:
                sockets = set()
            if inodes & sockets:
                # Verify the running image after this child owns its ready
                # listener, rather than sampling /proc during startup.
                require(digest(f'/proc/{child.pid}/exe') == expected, 'executed binary hash differs')
                return child
            time.sleep(0.05)
        raise RuntimeError('owned checkpoint listener did not become ready')

    def stop(self, child):
        if child in self.stopped:
            return child.returncode
        deadline = time.monotonic() + 15
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=max(.001, deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                self.kill_failed_group(child)
        # Parent exit triggers PDEATHSIG; workers can still be exiting or awaiting reaping.
        # Require disappearance of the entire owned group, including zombies, within the same bound.
        while True:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                self.stopped.add(child)
                return child.returncode
            if time.monotonic() >= deadline:
                self.kill_failed_group(child)
            time.sleep(.01)

    def kill_failed_group(self, child):
        self.cleanup_failed = True
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        raise RuntimeError('checkpoint process group required SIGKILL')

    def close(self):
        failed = self.cleanup_failed
        for child in reversed(self.children):
            try:
                failed |= self.stop(child) not in (0, -signal.SIGTERM)
            except Exception:
                failed = True
        for handle in self.logs:
            handle.close()
        return int(failed)
