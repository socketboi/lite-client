"""Test explicit config loading against the unmodified pinned Xray executable."""

from contextlib import contextmanager
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from threading import Thread
import time
import unittest


LAUNCHER = Path(__file__).resolve().with_name("lc-xray")
INIT_SCRIPT = LAUNCHER.parent / "files" / "lite-client-xray.init"
REFERENCE = os.environ["XRAY_TEST_CORE"]
LOCAL = "127.0.0.1"
UUID = "96a63a6d-6864-4bc8-8753-256a8399aa16"


def free_port():
    with socket.socket() as listener:
        listener.bind((LOCAL, 0))
        return listener.getsockname()[1]


class Responder(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"received through the configured outbound")

    def log_message(self, *_args):
        pass


class XrayRuntimeTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.command = ["sh", str(LAUNCHER), "--core", REFERENCE]

    def config(self, name, content):
        path = self.directory / name
        path.write_text(json.dumps(content))
        return path

    def check(self, *args, env=None):
        return subprocess.run([*self.command, "check", *args], capture_output=True, text=True,
                              timeout=10, env=env)

    def test_requires_explicit_files_and_ignores_implicit_sources(self):
        self.assertNotEqual(self.check("--confdir", "").returncode, 0)
        self.assertNotEqual(self.check("--confdir", self.directory).returncode, 0)
        self.assertNotEqual(self.check().returncode, 0)
        self.assertNotEqual(self.check("https://example.test/secret.json").returncode, 0)
        extra = self.directory / "implicit"
        extra.mkdir()
        (extra / "00-invalid.json").write_text("{]")
        valid = self.config("valid.json", {"outbounds": [{"protocol": "freedom"}]})
        env = {**os.environ, "XRAY_LOCATION_CONFDIR": str(extra), "xray.location.confdir": str(extra)}
        result = self.check(valid, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        valid.write_text("{]")
        self.assertNotEqual(self.check(valid).returncode, 0)

    def test_all_inbound_protocols_load_with_their_upstream_settings(self):
        settings = {
            "tunnel": {"address": LOCAL, "port": 80},
            "http": {},
            "shadowsocks": {"method": "aes-128-gcm", "password": "fixture"},
            "socks": {"udp": True},
            "trojan": {"clients": [{"password": "fixture"}]},
            "vless": {"decryption": "none", "clients": [{"id": UUID}]},
            "vmess": {"clients": [{"id": UUID}]},
            "wireguard": {"secretKey": "12" * 32, "noKernelTun": True},
            "hysteria": {"version": 2, "clients": [{"auth": "fixture", "email": "fixture"}]},
            "masque": {"address": ["10.224.0.1/24"], "clients": [{"pass": "fixture", "email": "fixture"}]},
            "tun": {"name": "xray-fixture", "mtu": 1500},
        }
        certificate = self.directory / "certificate.pem"
        key = self.directory / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-out", str(certificate), "-keyout", str(key),
        ], check=True, capture_output=True, timeout=10)
        for protocol, options in settings.items():
            with self.subTest(protocol=protocol):
                inbound = {"tag": "in", "protocol": protocol, "settings": options}
                if protocol != "tun":
                    inbound.update(port=31234, listen=LOCAL)
                if protocol in {"hysteria", "masque"}:
                    inbound["streamSettings"] = {
                        "network": protocol,
                        "security": "tls",
                        "tlsSettings": {
                            "certificates": [{"certificateFile": str(certificate), "keyFile": str(key)}],
                        },
                    }
                path = self.config("inbound.json", {"inbounds": [inbound], "outbounds": [{"protocol": "freedom"}]})
                result = self.check(path)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_service_preflight_leaves_a_running_service_untouched_on_error(self):
        wrapper = self.directory / "launcher"
        wrapper.write_text('#!/bin/sh\nexec sh "$FIXTURE_LAUNCHER" --core "$XRAY_TEST_CORE" "$@"\n')
        wrapper.chmod(0o700)
        config = self.config("profile.json", {"outbounds": [{"protocol": "freedom"}]})
        # rc.common commits the registration after start_service returns.
        shell = """
            extra_command() { :; }
            config_load() { [ "$1" = lite-client-xray ]; }
            config_get_bool() { enabled=1; }
            config_get() { directory=$FIXTURE_DIRECTORY; }
            procd_open_instance() { printf 'instance %s\\n' "$1"; }
            procd_set_param() { printf '%s\\n' "$*"; }
            procd_append_param() { printf '%s\\n' "$*"; }
            procd_close_instance() { :; }
            . "$1"
            LAUNCHER=$2
            start_service
            printf 'registered\\n'
        """
        command = ["sh", "-c", shell, "test", INIT_SCRIPT, wrapper]
        env = {**os.environ, "FIXTURE_DIRECTORY": str(self.directory), "FIXTURE_LAUNCHER": str(LAUNCHER)}
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"file {config}\n", result.stdout)
        self.assertIn("registered\n", result.stdout)

        config.write_text("{]")
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("/etc/init.d/lite-client-xray check", result.stderr)

    @contextmanager
    def running(self, *args):
        process = subprocess.Popen([*self.command, "run", *args], stdout=subprocess.DEVNULL)
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def test_multiple_files_inbounds_and_routed_outbounds(self):
        backend = ThreadingHTTPServer((LOCAL, 0), Responder)
        thread = Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(backend.server_close)
        self.addCleanup(backend.shutdown)
        with socket.socket() as held:
            held.bind((LOCAL, 0))
            allowed = held.getsockname()[1]
            denied = free_port()
        self.config("10 inbounds.json", {
            "inbounds": [
                {"listen": LOCAL, "port": allowed, "tag": "allowed", "protocol": "http"},
                {"listen": LOCAL, "port": denied, "tag": "denied", "protocol": "http"},
            ],
            "routing": {"rules": [{"inboundTag": ["allowed"], "outboundTag": "block"}]},
        })
        routing = self.config("20-routing.jsonc", {
            "outbounds": [{"tag": "block", "protocol": "blackhole"}, {"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"inboundTag": ["allowed"], "outboundTag": "direct"}]},
        })
        routing.write_text("// The route is defined in a separate file.\n" + routing.read_text())
        with self.running("--confdir", self.directory) as process:
            for port in (allowed, denied):
                deadline = time.monotonic() + 5
                while True:
                    try:
                        with socket.create_connection((LOCAL, port), timeout=0.25):
                            break
                    except OSError:
                        if time.monotonic() >= deadline or process.poll() is not None:
                            self.fail(f"Xray listener {port} did not start (exit {process.poll()})")
                        time.sleep(0.05)
            target = f"http://{LOCAL}:{backend.server_port}/"
            for port in (allowed, denied):
                connection = HTTPConnection(LOCAL, port, timeout=2)
                self.addCleanup(connection.close)
                connection.request("GET", target)
                if port == allowed:
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"received through the configured outbound")
                else:
                    try:
                        response = connection.getresponse()
                    except (OSError, TimeoutError):
                        continue
                    self.assertNotEqual(response.status, 200)


if __name__ == "__main__":
    unittest.main()
