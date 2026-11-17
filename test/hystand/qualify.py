#!/usr/bin/env python3
"""Offline, loopback-only Hysteria compatibility and bounded mixed-load gate."""
import argparse
import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def analyze(root):
    if not __debug__:
        raise RuntimeError('qualification requires assertions enabled')
    result = json.loads((root / 'result.json').read_text())
    assert result['schema'] == 'hysteria-local-qualification-v1'
    assert result['completed'] and not result['errors']
    for name in ('client', 'server', 'driver'):
        assert digest(root / 'inputs' / name) == result[name + '_sha256'], 'frozen input changed'
    assert result['load_seconds'] >= result['scheduled_seconds']
    modes = Counter(case['mode'] for case in result['cases'])
    assert modes['denied'] == modes['bad-pin'] == 1
    assert modes['plain'] == modes['tls'] and modes['plain'] >= 4
    assert modes['udp'] == modes['udp-oversize-drop'] * 5 and modes['udp-oversize-drop'] >= 1
    assert Counter((case['bytes'], case['sha256']) for case in result['cases'] if case['mode'] in ('plain', 'tls')) == \
        Counter((receipt['bytes'], receipt['sha256']) for receipt in result['backend']), 'incomplete backend receipts'
    assert Counter(case['sha256'] for case in result['cases'] if case['mode'] == 'udp') == \
        Counter(result['udp_backend']), 'incomplete UDP receipts'
    assert {row['mode'] for row in result['monitor']} == {'plain', 'tls'}
    expected = {'server': 0, 'plain': -signal.SIGTERM, 'tls': -signal.SIGTERM, 'denied': 1, 'bad-pin': 1}
    assert Counter(row['role'] for row in result['exits']) == Counter(expected.keys())
    assert all(row['exit'] == expected[row['role']] for row in result['exits'])
    return {'completed': True, 'cases': len(result['cases']), 'load_seconds': result['load_seconds']}


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as channel:
        channel.bind(('127.0.0.1', 0))
        return channel.getsockname()[1]


def owns_listener(child, port, table):
    if child.poll() is not None:
        return False
    inodes = set()
    for entry in Path(f'/proc/{child.pid}/fd').iterdir():
        try:
            target = os.readlink(entry)
            if target.startswith('socket:['):
                inodes.add(target[8:-1])
        except FileNotFoundError:
            pass
    return any(int(row.split()[1].split(':')[1], 16) == port and row.split()[9] in inodes
               and (table == 'udp' or row.split()[3] == '0A')
               for family in (table, table + '6')
               for row in Path('/proc/net/' + family).read_text().splitlines()[1:])


async def ready(child, port, table):
    for _ in range(300):
        if owns_listener(child, port, table):
            return
        if child.poll() is not None:
            raise RuntimeError(f'process exited before owning {table} listener: {child.returncode}')
        await asyncio.sleep(.05)
    raise TimeoutError('owned listener did not become ready')


class Echo(asyncio.DatagramProtocol):
    def __init__(self, journal):
        self.journal = journal

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.journal.append(hashlib.sha256(data).hexdigest())
        self.transport.sendto(data, address)


async def run(args):
    if not __debug__:
        raise RuntimeError('qualification requires assertions enabled')
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / 'inputs').mkdir()
    for name, source in [('client', args.client), ('server', args.server), ('driver', Path(__file__))]:
        shutil.copy2(source, root / 'inputs' / name)
    args.client, args.server = root / 'inputs/client', root / 'inputs/server'
    children, logs, receipts, udp_receipts, monitors, cases = [], [], [], [], [], []
    names = {}
    errors, exits = [], []
    backends, datagram = [], None
    started = time.monotonic()
    load_seconds = 0

    def start(command, name):
        handle = (root / (name + '.log')).open('w')
        logs.append(handle)
        child = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
        children.append(child)
        names[child.pid] = name
        assert digest(f'/proc/{child.pid}/exe') == digest(command[0]), 'executed binary mismatch'
        return child

    async def echo(reader, writer):
        try:
            size = struct.unpack('!I', await reader.readexactly(4))[0]
            assert 0 < size <= 8 * 1024 * 1024
            count, sha = 0, hashlib.sha256()
            while count < size:
                data = await reader.read(min(32768, size - count))
                assert data, 'truncated upload'
                count += len(data)
                sha.update(data)
                if args.corrupt_reply and count == len(data):
                    data = bytes([data[0] ^ 1]) + data[1:]
                writer.write(data)
                await writer.drain()
            writer.write(b'LCOK' + sha.digest())
            await writer.drain()
            receipts.append({'bytes': count, 'sha256': sha.hexdigest()})
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    try:
        with tempfile.TemporaryDirectory(prefix='lc-hysteria-qualification-') as temporary:
            temp = Path(temporary)
            cert, key = temp / 'cert.pem', temp / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(cert), '-days', '2', '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            auth = temp / 'auth'
            auth.write_text(secrets.token_hex(24))
            auth.chmod(0o600)
            obfs = temp / 'obfs'
            obfs.write_text(secrets.token_hex(24))
            obfs.chmod(0o600)
            tls_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_server.minimum_version = tls_server.maximum_version = ssl.TLSVersion.TLSv1_3
            tls_server.load_cert_chain(cert, key)
            tls_client = ssl.create_default_context(cafile=str(cert))
            listeners = {}
            for name, context in [('plain', None), ('tls', tls_server)]:
                backend = await asyncio.start_server(echo, '127.0.0.1', 0, ssl=context)
                backends.append(backend)
                listeners[name] = backend.sockets[0].getsockname()[1]
            loop = asyncio.get_running_loop()
            datagram, _ = await loop.create_datagram_endpoint(lambda: Echo(udp_receipts), local_addr=('127.0.0.1', 0))
            udp_port = datagram.get_extra_info('sockname')[1]
            node_port = free_port(socket.SOCK_DGRAM)
            config = temp / 'server.json'
            server_config = {'listen': f'127.0.0.1:{node_port}',
                'tls': {'cert': str(cert), 'key': str(key)},
                'auth': {'type': 'password', 'password': auth.read_text()}}
            if args.obfs != 'none':
                server_config['obfs'] = {'type': args.obfs, args.obfs: {'password': obfs.read_text()}}
            config.write_text(json.dumps(server_config))
            server = start([str(args.server), 'server', '-c', str(config)], 'server')
            await ready(server, node_port, 'udp')

            def client_command(auth_value, pin_value, port, target, udp=None):
                command = [str(args.client), '-H', '127.0.0.1', str(node_port), 'localhost', auth_value,
                           '-' if args.obfs == 'none' else '@' + str(obfs), str(port),
                           '-t', f'127.0.0.1:{target}', '-p', pin_value]
                if args.obfs == 'gecko':
                    command += ['-g', '512-1200']
                if udp is not None:
                    command += ['-u', f'{udp}@127.0.0.1:{udp_port}']
                return command

            clients = {}
            ports = {}
            for name, target in listeners.items():
                tcp, udp = free_port(), free_port(socket.SOCK_DGRAM)
                command = client_command('@' + str(auth), pin, tcp, target, udp)
                clients[name] = start(command, name)
                ports[name] = (tcp, udp)
                await ready(clients[name], tcp, 'tcp')
                await ready(clients[name], udp, 'udp')

            async def transfer(name, nonce):
                data = hashlib.shake_256(nonce).digest(1024 * 1024)
                reader, writer = await asyncio.open_connection('127.0.0.1', ports[name][0],
                    ssl=tls_client if name == 'tls' else None, server_hostname='localhost' if name == 'tls' else None)
                async def upload():
                    writer.write(struct.pack('!I', len(data)) + data)
                    await writer.drain()
                async def download():
                    returned = await reader.readexactly(len(data))
                    assert returned == data, 'payload mismatch'
                    assert await reader.readexactly(36) == b'LCOK' + hashlib.sha256(data).digest(), 'backend receipt mismatch'
                try:
                    await asyncio.wait_for(asyncio.gather(upload(), download()), 20)
                    cases.append({'mode': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
                finally:
                    writer.close()
                    await writer.wait_closed()

            async def udp_checks():
                # proxy.go::UDPMessage.HeaderSize: 8 fixed bytes, a one-byte
                # address length, then the fixed target's address. MaxUDPSize=4096.
                maximum = 4096 - 9 - len(f'127.0.0.1:{udp_port}')
                channel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                channel.setblocking(False)
                channel.connect(('127.0.0.1', ports['plain'][1]))
                try:
                    for size in [1, 23, 1200, maximum, maximum + 1, 31]:
                        data = secrets.token_bytes(size)
                        await loop.sock_sendall(channel, data)
                        try:
                            reply = await asyncio.wait_for(loop.sock_recv(channel, 8192), 1 if size > maximum else 5)
                        except asyncio.TimeoutError:
                            assert size > maximum, 'mandatory UDP echo timed out'
                            cases.append({'mode': 'udp-oversize-drop', 'bytes': size})
                            continue
                        assert size <= maximum and reply == data, 'UDP boundary/payload mismatch'
                        assert hashlib.sha256(data).hexdigest() in udp_receipts, 'missing UDP backend receipt'
                        cases.append({'mode': 'udp', 'bytes': size, 'sha256': hashlib.sha256(data).hexdigest()})
                finally:
                    channel.close()

            # Wrong credentials and wrong server pin must fail before opening a listener.
            for name, bad_auth, bad_pin in [('denied', 'wrong-qualification-auth', pin),
                                              ('bad-pin', '@' + str(auth), '0' * 64)]:
                port = free_port()
                child = start(client_command(bad_auth, bad_pin, port, listeners['plain']), name)
                assert await asyncio.to_thread(child.wait, 15) == 1, 'invalid authentication/pin accepted'
                assert 'listening on' not in (root / (name + '.log')).read_text()
                cases.append({'mode': name, 'exit': child.returncode})

            load_start = time.monotonic()
            until = load_start + args.seconds
            while time.monotonic() < until:
                assert all(child.poll() is None for child in [server, *clients.values()]), 'live process exited'
                async with asyncio.TaskGroup() as batch:
                    for name in clients:
                        for _ in range(4):
                            batch.create_task(transfer(name, secrets.token_bytes(16)))
                    batch.create_task(udp_checks())
                for name, child in clients.items():
                    status = Path(f'/proc/{child.pid}/status').read_text()
                    monitors.append({'mode': name, 'pid': child.pid, 'seconds': time.monotonic() - started,
                        'rss_kib': int(status.split('VmRSS:')[1].split()[0]),
                        'descriptors': len(list(Path(f'/proc/{child.pid}/fd').iterdir()))})
                await asyncio.sleep(.1)
            assert len(receipts) == sum(case['mode'] in ('plain', 'tls') for case in cases), 'incomplete backend receipts'
            load_seconds = time.monotonic() - load_start
    except BaseException as error:
        errors.append(f'{type(error).__name__}: {error}')
        raise
    finally:
        for child in reversed(children):
            name = names[child.pid]
            if child.poll() is not None and name not in ('denied', 'bad-pin'):
                errors.append('live process exited before cleanup: ' + name)
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    await asyncio.to_thread(child.wait, 5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    await asyncio.to_thread(child.wait, 5)
                    errors.append('owned process required SIGKILL')
            exits.append({'role': name, 'pid': child.pid, 'exit': child.returncode})
            try:
                os.killpg(child.pid, 0)
                errors.append('owned process group survived cleanup')
            except ProcessLookupError:
                pass
        if datagram:
            datagram.close()
        for backend in backends:
            backend.close()
            await backend.wait_closed()
        for handle in logs:
            handle.close()
        result = {'schema': 'hysteria-local-qualification-v1', 'completed': not errors, 'obfs': args.obfs,
            'client_sha256': digest(args.client), 'server_sha256': digest(args.server),
            'driver_sha256': digest(root / 'inputs/driver'), 'scheduled_seconds': args.seconds, 'load_seconds': load_seconds,
            'elapsed_seconds': time.monotonic() - started, 'cases': cases, 'backend': receipts,
            'udp_backend': udp_receipts, 'monitor': monitors, 'exits': exits, 'errors': errors}
        (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    assert not errors, errors
    print(json.dumps(analyze(root)))


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('qualification requires assertions enabled')
    def terminate(number, _frame):
        raise SystemExit(128 + number)
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analyze', type=Path, help='independently replay retained evidence')
    parser.add_argument('--client', type=Path)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--corrupt-reply', action='store_true', help='negative control: corrupt backend payloads')
    parser.add_argument('--obfs', choices=('none', 'salamander', 'gecko'), default='none')
    parser.add_argument('--seconds', type=int, default=300, choices=range(1, 3601), metavar='1..3600')
    options = parser.parse_args()
    if options.analyze:
        print(json.dumps(analyze(options.analyze)))
    else:
        if not all((options.client, options.server, options.output)):
            parser.error('--client, --server and --output are required to run')
        asyncio.run(run(options))
