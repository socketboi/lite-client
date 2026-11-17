#!/usr/bin/env python3
"""Isolated reference-node fixture: checked duplex streams and local-only control."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import ssl
import struct
import subprocess

ROOT = Path('/fixture')
STATE = Path('/run/stand')
BLOCK = 32768
HEADER = struct.Struct('!4sQQIIBB')
processes, logs = {}, {}


def block(seed, index, size):
    return hashlib.shake_256(struct.pack('!QI', index, seed)).digest(size)


def report(**record):
    print(json.dumps(record), flush=True)


def start(name):
    args = ([str(ROOT / 'ref-xray'), 'run', '-c', str(ROOT / 'xray.json')] if name == 'reality' else
            [str(ROOT / 'ref-hysteria'), 'server', '-c', str(ROOT / 'hysteria.json')])
    logs[name] = (STATE / (name + '.log')).open('ab')
    processes[name] = subprocess.Popen(args, stdout=logs[name], stderr=subprocess.STDOUT)


async def ready(name):
    port = 29600 if name == 'reality' else 29601
    process = processes[name]
    for unused in range(200):
        if process.poll() is not None:
            raise RuntimeError('reference exited before listening')
        sockets = set()
        for entry in Path('/proc', str(process.pid), 'fd').iterdir():
            try:
                target = os.readlink(entry)
                if target.startswith('socket:['):
                    sockets.add(target[8:-1])
            except FileNotFoundError:
                pass
        table = Path('/proc/net/tcp' if name == 'reality' else '/proc/net/udp')
        for row in table.read_text().splitlines()[1:]:
            fields = row.split()
            if int(fields[1].split(':')[1], 16) == port and fields[9] in sockets:
                return
        await asyncio.sleep(.05)
    raise TimeoutError('reference listener not owned by its process')


async def halt(name):
    process = processes[name]
    if process.poll() is None:
        process.send_signal(signal.SIGCONT)
        process.terminate()
        try:
            await asyncio.to_thread(process.wait, 5)
        except subprocess.TimeoutExpired:
            process.kill()
            await asyncio.to_thread(process.wait)
    logs[name].close()


async def duplex(reader, writer):
    down = None
    seed = None
    try:
        raw = await asyncio.wait_for(reader.readexactly(HEADER.size), 15)
        magic, up_size, down_size, seed, down_seed, delay, corrupt = HEADER.unpack(raw)
        if magic != b'LCI1' or max(up_size, down_size) > 128 * 1024 * 1024:
            raise ValueError('invalid fixture header')
        report(event='accepted', seed=seed, upload=up_size, download=down_size)

        async def send_down():
            digest = hashlib.sha256()
            for index, offset in enumerate(range(0, down_size, BLOCK)):
                data = block(down_seed, index, min(BLOCK, down_size - offset))
                digest.update(data)
                if corrupt and index == 0:
                    data = bytes([data[0] ^ 1]) + data[1:]
                writer.write(data)
                await writer.drain()
            return digest.digest()

        down = asyncio.create_task(send_down())
        digest = hashlib.sha256()
        for index, offset in enumerate(range(0, up_size, BLOCK)):
            data = await reader.readexactly(min(BLOCK, up_size - offset))
            if data != block(seed, index, len(data)):
                raise ValueError('upload mismatch at ' + str(offset))
            digest.update(data)
            if delay:
                await asyncio.sleep(delay / 1000)
        down_hash = await down
        writer.write(b'LCOK' + digest.digest() + down_hash)
        await writer.drain()
        report(event='complete', seed=seed, upload=up_size, download=down_size)
    except (Exception, asyncio.CancelledError) as error:
        report(event='connection_ended', seed=seed, error=type(error).__name__, detail=str(error)[:160])
    finally:
        if down is not None and not down.done():
            down.cancel()
            await asyncio.gather(down, return_exceptions=True)
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.transport.sendto(data, address)


async def donor(reader, writer):
    try:
        await asyncio.wait_for(reader.read(4096), 10)
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
        await writer.drain()
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()


async def control(reader, writer):
    response = {}
    try:
        request = json.loads(await asyncio.wait_for(reader.readline(), 5))
        action, name = request['action'], request['plane']
        if name not in ('reality', 'hysteria'):
            raise ValueError('invalid plane')
        process = processes[name]
        if action == 'pause':
            process.send_signal(signal.SIGSTOP)
        elif action == 'resume':
            process.send_signal(signal.SIGCONT)
        elif action == 'stop':
            await halt(name)
        elif action == 'restart':
            await halt(name)
            start(name)
            await ready(name)
        elif action != 'status':
            raise ValueError('invalid action')
        response = dict(ok=True, pid=processes[name].pid, exit=processes[name].poll())
    except Exception as error:
        response = dict(ok=False, error=type(error).__name__)
    writer.write(json.dumps(response).encode() + b'\n')
    await writer.drain()
    writer.close()


async def main():
    STATE.mkdir(exist_ok=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(ROOT / 'cert.pem', ROOT / 'key.pem')
    donor_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    donor_context.minimum_version = ssl.TLSVersion.TLSv1_3
    donor_context.load_cert_chain(ROOT / 'cert.pem', ROOT / 'key.pem')
    donor_context.set_alpn_protocols(['h2', 'http/1.1'])
    servers = [await asyncio.start_server(duplex, '127.0.0.1', 29602),
               await asyncio.start_server(duplex, '127.0.0.1', 29603, ssl=context),
               await asyncio.start_server(donor, '127.0.0.1', 29604, ssl=donor_context),
               await asyncio.start_unix_server(control, STATE / 'control.sock')]
    os.chmod(STATE / 'control.sock', 0o600)
    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=('127.0.0.1', 29605))
    for name in ('reality', 'hysteria'):
        start(name)
        await ready(name)
    report(event='fixture_ready')
    stopped = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(sig, stopped.set)
    try:
        await stopped.wait()
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()
        udp.close()
        for name in ('reality', 'hysteria'):
            await halt(name)


if __name__ == '__main__':
    asyncio.run(main())
