#!/usr/bin/env python3
"""Qualify the checked backend through the pinned Xray reference client."""
import asyncio
import hashlib
import struct


async def main():
    reader, writer = await asyncio.open_connection('127.0.0.1', 29610)
    writer.write(b'CONNECT 127.0.0.1:29602 HTTP/1.1\r\nHost: 127.0.0.1:29602\r\n\r\n')
    await writer.drain()
    reply = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 15)
    assert b' 200 ' in reply
    writer.write(struct.pack('!4sQQIIBB', b'LCI1', 65536, 65536, 71, 72, 0, 0))
    digest = hashlib.sha256()
    for index in range(2):
        data = hashlib.shake_256(struct.pack('!QI', index, 71)).digest(32768)
        digest.update(data)
        writer.write(data)
    await writer.drain()
    down = hashlib.sha256()
    for index in range(2):
        data = await asyncio.wait_for(reader.readexactly(32768), 20)
        assert data == hashlib.shake_256(struct.pack('!QI', index, 72)).digest(32768)
        down.update(data)
    assert await reader.readexactly(68) == b'LCOK' + digest.digest() + down.digest()
    writer.close()
    await writer.wait_closed()
    print('REFERENCE_REALITY_BACKEND_PASSED', flush=True)


asyncio.run(main())
