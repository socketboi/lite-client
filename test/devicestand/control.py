#!/usr/bin/env python3
"""Control only the reference processes inside the disposable fixture container."""
import json
import socket
import sys

with socket.socket(socket.AF_UNIX) as channel:
    channel.connect('/run/stand/control.sock')
    channel.sendall(json.dumps(dict(action=sys.argv[1], plane=sys.argv[2])).encode() + b'\n')
    result = json.loads(channel.makefile('rb').readline())
    print(json.dumps(result))
    raise SystemExit(0 if result.get('ok') else 1)
