#!/usr/bin/env python3
"""Go cache protocol: read shared immutable artifacts, write only clone cache."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

local = Path(os.environ['GOCACHE'])
shared = Path('/work/cache/go/build')
def cachepath(root, digest, suffix):
    return root / digest[:2] / (digest + suffix)
def reply(data):
    print(json.dumps(data), flush=True)
reply({'ID': 0, 'KnownCommands': ['get', 'put', 'close']})
stream = sys.stdin.buffer
while True:
    line = stream.readline()
    if not line:
        break
    if not line.strip():
        continue
    req = json.loads(line)
    out = {'ID': req['ID']}
    command = req['Command']
    if command == 'close':
        reply(out)
        break
    action = base64.b64decode(req['ActionID']).hex()
    if command == 'get':
        out['Miss'] = True
        for root in [local, shared]:
            try:
                version, stored_action, output, size, stamp = cachepath(root, action, '-a').read_text().split()
                path = cachepath(root, output, '-d')
                if version != 'v1' or stored_action != action or path.stat().st_size != int(size):
                    continue
                out.update(Miss=False, OutputID=base64.b64encode(bytes.fromhex(output)).decode(), Size=int(size), DiskPath=str(path))
                break
            except (OSError, ValueError):
                continue
    elif command == 'put':
        output = base64.b64decode(req['OutputID']).hex()
        path = cachepath(local, output, '-d')
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + '.' + uuid.uuid4().hex)
        size = req.get('BodySize', 0)
        digest = hashlib.sha256()
        with temporary.open('wb') as destination:
            if size:
                while (char := stream.read(1)) in (b'\n', b'\r'):
                    pass
                assert char == b'"'
                remaining = ((size + 2) // 3) * 4
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise EOFError('cache body')
                    data = base64.b64decode(chunk)
                    destination.write(data)
                    digest.update(data)
                    remaining -= len(chunk)
                assert stream.read(1) == b'"'
        assert temporary.stat().st_size == size
        assert digest.hexdigest() == output
        os.replace(temporary, path)
        entry = cachepath(local, action, '-a')
        entry.parent.mkdir(parents=True, exist_ok=True)
        temporary_entry = entry.with_name(entry.name + '.' + uuid.uuid4().hex)
        temporary_entry.write_text(f'v1 {action} {output} {size:20d} {time.time_ns():20d}\n')
        os.replace(temporary_entry, entry)
        out['DiskPath'] = str(path)
    reply(out)
