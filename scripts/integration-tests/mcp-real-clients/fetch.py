#!/usr/bin/env python3
"""Fetch test-only SDKs outside the checkout; never modify product manifests."""
import os
from pathlib import Path
import subprocess
import zipfile

root = Path(__file__).resolve().parents[3]
scratch = Path(os.environ.get('TUNN_MCP_CLIENTS_SCRATCH', str(root.parent / 'scratch'))).resolve()
assert scratch != root and root not in scratch.parents
scratch.mkdir(parents=True, exist_ok=True)
subprocess.run(['npm','--prefix',str(scratch/'node'),'install','--no-save','--no-package-lock',
                '@modelcontextprotocol/sdk@1.29.0'],check=True)
subprocess.run(['python3','-m','pip','download','--dest',str(scratch/'wheels'),'mcp==2.3.0'],check=True)
for wheel in (scratch/'wheels').glob('*.whl'):
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(scratch/'python')
print('Fetched SDKs into '+str(scratch))
