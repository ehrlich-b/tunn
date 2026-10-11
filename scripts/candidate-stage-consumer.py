#!/usr/bin/env python3
"""Stage the second exported SDK importer from immutable local Git objects."""
import pathlib,subprocess,json,os
root=pathlib.Path(__file__).resolve().parents[1]
# Reuse the pinned offline archive stager, then replace only consumer fixtures.
p=subprocess.run(['python3',str(root/'scripts/stage-sdk-response-consumer.py')],cwd=root,text=True,capture_output=True,check=True)
dir=pathlib.Path(p.stdout.strip()).resolve()
for file in dir.glob('*.go'):file.unlink()
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
files=subprocess.check_output(['git','ls-tree','-r','--name-only',sha,'sdk/testdata/candidate-consumer'],cwd=root,text=True).splitlines()
if not files:raise SystemExit('REQUIRED-UNRUN: second consumer is not committed')
for file in files:(dir/pathlib.Path(file).name).write_bytes(subprocess.check_output(['git','show',sha+':'+file],cwd=root))
print(dir)
