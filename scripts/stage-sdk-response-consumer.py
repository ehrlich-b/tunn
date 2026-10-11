#!/usr/bin/env python3
"""Stage a fresh, immutable offline SDK importer; never publish or resolve URLs."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

root = Path(__file__).resolve().parents[1]
scratch = root / '.scratch'
cache = Path(os.environ['GOMODCACHE']).resolve()
if not cache.is_relative_to(scratch.resolve()):
    raise SystemExit('GOMODCACHE must be inside this clone/.scratch')
sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
date = subprocess.check_output(['git', 'show', '-s', '--format=%cI', sha], cwd=root, text=True).strip()
# The local pseudo-version is unique per committed snapshot, avoiding reuse of
# the v0.0.0 archive from another review. No replace/workspace/source fallback.
from datetime import datetime, timezone
stamp = datetime.fromisoformat(date).astimezone(timezone.utc)
version = f'v0.0.0-{stamp:%Y%m%d%H%M%S}-{sha[:12]}'
download = cache / 'cache/download/github.com/ehrlich-b/tunn/@v'
download.mkdir(parents=True, exist_ok=True)
archive = subprocess.check_output(['git', 'archive', sha], cwd=root)
zip_path = download / f'{version}.zip'
if not zip_path.exists():
    with tarfile.open(fileobj=io.BytesIO(archive)) as source, zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as target:
        for member in source.getmembers():
            if member.isfile() and not member.name.startswith('sdk/testdata/'):
                data = source.extractfile(member).read()
                target.writestr(f'github.com/ehrlich-b/tunn@{version}/{member.name}', data)
                if member.name == 'go.mod':
                    (download / f'{version}.mod').write_bytes(data)
    (download / f'{version}.info').write_text(json.dumps({'Version': version, 'Time': stamp.isoformat().replace('+00:00', 'Z')}))
consumer_parent = scratch / 'sdk-response-consumer'
consumer_parent.mkdir(parents=True, exist_ok=True)
consumer = Path(tempfile.mkdtemp(prefix='run-', dir=consumer_parent))
for path in (root / 'sdk/testdata/response-consumer').glob('*.go'):
    shutil.copyfile(path, consumer / path.name)
(consumer / 'go.mod').write_text(f'module tunn-response-consumer\n\ngo 1.25.0\n\nrequire github.com/ehrlich-b/tunn {version}\n')
shutil.copyfile(root / 'go.sum', consumer / 'go.sum')
(consumer / 'snapshot.json').write_text(json.dumps({'sha': sha, 'version': version}) + '\n')
(consumer / 'Makefile').write_text('''test:
	GOWORK=off GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -mod=mod -race -v -count=1 -parallel=2 -timeout=20s ./...
build:
	GOWORK=off GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go build -mod=mod -o response-consumer .
verify-module:
	GOWORK=off GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go list -m -json github.com/ehrlich-b/tunn > module.json
	python3 -c 'import json, os, pathlib; m=json.loads(pathlib.Path("module.json").read_text()); assert "Replace" not in m and pathlib.Path(m["Dir"]).is_relative_to(pathlib.Path(os.environ["GOMODCACHE"])), m; print("PASS: immutable cache import", m["Version"])'
''')
print(consumer)
