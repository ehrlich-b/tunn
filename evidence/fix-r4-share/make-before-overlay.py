"""Reconstruct the reviewed sharing behavior without another checkout.

Keep only the validated lower owner-limit option needed by the bounded host
fixture; it does not change the reviewed retirement or RPC behavior.
"""
import json
import pathlib
import subprocess

root = pathlib.Path.cwd().resolve()
archive = root / 'evidence/fix-r4-share/before-source'
archive.mkdir(exist_ok=True)
replacements = {}
for name in ('sharing.go', 'sharing_limits.go', 'remote.go'):
    path = pathlib.Path('internal/metering') / name
    data = subprocess.check_output(['git', 'show', f'1188c57:{path}'])
    dest = archive / (name + '.txt')
    dest.write_bytes(data)
    replacements[str(root / path)] = str(dest)
path = pathlib.Path('internal/metering/store.go')
data = (root / path).read_text().replace(
    'var ErrCapacity error = &admissionError{message: "metering storage capacity reached", reason: "CAPACITY"}',
    'var ErrCapacity = errors.New("metering storage capacity reached")',
)
dest = archive / 'store.go.txt'
dest.write_text(data)
replacements[str(root / path)] = str(dest)
(root / 'evidence/fix-r4-share/before-overlay.json').write_text(json.dumps({'Replace': replacements}, indent=2) + '\n')
