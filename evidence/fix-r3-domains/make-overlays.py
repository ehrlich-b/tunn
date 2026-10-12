"""Recreate before-source and original-review overlays without another checkout."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
scratch = root / '.scratch/domains-before'
scratch.mkdir(parents=True, exist_ok=True)
replace = {}
for name in ['registry.go', 'wildcard.go']:
    dest = scratch / name
    dest.write_bytes(subprocess.check_output(['git', 'show', 'bbe8014:internal/domains/' + name], cwd=root))
    replace[str(root / 'internal/domains' / name)] = str(dest)
empty = scratch / 'empty.go'
empty.write_text('package domains\n')
for name in ['claims.go', 'issuance.go']:
    replace[str(root / 'internal/domains' / name)] = str(empty)
(root / '.scratch/domains-before-overlay.json').write_text(json.dumps({'Replace': replace}))
(root / '.scratch/domains-review-overlay.json').write_text(json.dumps({'Replace': {
    str(root / 'internal/domains/review_r3_test.go'): str(root / 'evidence/fix-r3-domains/review_r3_original.go.txt')
}}))
