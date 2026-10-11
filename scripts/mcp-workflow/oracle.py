"""Independent finite-task oracle: no Go/server imports, no network, no secrets."""
import hashlib
import re
from pathlib import Path

EXPECTED = {'harbor/day1': 'HN-104', 'harbor/day2': 'HN-108', 'ridge': 'no_actionable_issue'}

def reconcile(output, fixture_root, fixture):
    root = Path(fixture_root).resolve()
    files = {entry['path']: entry for entry in output['files']}
    paths = sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file())
    if sorted(files) != paths:
        raise ValueError('manifest differs from supplied fixture')
    text = {}
    checked = 0
    for span in output['reads']:
        name = span['path']
        if name not in files or name in text:
            raise ValueError('duplicate or unlisted citation path')
        data = (root / name).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        lines = data.splitlines(keepends=True)
        if span['sha256'] != digest or files[name]['sha256'] != digest:
            raise ValueError('source hash mismatch')
        if files[name]['bytes'] != len(data) or files[name]['lines'] != len(lines):
            raise ValueError('manifest length mismatch')
        first, last = span['firstLine'], span['lastLine']
        if not (1 <= first <= last <= len(lines)):
            raise ValueError('invalid citation range')
        start, end = sum(map(len, lines[:first-1])), sum(map(len, lines[:last]))
        if (span['startByte'], span['endByte']) != (start, end):
            raise ValueError('citation offsets mismatch')
        if data[start:end].decode('utf-8') != span['text']:
            raise ValueError('citation text mismatch')
        if first != 1 or last != len(lines):
            raise ValueError('oracle requires complete supplied file evidence')
        text[name] = span['text']
        checked += 1
    if sorted(text) != paths:
        raise ValueError('missing source evidence')
    if 'Choose an open, ready issue not listed as shipped' not in text['README.md']:
        raise ValueError('task selection rule missing')
    candidates = []
    for issue, status, readiness, priority in re.findall(
        r'^## (HN-\d+) — [^\n]+\nStatus: (\w+); Readiness: (\w+); Priority: (\d+)',
        text['ISSUES.md'], re.MULTILINE,
    ):
        if status == 'open' and readiness == 'ready' and f'Shipped {issue}:' not in text['CHANGELOG.md']:
            candidates.append((int(priority), int(issue[3:]), issue))
    answer = min(candidates)[2] if candidates else 'no_actionable_issue'
    if answer != EXPECTED[fixture]:
        raise ValueError('independent answer differs from hand-computed answer')
    return {'state': 'PASS', 'scope': 'fixture-only', 'answer': answer, 'filesChecked': checked,
            'method': 'Python standard-library oracle from tool-returned complete files, hashes and spans'}
