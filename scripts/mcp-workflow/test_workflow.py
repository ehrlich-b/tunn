import copy
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

from external_operator import validate_external
from oracle import reconcile

ROOT = Path(__file__).resolve().parents[2] / 'examples/mcp-project-reader/fixtures'

def source_output(fixture):
    files, reads = [], []
    root = ROOT / fixture
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        data = path.read_bytes()
        name, digest = path.relative_to(root).as_posix(), hashlib.sha256(data).hexdigest()
        count = len(data.splitlines())
        files.append({'path': name, 'sha256': digest, 'bytes': len(data), 'lines': count})
        reads.append({'path': name, 'sha256': digest, 'firstLine': 1, 'lastLine': count,
                      'startByte': 0, 'endByte': len(data), 'text': data.decode()})
    return {'files': files, 'reads': reads}

class WorkflowTests(unittest.TestCase):
    def test_explicit_offline_boundary(self):
        with patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('network forbidden')):
            validate_external('in-memory', None, None, False)
            for args in [('in-memory', 'https://live.invalid/mcp', None, False),
                         ('in-memory', None, '/secret/token', False),
                         ('in-memory', None, None, True),
                         ('external-host', 'https://live.invalid/mcp', '/secret/token', False),
                         ('external-host', 'http://live.invalid/mcp', '/secret/token', True),
                         ('external-host', 'https://user:pass@live.invalid/mcp', '/secret/token', True),
                         ('external-host', 'https://live.invalid/account', '/secret/token', True),
                         ('external-host', 'https://live.invalid/mcp?token=private', '/secret/token', True)]:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    validate_external(*args)

    def test_known_answers_and_no_answer(self):
        for fixture, answer in [('harbor/day1', 'HN-104'), ('harbor/day2', 'HN-108'),
                                ('ridge', 'no_actionable_issue')]:
            result = reconcile(source_output(fixture), ROOT / fixture, fixture)
            self.assertEqual(result['answer'], answer)

    def test_duplicate_manifest_entry_rejected(self):
        changed = source_output('harbor/day1')
        changed['files'].append(copy.deepcopy(changed['files'][0]))
        with self.assertRaises(ValueError):
            reconcile(changed, ROOT / 'harbor/day1', 'harbor/day1')

    def test_bad_citations_and_missing_evidence_rejected(self):
        original = source_output('harbor/day1')
        for field, value in [('endByte', 1), ('sha256', '0' * 64), ('text', 'fabricated'),
                             ('path', '../outside'), ('firstLine', 0), ('lastLine', 999)]:
            changed = copy.deepcopy(original)
            changed['reads'][0][field] = value
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                reconcile(changed, ROOT / 'harbor/day1', 'harbor/day1')
        changed = copy.deepcopy(original)
        changed['reads'].pop()
        with self.assertRaises(ValueError):
            reconcile(changed, ROOT / 'harbor/day1', 'harbor/day1')
        changed = copy.deepcopy(original)
        changed['reads'].append(changed['reads'][0])
        with self.assertRaises(ValueError):
            reconcile(changed, ROOT / 'harbor/day1', 'harbor/day1')

if __name__ == '__main__':
    unittest.main()
