import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('watch', HERE / 'launch-watch.py')
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


class WatchTest(unittest.TestCase):
    def test_counts_and_window(self):
        lines = (HERE / 'testdata/launch-watch.txt').read_text().splitlines()
        counts, types = watch.summarize(lines, datetime(2026, 10, 31, 12, tzinfo=timezone.utc))
        self.assertEqual(dict(types), {'invoice.paid': 1, 'checkout.session.completed': 1})
        self.assertEqual(dict(counts), {**{v[0]: 1 for v in watch.MESSAGES.values()}, 'registrations': 1, 'malformed': 1})
        counts, types = watch.summarize(['time=bad level=INFO msg="x"', 'time=2026-10-31T12:00:00Z level=INFO msg="received Stripe webhook"'], datetime(2026, 10, 31, 12, tzinfo=timezone.utc))
        self.assertEqual(counts['malformed'], 2)
        self.assertFalse(types)

    def test_prefix_boundary(self):
        now = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)
        event = 'time=2026-10-31T12:00:00Z level=INFO msg="received Stripe webhook" type=invoice.paid'
        lines = [prefix + event for prefix in ('[info]', '[error]', '[info] ', '')]
        counts, types = watch.summarize(lines + ['nottime=' + event], now)
        self.assertEqual(types['invoice.paid'], 4)
        self.assertEqual(counts['malformed'], 1)

    def test_cli_file_and_stdin(self):
        fixture = HERE / 'testdata/launch-watch.txt'
        cmd = [sys.executable, str(HERE / 'launch-watch.py')]
        file_result = subprocess.check_output(cmd + [str(fixture)], text=True)
        stdin_result = subprocess.check_output(cmd, input=fixture.read_text(), text=True)
        self.assertEqual(file_result, stdin_result)
        self.assertIn('unavailable (not logged as such)', file_result)
        self.assertIn('Malformed lines (all input, irrespective of time): 1', file_result)


if __name__ == '__main__':
    unittest.main()
