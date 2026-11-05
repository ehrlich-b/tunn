import importlib.util
import json
import tempfile
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
        self.assertEqual(dict(counts), {**{v[0]: 1 for v in watch.MESSAGES.values() if v[0] not in ('authority unavailable', 'not committed')}, 'registrations': 1, 'malformed': 1})
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

    def test_real_slog_text_handler(self):
        logger = HERE / 'testdata/launch-watch-logger/main.go'
        line = subprocess.check_output(['go', 'run', str(logger)], text=True)
        self.assertIn("email=o'brien@example.com", line)
        counts, types = watch.summarize([line], datetime(2026, 10, 31, 12, tzinfo=timezone.utc))
        self.assertEqual(dict(counts), {'magic link': 1})
        self.assertFalse(types)
        self.assertEqual(watch.parse_fields(line)['error'], 'SMTP "failure"\nretry')

    def test_webhook_error_exit(self):
        from datetime import timedelta
        stamp = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        line = f'time={stamp} level=ERROR msg="invalid Stripe signature"\n'
        cmd = [sys.executable, str(HERE / 'launch-watch.py')]
        result = subprocess.run(cmd, input=line, text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('invalid signature: 1', result.stdout)

    def test_funnel_alert_and_conversion(self):
        report = {'days': [{'day': '2026-11-05', 'stage': 'signup', 'count': 2},
                           {'day': '2026-11-05', 'stage': 'tunnel', 'count': 1}],
                  'checkout_without_pro': 1}
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8') as fixture:
            json.dump(report, fixture)
            fixture.flush()
            cmd = [sys.executable, str(HERE / 'launch-watch.py'), '--funnel', fixture.name]
            result = subprocess.run(cmd, input="", text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('tunnel: 1 (conversion: 50.0%)', result.stdout)
            fixture.seek(0)
            fixture.truncate()
            report['checkout_without_pro'] = 0
            json.dump(report, fixture)
            fixture.flush()
            self.assertEqual(subprocess.run(cmd, input="", text=True, capture_output=True).returncode, 0)

    def test_funnel_with_webhook_error(self):
        report = {'days': [], 'checkout_without_pro': 0}
        stamp = datetime.now(timezone.utc).isoformat()
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8') as funnel, \
             tempfile.NamedTemporaryFile(mode='w', encoding='utf-8') as logs:
            json.dump(report, funnel)
            funnel.flush()
            logs.write(f'time={stamp} level=ERROR msg="invalid Stripe signature"\n')
            logs.flush()
            result = subprocess.run([sys.executable, str(HERE / 'launch-watch.py'), '--funnel', funnel.name, logs.name], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('invalid signature: 1', result.stdout)

    def test_funnel_with_stdin_webhook_errors(self):
        stamp = datetime.now(timezone.utc).isoformat()
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8') as funnel:
            json.dump({'days': [], 'checkout_without_pro': 0}, funnel)
            funnel.flush()
            cmd = [sys.executable, str(HERE / 'launch-watch.py'), '--funnel', funnel.name]
            for message in ('invalid Stripe signature', 'billing webhook authority unavailable',
                            'billing webhook event not committed'):
                with self.subTest(message=message):
                    line = f'time={stamp} level=ERROR msg="{message}"\n'
                    result = subprocess.run(cmd, input=line, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2, result.stdout)
                    self.assertIn('Webhook rejections:', result.stdout)
            self.assertEqual(subprocess.run(cmd, input='', capture_output=True, text=True).returncode, 0)

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
