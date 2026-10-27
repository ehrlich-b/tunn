#!/usr/bin/env python3
"""The acceptance report must fail closed for omitted or skipped cases."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('journey', Path(__file__).parent / 'integration-tests/recipient-journey.py')
journey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journey)


class ReportRefusal(unittest.TestCase):
    def test_missing_required_case(self):
        for missing in journey.REQUIRED:
            with self.subTest(missing=missing), self.assertRaisesRegex(AssertionError, 'missing'):
                journey.validate({'cases': {case: 'PASS' for case in journey.REQUIRED - {missing}}})

    def test_skipped_or_failed_required_case(self):
        for status in ('SKIP', 'PENDING', 'FAIL', ''):
            for case in journey.REQUIRED:
                report = {'cases': dict.fromkeys(journey.REQUIRED, 'PASS')}
                report['cases'][case] = status
                with self.subTest(case=case, status=status), self.assertRaisesRegex(AssertionError, 'failed or skipped'):
                    journey.validate(report)


if __name__ == '__main__':
    unittest.main()
