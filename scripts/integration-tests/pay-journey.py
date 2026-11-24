#!/usr/bin/env python3
"""Walk both Pro offers through real HTTPS handlers and an in-memory provider.

Hold five publishers through checkout and prove the refused sixth becomes usable
through one ServeClient.Run call with the same credential. Measure from sending
the signed webhook to the sixth tunnel's first successful HTTP response, using
Go's monotonic clock.

Needs Node, npm's cached playwright@1.64.1 and its cached Chromium. Reuses a
Playwright module on Node's module path, or prepares the pinned test dependency
offline in .scratch/pay-journey/node, following the integration clients' scratch
convention. Select an existing npm cache with standard npm_config_cache when
the default cache is empty. TUNN_PLAYWRIGHT_MODULE can override resolution. No downloads, global
installs, provider credentials, interactive sign-in or hosted service are used.

TUNN_PAY_JOURNEY_EVIDENCE defaults to ../evidence (outside the checkout).
PLAYWRIGHT_BROWSERS_PATH defaults to /work/cache/ms-playwright.
"""
import argparse
from datetime import datetime
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import subprocess
import struct

ROOT = Path(__file__).resolve().parents[2]
STEPS = ['pricing', 'go-pro-sign-in', 'sign-in-link-sent', 'fixture-checkout',
         'signed-webhook', 'usable-limit', 'return-account-pro']


def verify(report_path):
    """Check the complete step matrix, screenshot dimensions and signed receipts."""
    report = json.loads(report_path.read_text())
    assert report['result'] == 'PASS'
    expected = {(period, width) for period in ('monthly', 'yearly') for width in (390, 1440)}
    assert len(report['cases']) == 4
    assert {(c['period'], c['width']) for c in report['cases']} == expected
    for case in report['cases']:
        period, width = case['period'], case['width']
        assert case['result'] == 'PASS'
        assert case['browser_errors'] == [] and case['blocked_external_requests'] == []
        assert len(case['checkout_redirects']) == 1
        assert [step['name'] for step in case['steps']] == STEPS
        authority = case['authority']
        assert authority['before_plan'] == 'free' and authority['after_plan'] == 'pro'
        assert authority['provider_reads'] == authority['mappings'] == authority['automatic_audits'] == 1
        assert authority['webhook_status'] == 200 and authority['webhook_state'] == 'reconciled'
        assert authority['period_seconds'] == (30 if period == 'monthly' else 365) * 24 * 3600
        limit = authority['limit']
        assert limit['before_count'] == limit['before_limit'] == 5
        assert limit['before_error_code'] == 'tunnel_limit'
        assert 'Free tunnel limit reached: 5/5' in limit['before_refusal']
        assert limit['after_count'] == 6 and limit['after_limit'] == 25
        assert limit['sixth_registered'] is True and limit['sixth_http_status'] == 200
        assert limit['persistent_publishers'] == 5
        assert limit['publisher_restarts'] == limit['new_logins'] == 0
        assert limit['serve_client_run_calls'] == 6 and limit['sixth_run_calls'] == 1
        assert limit['automatic_registration_retry'] is True
        assert limit['sixth_refused_while_running'] is True
        assert limit['sixth_running_after_activation'] is True
        assert limit['publisher_pid_before'] == limit['publisher_pid_after'] > 0
        assert len(limit['credential_sha256_before']) == 64
        assert limit['credential_sha256_before'] == limit['credential_sha256_after']
        seconds = limit['seconds_from_signed_webhook_to_usable_limit']
        assert math.isfinite(seconds) and 0 < seconds < 60
        elapsed = (datetime.fromisoformat(limit['sixth_usable_at'].replace('Z', '+00:00')) -
                   datetime.fromisoformat(limit['signed_webhook_sent_at'].replace('Z', '+00:00'))).total_seconds()
        assert abs(elapsed - seconds) < 0.00001
        assert all(case['steps'][5][key] == value for key, value in limit.items())
        for step in case['steps']:
            image = report_path.parent / step['screenshot']
            raw = image.read_bytes()
            assert raw[:8] == b'\x89PNG\r\n\x1a\n', image
            image_width, height = struct.unpack('>II', raw[16:24])
            assert image_width == width and height >= 900, image
        receipt = json.loads((report_path.parent / case['steps'][4]['receipt']).read_text())
        assert receipt['http_status'] == 200 and receipt['result']['state'] == 'reconciled'
        timestamp, signature = receipt['signature'].split(',')
        assert timestamp.startswith('t=') and signature.startswith('v1=')
        signed = timestamp[2:] + '.' + receipt['body']
        digest = hmac.new(b'whsec_first_fixture', signed.encode(), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(digest, signature[3:]), 'fixture webhook signature differs'
        assert json.loads(receipt['body'])['type'] == 'checkout.session.completed'
        assert receipt['limit'] == limit
        final = case['steps'][-1]
        assert final['expected_plan'] == final['actual_plan'] == 'pro' and final['state'] == 'active'
    print('PASS: four complete journeys, 28 correctly sized screenshots, four live limit increases and four signed webhook receipts')


def playwright_module():
    """Use standard Node resolution, then npm's configured offline cache."""
    override = os.environ.get('TUNN_PLAYWRIGHT_MODULE')
    if override:
        return override
    resolved = subprocess.run(['node', '-p', "require.resolve('playwright')"],
                              cwd=ROOT, text=True, capture_output=True)
    if resolved.returncode == 0:
        return resolved.stdout.strip()
    # Like mcp-real-clients, keep test dependencies separate from product SDKs.
    prefix = ROOT / '.scratch/pay-journey/node'
    module = prefix / 'node_modules/playwright'
    package = module / 'package.json'
    if not package.is_file() or json.loads(package.read_text())['version'] != '1.64.1':
        subprocess.run(['npm', '--prefix', str(prefix), 'install', '--offline',
                        '--ignore-scripts', '--no-audit', '--no-fund', '--no-save',
                        '--no-package-lock', 'playwright@1.64.1'], cwd=ROOT, check=True)
    return str(module)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', type=Path, help='verify a previously generated report')
    args = parser.parse_args()
    if args.verify:
        verify(args.verify.resolve())
        return
    output = Path(os.environ.get('TUNN_PAY_JOURNEY_EVIDENCE', ROOT.parent / 'evidence')).resolve()
    if output == ROOT or ROOT in output.parents:
        raise SystemExit('Evidence must be outside the checkout')
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TUNN_PLAYWRIGHT_MODULE=playwright_module(),
               TUNN_PAY_JOURNEY='1', TUNN_PAY_JOURNEY_EVIDENCE=str(output),
               PLAYWRIGHT_BROWSERS_PATH=os.environ.get('PLAYWRIGHT_BROWSERS_PATH', '/work/cache/ms-playwright'))
    command = ['go', 'test', '-p', '2', '-count=1', '-timeout=300s', '-v',
               '-run', '^TestPayJourneyBrowser$', './internal/host']
    with (output / 'pay-journey-go.log').open('w') as log:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            log.write(line)
            print(line, end='', flush=True)
        code = process.wait()
    if code:
        raise SystemExit(code)
    cases = []
    for period in ('monthly', 'yearly'):
        for width in (390, 1440):
            run = f'{period}-{width}'
            case = json.loads((output / f'{run}-browser.json').read_text())
            authority = json.loads((output / f'{run}-authority.json').read_text())
            assert case['result'] == 'PASS'
            assert [s['name'] for s in case['steps']] == STEPS
            assert authority['before_plan'] == 'free' and authority['after_plan'] == 'pro'
            assert authority['provider_reads'] == 1
            for step in case['steps']:
                image = output / step['screenshot']
                assert image.is_file() and image.stat().st_size > 0, image
            case['authority'] = authority
            cases.append(case)
    report = {'result': 'PASS', 'provider': 'shared firstCustomerStripeFixture (in-memory)',
              'network_policy': 'Chromium maps checkout hostname to loopback fixture; all other external names fail resolution',
              'cases': cases}
    (output / 'pay-journey.json').write_text(json.dumps(report, indent=2) + '\n')
    verify(output / 'pay-journey.json')
    print(f'PASS: monthly and yearly at 390/1440 px; report: {output / "pay-journey.json"}')


if __name__ == '__main__':
    main()
