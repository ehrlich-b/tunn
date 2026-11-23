#!/usr/bin/env python3
"""Walk both Pro offers through real HTTPS handlers and an in-memory provider.

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
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import subprocess
import struct
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[2]
STEPS = ['pricing', 'go-pro-sign-in', 'sign-in-link-sent', 'fixture-checkout',
         'signed-webhook', 'return-account-pro']
CONTROLS = ('unsigned-webhook', 'other-account-webhook', 'replayed-checkout')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parsed(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            assert key not in out, 'duplicate JSON field'
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=unique)


def equal_json(actual, expected):
    # JSON equality must distinguish booleans, integers and floating point values.
    assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True), 'canonical fixture fields differ'


def signed_receipt(receipt, intent_created):
    assert re.fullmatch(r't=(0|[1-9][0-9]*),v1=[0-9a-f]{64}', receipt['signature']), 'strict fixture signature header required'
    timestamp, signature = receipt['signature'].split(',')
    assert timestamp.startswith('t=') and signature.startswith('v1=')
    received = receipt['received_unix']
    assert type(received) is int and received > 0, 'integer POST delivery time required'
    assert received - 300 <= int(timestamp[2:]) <= received + 300, 'fixture signature outside POST delivery window'
    signed = timestamp[2:] + '.' + receipt['body']
    expected = hmac.new(b'whsec_first_fixture', signed.encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, signature[3:]), 'fixture webhook signature differs'
    event = parsed(receipt['body'])
    assert event['type'] == 'checkout.session.completed'
    # Match the real parser's supported-checkout boundary. A fixture HMAC
    # authenticates the body but cannot make a one-time payment reconcile.
    assert event['data']['object'].get('mode') == 'subscription', 'signed control must represent a subscription checkout'
    # Match recordCheckoutPayment's completion window (CheckoutResumeWindow).
    # The fixture always supplies an explicit completion time; a signed body
    # predating its database intent or reaching expiry cannot prove reconciliation.
    completed = event.get('created')
    assert type(intent_created) is int and intent_created > 0, 'control must retain the database intent creation time'
    assert type(completed) is int and intent_created <= completed < intent_created + 24 * 60 * 60, 'signed control completion must be within its intent window'
    return event


def checkout_event(event_id, issued, reference, metadata_account=None):
    obj = dict(id='cs_first', customer='cus_first', subscription='sub_first',
               mode='subscription', payment_status='paid', client_reference_id=reference)
    if metadata_account is not None:
        obj['metadata'] = {'account_id': metadata_account}
    return dict(id=event_id, created=issued, type='checkout.session.completed', data={'object': obj})


def verify_capture(case, report_path, receipts, positive=False):
    authority = case['authority']
    run = f"{case['period'] if positive else case['name']}-{case['width']}"
    capture = parsed((report_path.parent / (run + '-capture.json')).read_bytes())
    assert set(capture) == {'run', 'start_unix', 'end_unix', 'posts', 'intents'}
    assert capture['run'] == run
    start, end = capture['start_unix'], capture['end_unix']
    assert type(start) is type(end) is int and 0 < start <= end, 'invalid capture run bounds'
    posts = capture['posts']
    assert len(posts) == len(receipts), 'capture POST count differs'
    target, reference = authority['target_account'], authority['target_reference']
    payment_reference = reference if positive else authority['payment_reference']
    owner = target if positive or case['name'] == 'unsigned-webhook' else authority['donor_account']
    intents = capture['intents']
    assert len(intents) == (1 if owner == target else 2), 'unexpected captured intents'
    by_reference = {i['reference']: i for i in intents}
    assert len(by_reference) == len(intents)
    assert set(by_reference) == {reference, payment_reference}
    for ref, account, email in ((reference, target, authority['target_email']),
                                (payment_reference, owner, authority['target_email'] if owner == target else 'donor@example.invalid')):
        intent = by_reference[ref]
        assert set(intent) == {'reference', 'account', 'email', 'created_unix'}
        assert intent['account'] == account and intent['email'] == email
        assert type(intent['created_unix']) is int and start <= intent['created_unix'] <= end, 'intent outside capture run'
    issued = by_reference[payment_reference]['created_unix']
    assert authority['payment_intent_created_unix'] == issued
    for index, (post, receipt) in enumerate(zip(posts, receipts)):
        assert set(post) == {'capture_id', 'run', 'received_unix', 'method', 'path', 'session_account',
                             'body', 'signature', 'body_sha256', 'http_status', 'response_body', 'response_sha256'}
        assert post['run'] == run and type(post['capture_id']) is int and post['capture_id'] == index + 1
        assert set(receipt) == (set(post) - {'run'}) | ({'result'} if positive else set())
        equal_json({k: v for k, v in receipt.items() if k != 'result'}, {k: v for k, v in post.items() if k != 'run'})
        received = post['received_unix']
        assert type(received) is int and start <= received <= end, 'POST outside capture run'
        assert received >= max(i['created_unix'] for i in intents), 'POST predates database intent'
        if index:
            assert posts[index - 1]['received_unix'] <= received, 'POST capture order differs'
        assert receipt['method'] == 'POST' and receipt['path'] == '/webhooks/stripe'
        assert receipt['session_account'] == ('' if positive else target)
        assert digest(receipt['body'].encode()) == receipt['body_sha256']
        assert digest(receipt['response_body'].encode()) == receipt['response_sha256']
        if positive or case['name'] != 'unsigned-webhook':
            signed_receipt(receipt, issued)
        event_id = 'evt_checkout' if positive else ('evt_control_replay' if index == 3 else 'evt_control')
        ref = reference if positive or index >= 2 else payment_reference
        equal_json(parsed(receipt['body']), checkout_event(event_id, issued, ref, None if positive else target))
        if not positive and case['name'] == 'unsigned-webhook':
            assert receipt['signature'] == '' and receipt['http_status'] == 400
            assert receipt['response_body'] == 'Missing signature\n'
        elif not positive and index == 2:
            assert receipt['http_status'] == 503 and receipt['response_body'] == 'Billing event not committed\n'
        else:
            result = dict(event_id=event_id, account_id=owner, state='reconciled', duplicate=index == 1)
            assert type(receipt['http_status']) is int and receipt['http_status'] == 200
            equal_json(parsed(receipt['response_body']), result)
            if positive:
                equal_json(receipt['result'], result)


class AccountHTML(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.badge, self.message, self.email, self.capture = '', '', '', None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'span' and 'plan-badge' in attrs.get('class', '').split() and not self.badge:
            self.capture = 'badge'
        elif tag == 'span' and 'mail' in attrs.get('class', '').split() and not self.email:
            self.capture = 'email'
        elif tag == 'p' and attrs.get('id') == 'billing-status':
            self.capture = 'message'

    def handle_endtag(self, tag):
        if tag in ('span', 'p'):
            self.capture = None

    def handle_data(self, data):
        if self.capture:
            setattr(self, self.capture, getattr(self, self.capture) + data)


def verify_page(page, plan, report_path):
    html = (report_path.parent / page['html_file']).read_bytes()
    assert digest(html) == page['html_sha256']
    assert digest(page['status_body'].encode()) == page['status_sha256']
    status = json.loads(page['status_body'])
    parsed = AccountHTML(html.decode())
    assert page['email'] == parsed.email.strip()
    assert page['status_http'] == 200
    assert status['plan'] == page['plan'] == page['badge'] == parsed.badge.strip() == plan
    assert status['state'] == page['state'] == ('active' if plan == 'pro' else 'pending')
    assert parsed.message.strip() == page['message']
    claims = parsed.badge.strip() == 'pro' or parsed.message.startswith('Pro is on.')
    assert page['claims_pro'] == claims == (plan == 'pro')
    assert parsed.message.startswith('Pro is on.' if plan == 'pro' else 'Pro activation is pending.')


def verify_control(case, report_path):
    name = case['name']
    assert name in CONTROLS and case['result'] == 'PASS'
    assert case['browser_errors'] == case['blocked_external_requests'] == []
    assert case['expected_plan'] == case['actual_plan'] == 'free'
    verify_page(case['before_page'], 'free', report_path)
    verify_page(case['after_page'], 'free', report_path)
    steps = STEPS[:4] + ['before-account-free', 'control-response', 'return-account-free']
    if name == 'replayed-checkout':
        steps += ['idempotent-owner-pro']
        verify_page(case['donor_page'], 'pro', report_path)
    assert [s['name'] for s in case['steps']] == steps
    assert case['steps'][4]['account_page'] == case['before_page']
    assert case['steps'][6]['account_page'] == case['after_page']
    authority = case['authority']
    assert authority['name'] == name
    assert authority['target_email'] == f'stranger+{name}-{case["width"]}@example.com'
    assert case['before_page']['email'] == case['after_page']['email'] == authority['target_email']
    if name == 'replayed-checkout':
        assert case['donor_page']['email'] == 'donor@example.invalid'
        assert case['steps'][7]['account_page'] == case['donor_page']
    assert authority['before_plan'] == authority['expected_plan'] == authority['after_plan'] == 'free'
    assert authority['target_mappings'] == 0
    want = 0 if name == 'unsigned-webhook' else 1
    assert authority['automatic_audits'] == want
    assert authority['provider_reads'] == (2 if name == 'replayed-checkout' else want)
    raw = (report_path.parent / case['steps'][5]['receipt']).read_bytes()
    assert digest(raw) == case['steps'][5]['receipt_sha256']
    receipt_file = json.loads(raw)
    equal_json(receipt_file, {k: v for k, v in authority.items() if k not in {'target_mappings', 'automatic_audits', 'provider_reads'}})
    receipts = authority['receipts']
    assert len(receipts) == (4 if name == 'replayed-checkout' else 1)
    if name == 'replayed-checkout':
        assert authority['payment_account'] == authority['donor_account']
        assert authority['recorded_payment_reference'] == authority['payment_reference']
    target = authority['target_account']
    assert target and authority['target_reference']
    for i, receipt in enumerate(receipts):
        assert receipt['method'] == 'POST' and receipt['path'] == '/webhooks/stripe'
        assert receipt['session_account'] == target
        assert digest(receipt['body'].encode()) == receipt['body_sha256']
        assert digest(receipt['response_body'].encode()) == receipt['response_sha256']
        event = parsed(receipt['body'])
        obj = event['data']['object']
        assert event['id'] == ('evt_control_replay' if i == 3 else 'evt_control')
        assert obj['metadata']['account_id'] == target
        assert obj['subscription'] == 'sub_first' and obj['customer'] == 'cus_first'
        if name == 'unsigned-webhook':
            assert event['type'] == 'checkout.session.completed'
            assert obj['mode'] == 'subscription' and obj['payment_status'] == 'paid', 'unsigned control must represent a paid subscription checkout'
            assert obj['id'] == 'cs_first'
            assert receipt['signature'] == '' and receipt['http_status'] == 400
            assert receipt['response_body'].strip() == 'Missing signature'
            assert obj['client_reference_id'] == authority['target_reference']
            assert authority['donor_account'] == authority['donor_plan'] == ''
        else:
            signed_receipt(receipt, authority['payment_intent_created_unix'])
            assert authority['donor_account'] and authority['donor_account'] != target
            assert authority['donor_plan'] == 'pro'
            assert authority['payment_reference'] != authority['target_reference']
            if i == 2:
                assert receipt['http_status'] == 503
                assert receipt['response_body'].strip() == 'Billing event not committed'
                assert obj['client_reference_id'] == authority['target_reference']
                assert receipt['body'] != receipts[0]['body']
            else:
                assert obj['client_reference_id'] == authority['target_reference' if i == 3 else 'payment_reference']
                if i == 3:
                    original = json.loads(receipts[0]['body'])
                    original['id'] = 'evt_control_replay'
                    original['data']['object']['client_reference_id'] = authority['target_reference']
                    assert event == original, 'fresh replay must reuse the paid checkout'
                result = json.loads(receipt['response_body'])
                assert receipt['http_status'] == 200 and result['state'] == 'reconciled'
                assert result['event_id'] == event['id']
                assert result['account_id'] == authority['donor_account']
                assert result['duplicate'] == (i == 1)
                if i == 1:
                    assert receipt['body'] == receipts[0]['body']
                    assert receipt['signature'] == receipts[0]['signature']

    verify_capture(case, report_path, receipts)


def verify(report_path):
    """Check local disposable fixture consistency, never production attestation.

    Public fixture keys/hashes bind captured local inputs and outcomes only.
    Delivery is checked against capture, so offline verification never expires.
    """
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
        assert authority['width'] == width
        assert authority['provider_reads'] == authority['mappings'] == authority['automatic_audits'] == 1
        assert authority['webhook_status'] == 200 and authority['webhook_state'] == 'reconciled'
        assert authority['period_seconds'] == (30 if period == 'monthly' else 365) * 24 * 3600
        for step in case['steps']:
            image = report_path.parent / step['screenshot']
            raw = image.read_bytes()
            assert raw[:8] == b'\x89PNG\r\n\x1a\n', image
            image_width, height = struct.unpack('>II', raw[16:24])
            assert image_width == width and height >= 900, image
        receipt = parsed((report_path.parent / case['steps'][4]['receipt']).read_bytes())
        assert receipt['http_status'] == 200 and receipt['result']['state'] == 'reconciled'
        signed_receipt(receipt, authority['payment_intent_created_unix'])
        verify_capture(case, report_path, [receipt], positive=True)
        final = case['steps'][-1]
        assert final['expected_plan'] == final['actual_plan'] == 'pro' and final['state'] == 'active'
        verify_page(final['account_page'], 'pro', report_path)
        assert final['account_page']['email'] == authority['target_email']
        assert authority['target_email'] == f'stranger+{period}-{width}@example.com'
    controls = report['negative_controls']
    assert len(controls) == 6
    assert {(c['name'], c['width']) for c in controls} == {(n, w) for n in CONTROLS for w in (390, 1440)}
    targets = [c['authority']['target_account'] for c in controls]
    assert len(set(targets)) == 6, 'negative accounts must be isolated'
    for case in controls:
        verify_control(case, report_path)
    for case in report['cases'] + controls:
        for step in case['steps']:
            raw = (report_path.parent / step['screenshot']).read_bytes()
            assert digest(raw) == step['screenshot_sha256']
            assert raw[:8] == b'\x89PNG\r\n\x1a\n'
            width, height = struct.unpack('>II', raw[16:24])
            assert width == case['width'] and height >= 900
            if 'receipt' in step:
                assert digest((report_path.parent / step['receipt']).read_bytes()) == step['receipt_sha256']
    print('PASS: original four journeys/24 screenshots/signed receipts and six isolated negative controls with hashed handler/page evidence')


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
    assert not any(output.iterdir()), 'use a new empty evidence directory; retain old receipts unchanged'
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
    controls = []
    for name in CONTROLS:
        for width in (390, 1440):
            run = f'{name}-{width}'
            case = json.loads((output / f'{run}-browser.json').read_text())
            case['authority'] = json.loads((output / f'{run}-authority.json').read_text())
            controls.append(case)
    report = {'negative_controls': controls, 'result': 'PASS', 'provider': 'shared firstCustomerStripeFixture (in-memory)',
              'network_policy': 'Chromium maps checkout hostname to loopback fixture; all other external names fail resolution',
              'cases': cases}
    (output / 'pay-journey.json').write_text(json.dumps(report, indent=2) + '\n')
    verify(output / 'pay-journey.json')
    print(f'PASS: monthly and yearly at 390/1440 px; report: {output / "pay-journey.json"}')


if __name__ == '__main__':
    main()
