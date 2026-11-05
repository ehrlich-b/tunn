#!/usr/bin/env python3
"""Real Chromium attacks against the disposable TLS relay and two accounts.

Invoked by make test-cross-tenant. All DNS resolves to loopback; external
requests are refused. HAR files embed every request, response and body.
"""
import json
from pathlib import Path
import sys
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

config = json.load(sys.stdin)
evidence = Path(sys.argv[1])
apex = 'https://tunn.test:' + config['port']
attacker = apex.replace('://tunn.', '://attacker.tunn.')
private = apex.replace('://tunn.', '://private.tunn.')
results = []

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True, args=[
        '--ignore-certificate-errors-spki-list=' + config['spki'], '--no-proxy-server', '--host-resolver-rules=MAP *.tunn.test 127.0.0.1, MAP tunn.test 127.0.0.1'])

    def scenario(name, person=None):
        ctx = browser.new_context( record_har_path=str(evidence / (name + '.har')),
                                  record_har_content='embed', record_har_mode='full')
        ctx.set_default_timeout(7000)
        ctx.route('**/*', lambda route: route.continue_() if
                  urlparse(route.request.url).hostname in ('tunn.test', 'attacker.tunn.test', 'private.tunn.test', 'tools.tunn.test')
                  else route.abort())
        page = ctx.new_page()
        if person:
            assert page.goto(apex + '/fixture/login?person=' + person).status == 200
        return ctx, page

    def done(name, ctx, exploited, detail):
        ctx.close()  # Flush the HAR before evaluating the result.
        result = 'exploited' if exploited else 'blocked'
        results.append(dict(scenario=name, result=result, detail=detail, traffic=name + '.har'))
        print(result.upper() + ': ' + name, flush=True)

    def plant(page):
        page.evaluate('plantCookies()')

    name = 'set-cookie-parent'
    ctx, page = scenario(name, 'owner')
    response = page.goto(attacker + '/headers')
    emitted = [h['value'] for h in response.headers_array() if h['name'].lower() == 'set-cookie']
    page.goto(apex + '/account')
    done(name, ctx, bool(emitted) or 'attacker@example.com' in page.inner_text('body'), 'Publisher reserved Set-Cookie fields filtered')

    name = 'document-cookie-shadow'
    ctx, page = scenario(name, 'owner')
    page.goto(attacker + '/')
    plant(page)
    page.goto(apex + '/account')
    text = page.inner_text('body')
    done(name, ctx, 'attacker@example.com' in text or 'owner@example.com' not in text,
         'Sibling JavaScript tries parent cookies at / and /account; owner identity must survive')

    name = 'login-fixation'
    ctx, page = scenario(name)
    page.goto(attacker + '/')
    plant(page)
    page.goto(apex + '/account')
    fixed = 'attacker@example.com' in page.inner_text('body')
    done(name, ctx, fixed, 'Signed-out visitor must remain on sign-in, never become attacker')
    if config['negative'] == 'true':
        # This is the same detection path as the protected run, not an expected
        # result override. The Go test requires this run to fail with fixation.
        assert fixed, 'negative fixture did not recreate cookie fixation'
        (evidence / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        browser.close()
        sys.exit(1)

    name = 'private-planted-cookie'
    ctx, page = scenario(name)
    page.goto(attacker + '/')
    plant(page)
    page.goto(private + '/')
    planted_denied = '/auth/login' in page.url
    # Positive controls exercise the complete new handoff and existing ACL.
    page.goto(apex + '/fixture/login?person=owner')
    page.goto(private + '/')
    owner_admitted = page.inner_text('body') == 'fixture'
    other = ctx.new_page()
    other.goto(apex + '/fixture/login?person=attacker')
    # A new browser context avoids reusing the owner's host-only app session.
    wrong_ctx, wrong = scenario(name + '-wrong-account', 'attacker')
    denied = wrong.goto(private + '/').status == 403
    wrong_ctx.close()
    done(name, ctx, not (planted_denied and owner_admitted and denied),
         'Plant denied; real owner handoff succeeds; real attacker account gets 403')

    for name, target, values in [
        ('csrf-account', '/account/emails', {'action': 'add', 'email': 'attacker@example.com'}),
        ('csrf-sharing', '/account/sharing?tunnel=private', {'action': 'share', 'email': 'attacker@example.com'}),
        ('csrf-logout', '/auth/logout', {}),
    ]:
        ctx, page = scenario(name, 'owner')
        # Supply a valid owner token as a stronger test of the exact-origin check.
        page.goto(apex + ('/account' if name == 'csrf-account' else target))
        token = page.locator('input[name="csrf_token"]').first.get_attribute('value')
        values['csrf_token'] = token
        page.goto(attacker + '/')
        with page.expect_response(lambda r: r.url == apex + target and r.request.method == 'POST') as pending:
            page.evaluate('args => postToAccount(args.url, args.values)', {'url': apex + target, 'values': values})
        response = pending.value
        assert response.request.headers['origin'] == attacker
        assert response.headers.get('x-fixture-fetch-site') == 'same-site', response.headers
        body = response.text()
        done(name, ctx, response.status != 403 or 'Invalid request origin' not in body,
             'Real same-site cross-origin form with valid victim CSRF token receives 403')

    name = 'cookie-reading'
    ctx, page = scenario(name, 'owner')
    owner_cookie = next(c for c in ctx.cookies() if c['name'] == '__Host-tunn_auth')
    # Also prove stripping on pre-migration parent-domain credentials actually
    # sent by the browser, rather than relying only on host-only transport.
    ctx.add_cookies([{'name': 'tunn_auth', 'value': owner_cookie['value'], 'domain': '.tunn.test',
                      'path': '/', 'secure': True, 'httpOnly': True},
                     {'name': 'app_cookie', 'value': 'keep', 'url': attacker}])
    response = page.goto(attacker + '/read')
    upstream = response.json()
    script_cookies = page.evaluate('document.cookie')
    leaked = owner_cookie['value'] in json.dumps(upstream) or owner_cookie['value'] in script_cookies
    done(name, ctx, leaked or upstream.get('Cookie') != 'app_cookie=keep',
         'Real parent cookie stripped before publisher; HttpOnly/host-only blocks script reads; app cookie preserved')

    name = 'mcp-consent-frame'
    ctx, page = scenario(name, 'owner')
    response = page.goto(apex + config['consent'])
    assert response.status == 200, (response.status, response.text())
    assert "frame-ancestors 'none'" in response.headers.get('content-security-policy', '')
    page.goto(attacker + '/')
    messages = []
    page.on('console', lambda message: messages.append(message.text))
    with page.expect_response(lambda r: '/oauth/authorize?' in r.url):
        page.evaluate('url => frameConsent(url)', apex + config['consent'])
    page.wait_for_timeout(500)
    blocked = any('frame-ancestors' in m for m in messages)
    (evidence / 'frame-console.json').write_text(json.dumps(messages, indent=2) + '\n')
    done(name, ctx, not blocked, 'Real consent renders directly; Chromium refuses attacker iframe by CSP')
    browser.close()

(evidence / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
assert all(r['result'] == 'blocked' for r in results), 'cross-tenant exploit detected'
print('PASS: all cross-tenant attacks blocked; positive controls passed')
