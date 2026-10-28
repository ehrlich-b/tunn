#!/usr/bin/env python3
"""Disposable TLS browser acceptance for app session renewal and recovery."""
import json, sys
from playwright.sync_api import sync_playwright

port, spki = sys.argv[1:]
app = 'https://dashboard.apps.example.com'
apex = 'https://tunn.test'
with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True, args=[
        '--no-proxy-server', '--disable-background-networking',
        '--ignore-certificate-errors-spki-list=' + spki,
        '--host-resolver-rules=MAP dashboard.apps.example.com 127.0.0.1:' + port + ', MAP tunn.test 127.0.0.1:' + port + ', MAP * ~NOTFOUND'])
    context = browser.new_context()
    page = context.new_page()
    page.goto(app + '/', wait_until='load')
    assert page.url == app + '/' and 'Fixture app' in page.content(), page.url
    def cookie(name):
        return next((c['value'] for c in context.cookies() if c['name'] == name), None)
    first = cookie('__Host-tunn_app')
    assert first
    # Use a platform tab for clock control so there is no cross-origin fetch.
    admin = context.new_page(); admin.goto(apex + '/fixture/clock?seconds=0')
    def clock(seconds):
        admin.goto(apex + '/fixture/clock?seconds=' + str(seconds))
    clock(600)
    assert page.evaluate('poll()')['status'] == 200
    second = cookie('__Host-tunn_app')
    assert second and second != first, 'browser did not replace cookie'
    clock(12 * 3600 + 1)
    assert page.evaluate('poll()')['status'] == 200, 'polling failed beyond old 12-hour expiry'
    assert cookie('__Host-tunn_app') != second
    # Application-origin 401 must not be interpreted as tunn login recovery.
    ordinary = page.evaluate("poll('/ordinary-401')")
    assert ordinary['status'] == 401 and ordinary['auth'] is None, ordinary
    navigations = []
    page.on('framenavigated', lambda frame: navigations.append(frame.url) if frame == page.main_frame else None)
    assert page.evaluate("recover('/ordinary-401')") == 401
    page.wait_for_timeout(100)
    assert not navigations, navigations
    assert page.url == app + '/' and page.evaluate('typeof poll') == 'function'
    other = context.new_page(); other.goto(app + '/')
    clock(7 * 24 * 3600)
    before = cookie('__Host-tunn_sso')
    denied = page.evaluate('poll()')
    assert denied == {'status':401, 'auth':'login', 'location':None}, denied
    assert cookie('__Host-tunn_sso') == before, 'background poll changed nonce'
    # Hold the next top-level callback; another tab must not replace its nonce.
    page.evaluate('setTimeout(() => recover(), 0)')
    admin.wait_for_function("fetch('/fixture/pending').then(r => r.text()).then(t => t === 'true')", timeout=10000)
    nonce = cookie('__Host-tunn_sso')
    assert nonce
    denied2 = other.evaluate('poll()')
    assert denied2['status'] == 401 and denied2['auth'] == 'login', denied2
    assert cookie('__Host-tunn_sso') == nonce, 'second tab replaced pending nonce'
    with page.expect_navigation(url=app + '/', wait_until='load'):
        admin.evaluate("fetch('/fixture/release')")
    assert page.evaluate('poll()')['status'] == 200
    print(json.dumps({'browser':'PASS', 'tls':'disposable TLS', 'provider':'real magic-link verification with fixture delivery', 'cookie_replacement':'PASS', 'old_12h_expiry':'PASS', 'cap_401_no_redirect_or_nonce_churn':'PASS', 'top_level_recovery':'PASS', 'pending_callback_second_tab':'PASS', 'upstream_401':'PASS'}))
    browser.close()
