#!/usr/bin/env bash
# Offline configuration check. Requires Python 3; never sources the env file.
set -eu
exec python3 - "$@" <<'PY'
import os
import re
import sys
from urllib.parse import urlsplit

BILLING = 'TUNN_BILLING_ENABLED'
WEBHOOK = 'TUNN_STRIPE_WEBHOOK_SECRET'
KEY = 'TUNN_STRIPE_SECRET_KEY'
PRICES = 'TUNN_STRIPE_PRO_PRICE_IDS'
URLS = ('TUNN_STRIPE_CHECKOUT_URL_MONTHLY', 'TUNN_STRIPE_CHECKOUT_URL_YEARLY')
names = (BILLING, *URLS, WEBHOOK, KEY, PRICES)
values = {name: os.environ.get(name, '') for name in names}
errors = []
notices = []

# A file is a complete snapshot, independent of the caller's environment.
# Accept literal dotenv assignments with optional export, quotes and comments.
# Reject shell expansion/commands rather than executing or guessing their values.
if len(sys.argv) > 2:
    errors.append('env file: expected at most one path')
elif len(sys.argv) == 2:
    values = dict.fromkeys(names, '')
    try:
        with open(sys.argv[1], encoding='utf-8') as source:
            for number, line in enumerate(source, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                match = re.fullmatch(r'(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', line)
                if not match:
                    errors.append(f'env file line {number}: malformed assignment')
                    continue
                name, value = match.groups()
                if name not in names:
                    continue
                if value.startswith(('"', "'")):
                    quoted = re.fullmatch(r'''(["'])(.*?)\1\s*(?:#.*)?''', value)
                    if not quoted:
                        errors.append(f'{name}: malformed literal assignment')
                        continue
                    value = quoted.group(2)
                else:
                    value = re.split(r'\s+#', value, maxsplit=1)[0].rstrip()
                if any(c in value for c in ('$', '`', '\\')):
                    errors.append(f'{name}: use a literal value without expansion or escapes')
                    continue
                values[name] = value
    except (OSError, UnicodeError):
        errors.append('env file: unreadable or invalid UTF-8')

for name, value in values.items():
    if not value:
        notices.append(f'{name}: missing')
    elif not value.strip() or any(c in value for c in '\x00\r\n'):
        errors.append(f'{name}: malformed; must be nonblank without control line breaks')

if values[BILLING] not in ('', 'true', 'false'):
    errors.append(f'{BILLING}: malformed; expected true or false')


def checkout_url(value):
    # Mirrors internal/host/revenue.go:stripeURL, including exact authority.
    try:
        u = urlsplit(value)
        return (value.startswith('https:') and u.scheme == 'https'
                and u.netloc == 'buy.stripe.com' and '#' not in value
                and u.path.startswith('/') and len(u.path) > 1
                and not any(c.isspace() or ord(c) < 32 for c in value)
                and re.search(r'%(?![0-9A-Fa-f]{2})', value) is None)
    except ValueError:
        return False


for name in URLS:
    if values[name] and not checkout_url(values[name]):
        errors.append(f'{name}: malformed; expected https://buy.stripe.com/<payment-link> without credentials or fragment')

# Config trims comma-separated entries and the server filters them with
# an ASCII alphanumeric price_ identifier of at most 128 bytes before enabling automation.
prices = [p.strip() for p in values[PRICES].split(',') if p.strip()]
approved = [p for p in prices if re.fullmatch(r'price_[A-Za-z0-9]+', p) and len(p) <= 128]
if values[PRICES] and (not prices or len(approved) != len(prices)):
    errors.append(f'{PRICES}: malformed; expected comma-separated Price IDs with the required prefix and a nonempty ASCII alphanumeric identifier, at most 128 bytes each')
for name, pattern, description in (
        (WEBHOOK, r'whsec_[A-Za-z0-9]+', 'webhook signing secret'),
        (KEY, r'sk_(?:test|live)_[A-Za-z0-9]+', 'test or live secret API key')):
    if values[name] and not re.fullmatch(pattern, values[name]):
        errors.append(f'{name}: malformed; expected {description} with a nonempty ASCII alphanumeric token')

if values[BILLING] == 'true':
    if not values[WEBHOOK]:
        errors.append(f'{WEBHOOK}: required when {BILLING} is true')
    if not any(values[name] for name in URLS):
        errors.extend(f'{name}: at least one checkout URL is required when {BILLING} is true' for name in URLS)

opened = values[BILLING] == 'true' and bool(values[WEBHOOK]) and any(checkout_url(values[name]) for name in URLS)
automatic = bool(values[KEY]) and bool(approved)
print('checkout closed' if not opened else
      'checkout open with automatic activation' if automatic else
      'checkout open with manual activation')
for notice in notices + errors:
    print(notice)
sys.exit(1 if errors else 0)
PY
