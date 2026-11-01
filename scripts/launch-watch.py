#!/usr/bin/env python3
"""Summarize existing relay slog text from `fly logs --no-tail`, offline.

Usage: python3 scripts/launch-watch.py [FILE] (stdin when FILE is omitted).
Counts are log records, not unique users, deliveries or successful payments.
INFO records require the relay's request/trace log level and retained Fly logs.
"""
import argparse
import ast
from collections import Counter
from datetime import datetime, timedelta, timezone
import re
import sys

MESSAGES = {
    'Stripe webhook received but STRIPE_WEBHOOK_SECRET not configured': ('unconfigured', 'internal/host/stripe.go:70'),
    'Stripe webhook received but storage not available': ('storage unavailable', 'internal/host/stripe.go:77'),
    'failed to read webhook body': ('body read', 'internal/host/stripe.go:85'),
    'missing Stripe-Signature header': ('missing signature', 'internal/host/stripe.go:93'),
    'invalid Stripe signature': ('invalid signature', 'internal/host/stripe.go:99'),
    'failed to parse Stripe event': ('parse', 'internal/host/stripe.go:107'),
    'failed to send magic link email': ('magic link', 'internal/host/magiclink.go:112'),
    'tunnel alert delivery failed': ('tunnel alert', 'internal/host/tunnel_alerts.go:191'),
}


# TextHandler uses Go double-quoted strings where needed, not shell quoting.
_QUOTED = r'"(?:[^"\\]|\\.)*"'
_FIELD = re.compile(r'(' + _QUOTED + r'|[^\s="]+)=(' + _QUOTED + r'|[^\s"]+)')


def parse_fields(text):
    fields = {}
    pos = 0
    while pos < len(text):
        match = _FIELD.match(text, pos)
        if not match:
            raise ValueError('invalid slog field')
        key, value = match.groups()
        if key.startswith('"'):
            key = ast.literal_eval(key)
        if value.startswith('"'):
            value = ast.literal_eval(value)
        fields[key] = value
        pos = match.end()
        if pos < len(text):
            if not text[pos].isspace():
                raise ValueError('missing field separator')
            while pos < len(text) and text[pos].isspace():
                pos += 1
    return fields


def summarize(lines, now):
    counts = Counter()
    types = Counter()
    for line in lines:
        # Fly prefixes each application line; the embedded slog time is authoritative.
        match = re.search(r'(?:^|\s|\[(?:info|error)\])(time=\S+\s+level=\S+\s+msg=)', line)
        if not match:
            counts['malformed'] += 1
            continue
        try:
            fields = parse_fields(line[match.start(1):])
            stamp = datetime.fromisoformat(fields['time'].replace('Z', '+00:00'))
            if stamp.tzinfo is None or not fields.get('level') or 'msg' not in fields:
                raise ValueError('missing field')
        except (ValueError, KeyError, SyntaxError):
            counts['malformed'] += 1
            continue
        if not now - timedelta(hours=24) <= stamp <= now:
            continue
        msg = fields['msg']
        if msg == 'received Stripe webhook':
            if 'type' not in fields:
                counts['malformed'] += 1
            else:
                types[fields['type'] or '(empty)'] += 1
        elif msg in MESSAGES:
            counts[MESSAGES[msg][0]] += 1
        elif msg == 'tunnel registered':
            counts['registrations'] += 1
    return counts, types


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', nargs='?', help='saved Fly log output (default: stdin)')
    args = parser.parse_args()
    if args.file:
        with open(args.file, encoding='utf-8', errors='replace') as stream:
            counts, types = summarize(stream, datetime.now(timezone.utc))
    else:
        counts, types = summarize(sys.stdin, datetime.now(timezone.utc))
    print('Last 24 hours; log records, not unique events (INFO may be disabled).')
    print('Stripe webhooks received by type [internal/host/stripe.go:112]:')
    for kind, count in sorted(types.items()):
        print(f'  {kind}: {count}')
    if not types:
        print('  none observed')
    print('Webhook rejections:')
    for msg, (label, source) in list(MESSAGES.items())[:6]:
        print(f'  {label}: {counts[label]} [{source}]')
    print('Email send failures:')
    for msg, (label, source) in list(MESSAGES.items())[6:]:
        print(f'  {label}: {counts[label]} [{source}]')
    print(f'Tunnel registrations (including reconnects): {counts["registrations"]} [internal/host/grpc_server.go:840]')
    print('Pro activations and activation errors, signups, first tunnel registrations, MCP consents: unavailable (not logged as such).')
    print(f'Malformed lines (all input, irrespective of time): {counts["malformed"]}')


if __name__ == '__main__':
    main()
