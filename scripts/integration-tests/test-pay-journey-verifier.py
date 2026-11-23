#!/usr/bin/env python3
"""Try plausible corrupted reports against the independent payment verifier."""
import copy
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pay_journey', Path(__file__).with_name('pay-journey.py'))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
report_path = Path(sys.argv[1]).resolve()
original = json.loads(report_path.read_text())
verifier.verify(report_path)
read_text, read_bytes = Path.read_text, Path.read_bytes
rejected = 0


def reject(name, change, reason=None):
    global rejected
    report = copy.deepcopy(original)
    replacements = {}
    change(report, replacements)
    def text(path, *args, **kwargs):
        return json.dumps(report) if path == report_path else read_text(path, *args, **kwargs)
    def raw(path):
        return replacements[path] if path in replacements else read_bytes(path)
    with patch.object(Path, 'read_text', text), patch.object(Path, 'read_bytes', raw):
        try:
            verifier.verify(report_path)
        except (AssertionError, KeyError, ValueError, TypeError, FileNotFoundError) as error:
            if reason:
                assert reason in str(error), (name, error)
            print('PASS rejected:', name, str(error))
            rejected += 1
        else:
            raise AssertionError('verifier accepted ' + name)


for name in verifier.CONTROLS:
    reject('missing '+name, lambda r, f, n=name: r.__setitem__('negative_controls', [c for c in r['negative_controls'] if c['name'] != n]))
reject('authoritative plan mismatch', lambda r, f: r['negative_controls'][0]['authority'].__setitem__('after_plan', 'pro'))
reject('page claim mismatch', lambda r, f: r['negative_controls'][0]['after_page'].__setitem__('claims_pro', True))


def forged_html(report, files):
    page = report['negative_controls'][0]['after_page']
    path = report_path.parent / page['html_file']
    raw = read_bytes(path).replace(b'Pro activation is pending.', b'Pro is on.')
    files[path] = raw
    page['html_sha256'] = hashlib.sha256(raw).hexdigest()
    page['message'] = 'Pro is on.'
    page['claims_pro'] = True


reject('forged page HTML with recomputed hash', forged_html)


def forged_receipt(report, files):
    case = next(c for c in report['negative_controls'] if c['name'] == 'other-account-webhook')
    receipt = case['authority']['receipts'][0]
    receipt['body'] = receipt['body'].replace('"payment_status":"paid"', '"payment_status":"unpaid"')
    receipt['body_sha256'] = hashlib.sha256(receipt['body'].encode()).hexdigest()
    step = case['steps'][5]
    path = report_path.parent / step['receipt']
    control = json.loads(read_bytes(path))
    control['receipts'] = copy.deepcopy(case['authority']['receipts'])
    raw = json.dumps(control).encode()
    files[path] = raw
    step['receipt_sha256'] = hashlib.sha256(raw).hexdigest()


reject('forged signed receipt with recomputed body/file hashes', forged_receipt, 'fixture webhook signature differs')

def altered_control(report, files, name, index, change, resign=False, width=390):
    case = next(c for c in report['negative_controls'] if c['name'] == name and c['width'] == width)
    receipt = case['authority']['receipts'][index]
    event = json.loads(receipt['body'])
    change(event)
    receipt['body'] = json.dumps(event, separators=(',', ':'))
    receipt['body_sha256'] = hashlib.sha256(receipt['body'].encode()).hexdigest()
    if resign:
        timestamp = receipt['signature'].split(',')[0]
        signed = timestamp[2:] + '.' + receipt['body']
        receipt['signature'] = timestamp + ',v1=' + hmac.new(b'whsec_first_fixture', signed.encode(), hashlib.sha256).hexdigest()
    step = case['steps'][5]
    path = report_path.parent / step['receipt']
    control = json.loads(read_bytes(path))
    control['receipts'] = copy.deepcopy(case['authority']['receipts'])
    raw = json.dumps(control).encode()
    files[path] = raw
    step['receipt_sha256'] = hashlib.sha256(raw).hexdigest()


reject('unsigned unpaid checkout with recomputed body/file hashes',
       lambda r, f: altered_control(r, f, 'unsigned-webhook', 0,
                                   lambda e: e['data']['object'].__setitem__('payment_status', 'unpaid')),
       'unsigned control must represent a paid subscription checkout')
reject('fresh replay collapsed to existing event ID with valid fixture signature',
       lambda r, f: altered_control(r, f, 'replayed-checkout', 3,
                                   lambda e: e.__setitem__('id', 'evt_control'), resign=True))
reject('fresh replay changed checkout with valid fixture signature',
       lambda r, f: altered_control(r, f, 'replayed-checkout', 3,
                                   lambda e: e['data']['object'].__setitem__('id', 'cs_other'), resign=True),
       'fresh replay must reuse the paid checkout')

# A valid fixture HMAC cannot make an unsupported checkout mode demonstrate
# reconciliation. Cover the other owner's payment and every replay response,
# including the intentional conflict and harmless idempotent duplicate.
for name, count in (('other-account-webhook', 1), ('replayed-checkout', 4)):
    for width in (390, 1440):
        for index in range(count):
            for mode in ('payment', 'setup', None):
                def change_mode(event, mode=mode):
                    obj = event['data']['object']
                    if mode is None:
                        obj.pop('mode')
                    else:
                        obj['mode'] = mode
                reject(f'{name}/{width} receipt {index} mode {mode!r} with valid fixture signature',
                       lambda r, f: altered_control(r, f, name, index, change_mode, resign=True, width=width),
                       'signed control must represent a subscription checkout')

# Completion timestamps are signed too, but must independently match the retained
# database intent window. Re-sign and rehash each mutation to reach that check.
for name, count in (('other-account-webhook', 1), ('replayed-checkout', 4)):
    for width in (390, 1440):
        case = next(c for c in original['negative_controls'] if c['name'] == name and c['width'] == width)
        issued = case['authority']['payment_intent_created_unix']
        for index in range(count):
            for completed in (1, issued - 1, issued + 86400, issued + 86401, 0, -1, None, str(issued), True):
                reject(f'{name}/{width} receipt {index} completion {completed!r} with valid fixture signature',
                       lambda r, f: altered_control(r, f, name, index,
                                                   lambda e: e.__setitem__('created', completed), resign=True, width=width),
                       'signed control completion must be within its intent window')
            reject(f'{name}/{width} receipt {index} missing completion with valid fixture signature',
                   lambda r, f: altered_control(r, f, name, index,
                                               lambda e: e.pop('created'), resign=True, width=width),
                   'signed control completion must be within its intent window')

        # Billing accepts completion at creation and immediately before expiry.
        # Exercise both boundaries without changing any supplied evidence.
        for completed in (issued, issued + 86400 - 1):
            receipt = copy.deepcopy(case['authority']['receipts'][0])
            event = json.loads(receipt['body'])
            event['created'] = completed
            receipt['body'] = json.dumps(event, separators=(',', ':'))
            timestamp = receipt['signature'].split(',')[0]
            signed = timestamp[2:] + '.' + receipt['body']
            receipt['signature'] = timestamp + ',v1=' + hmac.new(b'whsec_first_fixture', signed.encode(), hashlib.sha256).hexdigest()
            verifier.signed_receipt(receipt, issued)
        print(f'PASS: {name}/{width} completion window includes creation and excludes expiry')

reject('missing original positive journey', lambda r, f: r['cases'].pop())
reject('changed screenshot', lambda r, f: r['cases'][0]['steps'][0].__setitem__('screenshot_sha256', '0'*64))
assert rejected == 142, rejected
print(f'PASS: preserved all {rejected} existing corruption checks')


# Regenerate every unrelated hash/capture binding in memory so each mutation
# reaches the semantic contract. Never rewrite the retained input evidence.
def resign(receipt, timestamp=None):
    if timestamp is None:
        timestamp = receipt['signature'].split(',')[0][2:]
    timestamp = str(timestamp)
    receipt['signature'] = 't='+timestamp+',v1='+hmac.new(b'whsec_first_fixture', (timestamp+'.'+receipt['body']).encode(), hashlib.sha256).hexdigest()


def rewrite(report, files, positive, name, width, index, change, sync=True):
    case = next(c for c in report['cases' if positive else 'negative_controls']
                if c['width'] == width and c['period' if positive else 'name'] == name)
    step = case['steps'][4 if positive else 5]
    path = report_path.parent / step['receipt']
    blob = json.loads(read_bytes(path))
    receipts = [blob] if positive else case['authority']['receipts']
    change(receipts[index])
    for r in receipts:
        r['body_sha256'] = verifier.digest(r['body'].encode())
        r['response_sha256'] = verifier.digest(r['response_body'].encode())
    if not positive:
        blob['receipts'] = copy.deepcopy(receipts)
    raw = json.dumps(blob).encode()
    files[path] = raw
    step['receipt_sha256'] = verifier.digest(raw)
    run = f'{name}-{width}'
    path = report_path.parent / (run+'-capture.json')
    capture = json.loads(read_bytes(path))
    if sync:
        for post, r in zip(capture['posts'], receipts):
            for key in list(post):
                if key != 'run':
                    if key in r:
                        post[key] = r[key]
                    else:
                        post.pop(key) # only used by deliberate missing-field mutations
    files[path] = json.dumps(capture).encode()


def payload_change(receipt, keys, value, remove=False):
    event = json.loads(receipt['body'])
    parent = event
    for key in keys[:-1]:
        parent = parent[key]
    if remove:
        parent.pop(keys[-1])
    else:
        parent[keys[-1]] = value
    receipt['body'] = json.dumps(event, separators=(',', ':'))
    if receipt['signature']:
        resign(receipt)


positions = [(False, n, w, i) for n, count in (('unsigned-webhook', 1), ('other-account-webhook', 1), ('replayed-checkout', 4))
             for w in (390, 1440) for i in range(count)]
positions += [(True, p, w, 0) for p in ('monthly', 'yearly') for w in (390, 1440)]
fields = [(('data',), {}), (('data','object'), {}), (('id',), 'evt_other'), (('type',), 'invoice.paid'), (('created',), 1),
          (('data','object','id'), 'cs_other'), (('data','object','customer'), 'cus_other'),
          (('data','object','subscription'), 'sub_other'), (('data','object','mode'), 'payment'),
          (('data','object','payment_status'), 'unpaid'), (('data','object','client_reference_id'), 'other')]
extras = [('extra',), ('data','extra'), ('data','object','extra')]
for positive, name, width, index in positions:
    label = f'{name}/{width}/{index}'
    relevant = fields + ([] if positive else [(('data','object','metadata'), {}), (('data','object','metadata','account_id'), 'other')])
    for keys, value in relevant:
        for remove in (False, True):
            reject(f'{label} canonical {keys} remove={remove}',
                   lambda r, f, k=keys, val=value, rem=remove: rewrite(r, f, positive, name, width, index,
                       lambda receipt: payload_change(receipt, k, val, rem)))
    for keys in extras + ([('data','object','metadata')] if positive else [('data','object','metadata','extra')]):
        reject(f'{label} unexpected field {keys}', lambda r, f, k=keys: rewrite(r, f, positive, name, width, index,
               lambda receipt: payload_change(receipt, k, 'extra')))
    for key, value in (('http_status', 201), ('method', 'GET'), ('path', '/wrong'), ('session_account', 'other')):
        reject(f'{label} receipt {key}', lambda r, f, k=key, val=value: rewrite(r, f, positive, name, width, index,
               lambda receipt: receipt.__setitem__(k, val)))
    if name == 'unsigned-webhook' or (not positive and index == 2):
        reject(f'{label} error response extras', lambda r, f: rewrite(r, f, positive, name, width, index,
               lambda receipt: receipt.__setitem__('response_body', receipt['response_body']+'extra')))
    else:
        for key, value in (('event_id', 'evt_other'), ('account_id', 'other'), ('state', 'ignored'), ('duplicate', index != 1), ('extra', True)):
            for remove in ((False,) if key == 'extra' else (False, True)):
                def response_change(receipt, key=key, value=value, remove=remove):
                    response = json.loads(receipt['response_body'])
                    if remove: response.pop(key)
                    else: response[key] = value
                    receipt['response_body'] = json.dumps(response)
                    if positive: receipt['result'] = copy.deepcopy(response)
                reject(f'{label} response {key} remove={remove}', lambda r, f: rewrite(r, f, positive, name, width, index, response_change))
    if name != 'unsigned-webhook':
        # Every signed position, including duplicate/conflict receipts and positives.
        for timestamp in (1, 'future', 'past', 'no', '', 'missing', 'extra', 'duplicate', 'bad-hmac'):
            def signature_change(receipt, timestamp=timestamp):
                value = receipt['received_unix'] + 301 if timestamp == 'future' else receipt['received_unix'] - 301 if timestamp == 'past' else timestamp
                resign(receipt, value)
                if timestamp == 'missing': receipt['signature'] = receipt['signature'].split(',')[1]
                if timestamp == 'extra': receipt['signature'] += ',v0=extra'
                if timestamp == 'duplicate': receipt['signature'] += ','+receipt['signature']
                if timestamp == 'bad-hmac': receipt['signature'] = receipt['signature'].split(',')[0]+',v1='+'0'*64
            reject(f'{label} signed timestamp/header {timestamp}', lambda r, f: rewrite(r, f, positive, name, width, index, signature_change))
        source_case = next(c for c in original['cases' if positive else 'negative_controls'] if c['width'] == width and c['period' if positive else 'name'] == name)
        receipt = json.loads(read_bytes(report_path.parent / source_case['steps'][4]['receipt'])) if positive else copy.deepcopy(source_case['authority']['receipts'][index])
        issued = source_case['authority']['payment_intent_created_unix']
        for delta in (-300, 300):
            boundary = copy.deepcopy(receipt)
            resign(boundary, boundary['received_unix']+delta)
            verifier.signed_receipt(boundary, issued)
        print(f'PASS: {label} delivery +/-300 inclusive')
        for mode in ('payment', 'setup', None):
            reject(f'{label} historical mode {mode}', lambda r, f, mode=mode: rewrite(r, f, positive, name, width, index,
                   lambda receipt: payload_change(receipt, ('data','object','mode'), mode)))
    for value in (None, '1', True, 0, 1, 9999999999):
        reject(f'{label} malformed/out-of-run capture {value}', lambda r, f, value=value: rewrite(r, f, positive, name, width, index,
               lambda receipt: receipt.__setitem__('received_unix', value)))
    for field in ('capture_id', 'received_unix'):
        reject(f'{label} missing receipt capture {field}', lambda r, f, field=field: rewrite(r, f, positive, name, width, index,
               lambda receipt: receipt.pop(field), sync=False))
    reject(f'{label} wrong POST capture index', lambda r, f: rewrite(r, f, positive, name, width, index,
           lambda receipt: receipt.__setitem__('capture_id', 99)))
    reject(f'{label} receipt/capture mismatch', lambda r, f: rewrite(r, f, positive, name, width, index,
           lambda receipt: receipt.__setitem__('received_unix', receipt['received_unix']+1), sync=False))

# The raw control file is a complete witness, not an optional subset of authority.
for name in verifier.CONTROLS:
    for width in (390,1440):
        case = next(c for c in original['negative_controls'] if c['name']==name and c['width']==width)
        step=case['steps'][5]
        original_blob=json.loads(read_bytes(report_path.parent/step['receipt']))
        for key in list(original_blob)+['all']:
            def truncate_control(report,files,key=key):
                case=next(c for c in report['negative_controls'] if c['name']==name and c['width']==width)
                step=case['steps'][5]
                blob=copy.deepcopy(original_blob)
                if key=='all': blob={}
                else: blob.pop(key)
                raw=json.dumps(blob).encode()
                files[report_path.parent/step['receipt']]=raw
                step['receipt_sha256']=verifier.digest(raw)
            reject(f'{name}/{width} truncated control witness {key}',truncate_control)

for positive, name, width, index in positions:
    if index: continue
    for field in ('start_unix', 'end_unix', 'posts', 'intents', 'run'):
        def missing_capture(report, files, field=field):
            path = report_path.parent / f'{name}-{width}-capture.json'
            capture = json.loads(read_bytes(path))
            capture.pop(field)
            files[path] = json.dumps(capture).encode()
        reject(f'{name}/{width} missing capture {field}', missing_capture)
    def absent_capture(report, files):
        files[report_path.parent / f'{name}-{width}-capture.json'] = b'{}'
    reject(f'{name}/{width} absent capture', absent_capture)

for positive, name, width, index in positions:
    if index: continue
    for field in ('start_unix', 'end_unix'):
        for value in (None, True, '1', 0, 9999999999 if field == 'start_unix' else 1):
            def bad_bounds(report, files, field=field, value=value):
                path = report_path.parent / f'{name}-{width}-capture.json'
                capture = json.loads(read_bytes(path))
                capture[field] = value
                files[path] = json.dumps(capture).encode()
            reject(f'{name}/{width} invalid run bound {field}={value}', bad_bounds)
    for field,value in (('reference','other'),('account','other'),('email','other@example.invalid'),('created_unix',1)):
        def bad_intent(report, files, field=field, value=value):
            path = report_path.parent / f'{name}-{width}-capture.json'
            capture = json.loads(read_bytes(path))
            capture['intents'][0][field] = value
            files[path] = json.dumps(capture).encode()
        reject(f'{name}/{width} DB ownership/time {field}', bad_intent)
for period in ('monthly','yearly'):
    for width in (390,1440):
        for field,value in (('expected_plan','free'),('actual_plan','free'),('state','pending')):
            reject(f'{period}/{width} positive final {field}', lambda r, f, field=field, value=value:
                   next(c for c in r['cases'] if c['period']==period and c['width']==width)['steps'][-1].__setitem__(field,value))
        for field,value in (('state','pending'),('duplicate',True),('extra',True)):
            reject(f'{period}/{width} positive parsed result {field}', lambda r, f, field=field,value=value:
                   rewrite(r,f,True,period,width,0,lambda receipt: receipt['result'].__setitem__(field,value)))

with patch('time.time', return_value=4000000000):
    verifier.verify(report_path)
print('PASS: genuine captured report remains valid after simulated verifier clock advance')
print(f'PASS: all {rejected} corrupted reports rejected independently; every signed position, canonical field and response covered')
