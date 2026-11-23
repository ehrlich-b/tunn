#!/usr/bin/env python3
"""Small delivery-clock and canonical-event fragments, with no browser or sleep."""
import copy
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('journey', Path(__file__).with_name('pay-journey.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
issued = 1800000000
receipt = {'body': json.dumps(v.checkout_event('evt_checkout', issued, 'reference')), 'received_unix': issued}

def sign(timestamp):
    r = copy.deepcopy(receipt)
    r['signature'] = 't='+str(timestamp)+',v1='+hmac.new(b'whsec_first_fixture', (str(timestamp)+'.'+r['body']).encode(), hashlib.sha256).hexdigest()
    return r

for delta in (-300, 0, 300):
    with patch('time.time', return_value=issued+86400*365):
        v.signed_receipt(sign(issued+delta), issued)
for timestamp in (1, issued-301, issued+301, 'no', '', '-1', '1.0', '+1800000000', '01800000000'):
    try:
        v.signed_receipt(sign(timestamp), issued)
    except AssertionError:
        pass
    else:
        raise AssertionError('accepted bad timestamp '+str(timestamp))
for completed in (issued, issued+86399):
    r = sign(issued)
    e = json.loads(r['body'])
    e['created'] = completed
    r['body'] = json.dumps(e)
    r['signature'] = 't='+str(issued)+',v1='+hmac.new(b'whsec_first_fixture', (str(issued)+'.'+r['body']).encode(), hashlib.sha256).hexdigest()
    v.signed_receipt(r, issued)
print('PASS: delivery +/-300 inclusive, +/-301/ancient/future/malformed rejected; completion boundaries retained; advanced verifier clock independent')

# Check the full independent capture binding on one small synthetic POST.
r = sign(issued)
r.update(capture_id=1, method='POST', path='/webhooks/stripe', session_account='',
         http_status=200, response_body=json.dumps(dict(event_id='evt_checkout', account_id='account', state='reconciled', duplicate=False)))
r['result'] = json.loads(r['response_body'])
r['body_sha256'] = v.digest(r['body'].encode())
r['response_sha256'] = v.digest(r['response_body'].encode())
case = {'period':'monthly', 'width':390, 'authority':dict(target_account='account', target_reference='reference',
         target_email='stranger+monthly-390@example.com', payment_intent_created_unix=issued)}
capture = dict(run='monthly-390', start_unix=issued-1, end_unix=issued+1,
               posts=[dict({k:val for k,val in r.items() if k != 'result'},run='monthly-390')],
               intents=[dict(reference='reference', account='account', email=case['authority']['target_email'], created_unix=issued)])
for delta in (-300,0,300):
    candidate = copy.deepcopy(r)
    candidate['signature'] = sign(issued+delta)['signature']
    captured = copy.deepcopy(capture)
    captured['posts'][0]['signature'] = candidate['signature']
    with patch.object(Path,'read_bytes',return_value=json.dumps(captured).encode()):
        v.verify_capture(case,Path('/unused/report.json'),[candidate],positive=True)
for field in capture:
    changed = copy.deepcopy(capture)
    changed.pop(field)
    with patch.object(Path,'read_bytes',return_value=json.dumps(changed).encode()):
        try: v.verify_capture(case,Path('/unused/report.json'),[r],positive=True)
        except (KeyError,AssertionError): pass
        else: raise AssertionError('accepted absent capture '+field)
for field,value in [('received_unix',issued-2),('received_unix','1800000000'),('capture_id',2),('body','{}')]:
    changed = copy.deepcopy(capture)
    changed['posts'][0][field] = value
    with patch.object(Path,'read_bytes',return_value=json.dumps(changed).encode()):
        try: v.verify_capture(case,Path('/unused/report.json'),[r],positive=True)
        except (KeyError,AssertionError): pass
        else: raise AssertionError('accepted inconsistent capture '+field)
print('PASS: full capture fragment binds canonical POST, DB intent, run bounds, receipt and response; missing/inconsistent capture rejected')
