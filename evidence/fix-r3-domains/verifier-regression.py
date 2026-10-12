"""Exercise the exact app verifier snippet with local synthetic JWKS and keys."""
import argparse
import base64
import io
import json
import time
from pathlib import Path
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

parser = argparse.ArgumentParser()
parser.add_argument('--doc', type=Path, default=Path(__file__).resolve().parents[2] / 'docs/APPS-DOMAINS.md')
args = parser.parse_args()
scope = {}
exec(args.doc.read_text().split('```python\n', 1)[1].split('```', 1)[0], scope)
old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
def jwk(key, kid):
    x = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {'kid': kid, 'kty': 'OKP', 'crv': 'Ed25519', 'alg': 'EdDSA', 'use': 'sig', 'x': base64.urlsafe_b64encode(x).decode().rstrip('=')}
published = {'keys': [jwk(old, 'old')]}
fetches = []
def fetch(*args, **kwargs):
    fetches.append([k['kid'] for k in published['keys']])
    response = io.BytesIO(json.dumps(published).encode())
    response.headers = {'Cache-Control': 'public, max-age=60'}
    return response

def token(key=old, kid='old', **changes):
    now = int(time.time())
    claims = {'iss': scope['ISSUER'], 'aud': scope['HOST'], 'sub': 'ad38bf44-0c4a-40ce-bdee-2d8579bf63cc', 'account_id': 'ad38bf44-0c4a-40ce-bdee-2d8579bf63cc', 'provider': 'google', 'email': 'one@example.com', 'email_verified': True, 'idp': 'google', 'iat': now, 'nbf': now, 'exp': now + 120}
    claims.update(changes)
    return jwt.encode(claims, key, algorithm='EdDSA', headers={'kid': kid})
def verify(raw):
    return scope['verify']({'X-Tunn-Identity': raw})
def rejected(raw):
    try:
        verify(raw)
    except (jwt.PyJWTError, ValueError):
        return
    raise AssertionError('unsafe token accepted')

with patch('jwt.jwks_client.urllib.request.urlopen', fetch):
    for provider in ['github', 'magic_link', 'google']:
        assert verify(token(provider=provider, idp=provider)) == 'one@example.com'
    missing_account = jwt.decode(token(), options={'verify_signature': False})
    del missing_account['account_id']
    rejected(jwt.encode(missing_account, old, algorithm='EdDSA', headers={'kid': 'old'}))
    for raw in [token(aud='other.example.com'), token(iss='https://evil.test'), token(email_verified=False), token(idp='github'), token(provider='unknown', idp='unknown'), token(sub='different-account'), token(sub='', account_id=''), token(exp=int(time.time())-1), jwt.encode({}, '', algorithm='none', headers={'kid': 'old'}), jwt.encode({}, b'public-key-as-secret', algorithm='HS256', headers={'kid': 'old'})]:
        rejected(raw)
    assert scope['keys'].jwk_set_cache.lifespan == 60, 'documented verifier must explicitly bound its JWKS cache to 60 seconds'
    initial_fetches = len(fetches)
    published = {'keys': [jwk(new, 'new')]}
    stamp = scope['keys'].jwk_set_cache.jwk_set_with_timestamp.get_timestamp()
    with patch('jwt.jwk_set_cache.time.monotonic', return_value=stamp + 59):
        # A fresh token from a compromised retired seed remains trusted inside
        # the configured cache interval; token wall-clock stays real.
        assert verify(token()) == 'one@example.com'
        assert len(fetches) == initial_fetches
    with patch('jwt.jwk_set_cache.time.monotonic', return_value=stamp + 61):
        rejected(token())
        assert len(fetches) > initial_fetches
        assert verify(token(new, 'new')) == 'one@example.com'
    for age in [181, 301]:
        with patch('jwt.jwk_set_cache.time.monotonic', return_value=stamp + age):
            rejected(token())
            assert verify(token(new, 'new')) == 'one@example.com'
print(json.dumps({'PyJWT_version': jwt.__version__, 'JWKS_cache_seconds': 60, 'removed_key_accepted_at_59_seconds': True, 'removed_key_rejected_at_61_181_301_seconds': True, 'new_key_accepted': True, 'supported_providers': ['github', 'magic_link', 'google'], 'negative_identity_checks': 'PASS', 'network': 'mocked local JWKS only'}, indent=2))
