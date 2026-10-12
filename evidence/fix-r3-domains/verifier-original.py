import base64
import io
import json
import time
from pathlib import Path
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
doc = (ROOT / 'docs/APPS-DOMAINS.md').read_text()
snippet = doc.split('```python\n', 1)[1].split('```', 1)[0]
scope = {}
exec(snippet, scope)
old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
def jwk(key, kid):
    x = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {'kid': kid, 'kty': 'OKP', 'crv': 'Ed25519', 'alg': 'EdDSA', 'use': 'sig', 'x': base64.urlsafe_b64encode(x).decode().rstrip('=')}
old_jwk, new_jwk = jwk(old, 'old'), jwk(new, 'new')
published = {'keys': [old_jwk]}
fetches = []
def fetch(*args, **kwargs):
    fetches.append(list(k['kid'] for k in published['keys']))
    response = io.BytesIO(json.dumps(published).encode())
    response.headers = {'Cache-Control': 'public, max-age=60'}
    return response
def token(key=old, kid='old', **changes):
    now = int(time.time())
    claims = {'iss': scope['ISSUER'], 'aud': scope['HOST'], 'sub': 'owner-subject',
              'email': 'ehrlich.bryan@gmail.com', 'email_verified': True, 'idp': 'google',
              'iat': now, 'nbf': now, 'exp': now + 120}
    claims.update(changes)
    return jwt.encode(claims, key, algorithm='EdDSA', headers={'kid': kid})
def verify(raw):
    return scope['verify']({'X-Tunn-Identity': raw})
rejected = []
with patch('jwt.jwks_client.urllib.request.urlopen', fetch):
    assert verify(token()) == 'ehrlich.bryan@gmail.com'
    for name, raw in [
        ('wrong_audience', token(aud='reports.apps.ehrlich.dev')),
        ('wrong_issuer', token(iss='https://evil.test')),
        ('unverified_email', token(email_verified=False)),
        ('wrong_provider', token(idp='github')),
        ('expired', token(iat=int(time.time()) - 180, nbf=int(time.time()) - 180, exp=int(time.time()) - 60)),
        ('HS256_confusion', jwt.encode({'iss': scope['ISSUER'], 'aud': scope['HOST']}, b'public-key-as-secret', algorithm='HS256', headers={'kid': 'old'})),
        ('none_algorithm', jwt.encode({}, key='', algorithm='none', headers={'kid': 'old'})),
    ]:
        try:
            verify(raw)
        except (jwt.PyJWTError, ValueError):
            rejected.append(name)
        else:
            raise AssertionError(name + ' accepted')
    initial_fetches = len(fetches)
    published = {'keys': [new_jwk]}
    # Simulate cache age only; JWT wall-clock remains real, so a freshly signed
    # old-key token models a compromised retired seed, not an expired token.
    stamp = scope['keys'].jwk_set_cache.jwk_set_with_timestamp.get_timestamp()
    with patch('jwt.jwk_set_cache.time.monotonic', return_value=stamp + 181):
        assert verify(token()) == 'ehrlich.bryan@gmail.com'
        assert len(fetches) == initial_fetches
    with patch('jwt.jwk_set_cache.time.monotonic', return_value=stamp + 301):
        try:
            verify(token())
        except jwt.PyJWKClientError:
            pass
        else:
            raise AssertionError('Removed key survived expired JWKS cache')
    assert verify(token(new, 'new')) == 'ehrlich.bryan@gmail.com'
result = {'PyJWT_version': jwt.__version__, 'rejected': rejected,
          'JWKS_default_cache_seconds': scope['keys'].jwk_set_cache.lifespan,
          'removed_key_accepted_with_cache_age_181_seconds': True,
          'removed_key_rejected_with_cache_age_301_seconds': True,
          'new_key_accepted': True, 'fetches': fetches,
          'network': 'JWKS responses mocked locally; no external requests.'}
(ROOT / 'evidence/fix-r3-domains/verifier-original-result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
