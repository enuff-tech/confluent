# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2026 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import copy
import fnmatch
import hashlib
import hmac
import json
import math
import re
import secrets
import time

import confluent.config.configmanager as configmanager


_SECRET_ATTRIBUTE = 'secret.apikey'
_KEYS_ATTRIBUTE = 'apikeys'
_V2_CONTEXT = b'confluent-apikey-v2:'
_KID_RE = re.compile(r'^k[a-z2-7]{26}$')
VALID_OPERATIONS = ('retrieve', 'create', 'update', 'delete', 'start')
DEFAULT_MAX_LIFETIME_DAYS = 365
MAX_KEYS_PER_USER = 64
MAX_SCOPES = 32
MAX_PATHS = 64
SCOPE_PRESETS = {
    # fnmatch's * also matches '/', so '/*' is every path
    'readonly': [{'ops': ['retrieve'], 'paths': ['/*']}],
}


def _base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def _decode_base64url(value):
    if not isinstance(value, str):
        raise ValueError('Invalid bearer token')
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def _make_jws(username, secret, expiration=None):
    header = {'alg': 'HS256', 'typ': 'JWT'}
    payload = {'sub': username, 'iat': int(time.time())}
    if expiration is not None:
        payload['exp'] = payload['iat'] + int(expiration * 86400)
    encoded_header = _base64url(json.dumps(
        header, separators=(',', ':')).encode('utf8'))
    encoded_payload = _base64url(json.dumps(
        payload, separators=(',', ':')).encode('utf8'))
    signing_input = '{0}.{1}'.format(encoded_header, encoded_payload).encode('ascii')
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return '{0}.{1}'.format(signing_input.decode('ascii'), _base64url(signature))


def _username_string(username):
    if isinstance(username, bytes):
        return username.decode('utf8')
    return str(username)


def _get_expiration(reqbody):
    if not reqbody:
        return None
    if isinstance(reqbody, bytes):
        reqbody = reqbody.decode('utf8')
    try:
        body = json.loads(reqbody)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('Request body must be JSON')
    if not isinstance(body, dict):
        raise ValueError('Request body must be a JSON object')
    if 'expiration' not in body:
        raise ValueError('expiration is required parameter')
    expiration = body['expiration']
    if not expiration:  # a false-y expiration means opt out of expiration
        return None
    if not isinstance(expiration, (int, float)) or not math.isfinite(expiration) or expiration < 0:
        raise ValueError('Invalid number specified, must be either number of days or false/null')
    return expiration


def _is_time(value):
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value))


def _user_root_secret(cfgmgr, username):
    user = cfgmgr.get_user(username, decrypt=True)
    if not user or not user.get(_SECRET_ATTRIBUTE):
        return None, user
    secret = user[_SECRET_ATTRIBUTE]['value']
    if not isinstance(secret, bytes):
        secret = secret.encode('utf8')
    return secret, user


def validate_bearer(token, cfgmgr):
    """Check a bearer token.

    Returns None when the token is not valid, else a dict describing the
    key: 'username', 'kid' (None for a legacy key), 'scopes' (None when
    the key may do anything its user may do) and 'expires' (None for a
    legacy key without expiry).
    """
    try:
        encoded_header, encoded_payload, encoded_signature = token.split('.')
        header = json.loads(_decode_base64url(encoded_header))
        payload = json.loads(_decode_base64url(encoded_payload))
        signature = _decode_base64url(encoded_signature)
    except (AttributeError, ValueError, UnicodeDecodeError, json.JSONDecodeError,
            TypeError, base64.binascii.Error):
        return None
    if not isinstance(payload, dict):
        return None
    username = payload.get('sub')
    if not isinstance(username, str) or not username:
        return None
    if header == {'alg': 'HS256', 'typ': 'JWT'}:
        return _validate_legacy(cfgmgr, username, payload, encoded_header,
                                encoded_payload, signature)
    if (isinstance(header, dict) and set(header) == {'alg', 'typ', 'kid'} and
            header['alg'] == 'HS256' and header['typ'] == 'JWT' and
            isinstance(header['kid'], str) and _KID_RE.match(header['kid'])):
        return _validate_v2(cfgmgr, username, header['kid'], payload,
                            encoded_header, encoded_payload, signature)
    return None


def _signature_ok(secret, encoded_header, encoded_payload, signature):
    signing_input = '{0}.{1}'.format(
        encoded_header, encoded_payload).encode('ascii')
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return hmac.compare_digest(signature, expected)


def _validate_legacy(cfgmgr, username, payload, encoded_header,
                     encoded_payload, signature):
    if not legacy_keys_allowed():
        return None
    expiration = payload.get('exp')
    if expiration is not None and (
            not _is_time(expiration) or expiration <= time.time()):
        return None
    secret, _ = _user_root_secret(cfgmgr, username)
    if secret is None:
        return None
    if not _signature_ok(secret, encoded_header, encoded_payload, signature):
        return None
    return {'username': username, 'kid': None, 'scopes': None,
            'expires': expiration}


def _validate_v2(cfgmgr, username, kid, payload, encoded_header,
                 encoded_payload, signature):
    root, user = _user_root_secret(cfgmgr, username)
    if root is None:
        return None
    record = user.get(_KEYS_ATTRIBUTE, {}).get(kid)
    if not isinstance(record, dict):
        return None  # revoked, or never existed
    # The stored record, not the token, decides when a key expires.
    expires = record.get('expires')
    if not _is_time(expires) or expires <= time.time():
        return None
    if payload.get('exp') != expires:
        return None
    if not _signature_ok(_key_secret(root, kid), encoded_header,
                         encoded_payload, signature):
        return None
    return {'username': username, 'kid': kid,
            'scopes': copy.deepcopy(record.get('scopes')), 'expires': expires}


def validate_bearer_token(token, cfgmgr):
    """Return the token subject when a bearer token is valid."""
    keyinfo = validate_bearer(token, cfgmgr)
    if keyinfo is None:
        return None
    return keyinfo['username']


def key_is_current(cfgmgr, keyinfo):
    """Whether a key that was valid earlier still is (not expired, not
    revoked). Used when a session established with the key is reused."""
    expires = keyinfo.get('expires')
    if expires is not None and expires <= time.time():
        return False
    root, user = _user_root_secret(cfgmgr, keyinfo['username'])
    if root is None:
        return False
    if keyinfo.get('kid') is None:
        return legacy_keys_allowed()
    return isinstance(user.get(_KEYS_ATTRIBUTE, {}).get(keyinfo['kid']), dict)


def request_allowed(keyinfo, operation, path):
    """Whether a key's scopes allow an operation on a path."""
    scopes = keyinfo.get('scopes')
    if scopes is None:
        return True
    for suffix in ('.json', '.html'):
        if path.endswith(suffix):
            path = path[:-len(suffix)]
    if path.startswith('/sessions/current/apikey'):
        # A restricted key must not be able to mint a less restricted one.
        return False
    for scope in scopes:
        if operation in scope['ops'] and any(
                fnmatch.fnmatchcase(path, pattern) for pattern in scope['paths']):
            return True
    return False


# ------------------------------------------------------------ API keys v2
#
# A v2 key has an id ('kid', carried in the token header) and a record in
# the user's 'apikeys' attribute holding its expiry, optional scopes and
# description. The key's signing secret is derived from the user's
# existing secret.apikey and the kid, so no further secret is stored:
# deleting the record revokes one key, clearing secret.apikey revokes all.

def legacy_keys_allowed():
    """Legacy keys (no kid) are accepted unless apikey.legacy is false."""
    value = configmanager.get_global('apikey.legacy')
    return value is None or bool(value)


def max_lifetime_days():
    value = configmanager.get_global('apikey.max_lifetime_days')
    if _is_time(value) and value > 0:
        return value
    return DEFAULT_MAX_LIFETIME_DAYS


def _key_secret(root, kid):
    return hmac.new(root, _V2_CONTEXT + kid.encode('ascii'),
                    hashlib.sha256).digest()


def _new_kid():
    return 'k' + base64.b32encode(secrets.token_bytes(16)).decode(
        'ascii').lower().rstrip('=')


def _make_v2_jws(username, kid, secret, issued, expires):
    header = {'alg': 'HS256', 'typ': 'JWT', 'kid': kid}
    payload = {'sub': username, 'iat': issued, 'exp': expires}
    encoded_header = _base64url(json.dumps(
        header, separators=(',', ':')).encode('utf8'))
    encoded_payload = _base64url(json.dumps(
        payload, separators=(',', ':')).encode('utf8'))
    signing_input = '{0}.{1}'.format(encoded_header, encoded_payload).encode('ascii')
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return '{0}.{1}'.format(signing_input.decode('ascii'), _base64url(signature))


def parse_scopes(scopes):
    """Validate requested scopes; None means unrestricted."""
    if scopes is None:
        return None
    if isinstance(scopes, str):
        if scopes not in SCOPE_PRESETS:
            raise ValueError('Unknown scope preset "{0}"'.format(scopes))
        return copy.deepcopy(SCOPE_PRESETS[scopes])
    if not isinstance(scopes, list) or not 0 < len(scopes) <= MAX_SCOPES:
        raise ValueError('scopes must be a preset name or a list of 1 to '
                         '{0} scopes'.format(MAX_SCOPES))
    parsed = []
    for scope in scopes:
        if not isinstance(scope, dict) or set(scope) != {'ops', 'paths'}:
            raise ValueError('each scope must have exactly "ops" and "paths"')
        ops, paths = scope['ops'], scope['paths']
        if (not isinstance(ops, list) or not ops or
                not all(op in VALID_OPERATIONS for op in ops)):
            raise ValueError('ops must be a non-empty list of: ' +
                             ', '.join(VALID_OPERATIONS))
        if (not isinstance(paths, list) or not 0 < len(paths) <= MAX_PATHS or
                not all(isinstance(p, str) and p.startswith('/') and
                        len(p) <= 512 for p in paths)):
            raise ValueError('paths must be a list of 1 to {0} patterns '
                             'starting with /'.format(MAX_PATHS))
        parsed.append({'ops': sorted(set(ops)), 'paths': list(paths)})
    return parsed


def _parse_create_body(reqbody):
    if isinstance(reqbody, bytes):
        reqbody = reqbody.decode('utf8')
    try:
        body = json.loads(reqbody) if reqbody else None
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('Request body must be JSON')
    if not isinstance(body, dict):
        raise ValueError('Request body must be a JSON object')
    unknown = set(body) - {'expiration', 'scopes', 'description'}
    if unknown:
        raise ValueError('Unknown parameters: ' + ', '.join(sorted(unknown)))
    expiration = body.get('expiration')
    limit = max_lifetime_days()
    if not _is_time(expiration) or not 0 < expiration <= limit:
        raise ValueError('expiration is required, in days, greater than 0 '
                         'and at most {0}'.format(limit))
    description = body.get('description', '')
    if not isinstance(description, str) or len(description) > 200:
        raise ValueError('description must be a string of at most 200 characters')
    return expiration, parse_scopes(body.get('scopes')), description


def _public_record(kid, record):
    return {'kid': kid, 'created': record.get('created'),
            'expires': record.get('expires'),
            'scopes': record.get('scopes'),
            'description': record.get('description', '')}


async def handle_v2_request(url, username, cfgmgr, reqbody, method):
    """/sessions/current/apikeys: create, list, show and revoke the
    calling user's own v2 keys. Returns (status, payload)."""
    username = _username_string(username)
    rest = url[len('/sessions/current/apikeys'):].strip('/')
    if rest:
        if not _KID_RE.match(rest):
            return 404, {'error': 'No such API key'}
        user = cfgmgr.get_user(username)
        records = (user or {}).get(_KEYS_ATTRIBUTE, {})
        if rest not in records:
            return 404, {'error': 'No such API key'}
        if method == 'retrieve':
            return 200, _public_record(rest, records[rest])
        if method == 'delete':
            records = dict(records)
            del records[rest]
            await cfgmgr.set_user(username, {_KEYS_ATTRIBUTE: records})
            return 200, {'revoked': True, 'kid': rest}
        return 405, {'error': 'Method Not Allowed'}
    if method == 'retrieve':
        user = cfgmgr.get_user(username)
        records = (user or {}).get(_KEYS_ATTRIBUTE, {})
        return 200, {'apikeys': [_public_record(kid, records[kid])
                                 for kid in sorted(records)]}
    if method != 'create':
        return 405, {'error': 'Method Not Allowed'}
    try:
        expiration, scopes, description = _parse_create_body(reqbody)
    except ValueError as error:
        return 400, {'error': str(error)}
    root, user = _user_root_secret(cfgmgr, username)
    if user is None:
        await cfgmgr.create_user(username, role='Stub')
    if root is None:
        root = _base64url(secrets.token_bytes(32))
        await cfgmgr.set_user(username, {_SECRET_ATTRIBUTE: root})
        root = root.encode('utf8')
    now = int(time.time())
    records = dict((kid, rec) for kid, rec in
                   (cfgmgr.get_user(username) or {}).get(_KEYS_ATTRIBUTE, {}).items()
                   if _is_time(rec.get('expires')) and rec['expires'] > now)
    if len(records) >= MAX_KEYS_PER_USER:
        return 409, {'error': 'Too many API keys; revoke some first'}
    kid = _new_kid()
    while kid in records:
        kid = _new_kid()
    expires = now + int(expiration * 86400)
    records[kid] = {'created': now, 'expires': expires, 'scopes': scopes,
                    'description': description}
    await cfgmgr.set_user(username, {_KEYS_ATTRIBUTE: records})
    result = _public_record(kid, records[kid])
    result['token'] = _make_v2_jws(username, kid, _key_secret(root, kid),
                                   now, expires)
    return 200, result

async def handle_api_request(url, username, cfgmgr, reqbody, method):
    """Handle an authenticated API-key request.

    The HTTP layer supplies the authenticated request context.  The return
    value is a ``(status, payload)`` pair for ``httpapi`` to serialize.
    """
    username = _username_string(username)
    operation = url.removeprefix('/sessions/current/apikey/')
    if method == 'retrieve':
        if operation == 'provisioned':
            user = cfgmgr.get_user(username)
            if not user or not user.get(_SECRET_ATTRIBUTE):
                return 200, {'provisioned': False}
            return 200, {'provisioned': True}
        else:
            return 405, {'error': 'Method Not Allowed'}
    if operation == 'create':
        if not legacy_keys_allowed():
            return 403, {'error': 'Legacy API keys are disabled; use '
                                  '/sessions/current/apikeys'}
        try:
            expiration = _get_expiration(reqbody)
        except ValueError as error:
            return 400, {'error': str(error)}
        user = cfgmgr.get_user(username, decrypt=True)
        if user is None:
            await cfgmgr.create_user(username, role='Stub')
            user = cfgmgr.get_user(username, decrypt=True)
        secret = user.get(_SECRET_ATTRIBUTE, {}).get('value', None)
        if not secret:
            secret = secrets.token_bytes(32)
            secret = _base64url(secret)
            await cfgmgr.set_user(username, {_SECRET_ATTRIBUTE: secret})
        if isinstance(secret, str):
            secret = secret.encode('utf8')
        return 200, {'jws': _make_jws(username, secret, expiration)}
    if operation == 'provisioned':
        user = cfgmgr.get_user(username)
        if not user or not user.get(_SECRET_ATTRIBUTE):
            return 200, {'provisioned': False}
        return 200, {'provisioned': True}
    if operation == 'revokeall':
        user = cfgmgr.get_user(username, decrypt=True)
        if user is None:
            return 200, {'revoked': True, 'msg': "User doesn't exist"}
        if not user.get(_SECRET_ATTRIBUTE):
            return 200, {'revoked': True, 'msg': "No API keys to revoke"}
        # Without the secret no key validates; drop the v2 records too.
        await cfgmgr.set_user(username, {_SECRET_ATTRIBUTE: None,
                                         _KEYS_ATTRIBUTE: {}})
        return 200, {'revoked': True}
    return 404, {'error': 'Unknown API-key operation'}