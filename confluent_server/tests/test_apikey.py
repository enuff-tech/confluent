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

"""API keys: v2 keys (id, expiry, scopes, revocation), legacy keys, and
how the HTTP layer holds sessions to the key that opened them."""

import base64
import json
import time

import pytest
from aiohttp.test_utils import make_mocked_request

import confluent.apikey as apikey
import confluent.config.configmanager as configmanager

V2 = '/sessions/current/apikeys'


@pytest.fixture
async def cfm(confluent_config):
    configmanager.init_masterkey()
    cfm = confluent_config.manager()
    await cfm.create_user('alice', role='Administrator')
    await cfm.create_user('bob', role='Administrator')
    return cfm


async def _create(cfm, user='alice', **body):
    body.setdefault('expiration', 30)
    status, data = await apikey.handle_v2_request(
        V2, user, cfm, json.dumps(body).encode(), 'create')
    assert status == 200, data
    return data


async def _legacy_token(cfm, user='alice', expiration=None):
    status, data = await apikey.handle_api_request(
        '/sessions/current/apikey/create', user, cfm,
        json.dumps({'expiration': expiration}).encode(), 'create')
    assert status == 200, data
    return data['jws']


def _parts(token):
    def dec(part):
        return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
    head, payload, sig = token.split('.')
    return dec(head), dec(payload), sig


def _enc(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(',', ':')).encode()).rstrip(b'=').decode()


# ------------------------------------------------------------ v2 keys

async def test_create_and_validate_v2_key(cfm):
    data = await _create(cfm, description='ci')
    head, payload, _ = _parts(data['token'])
    assert head == {'alg': 'HS256', 'typ': 'JWT', 'kid': data['kid']}
    assert payload['sub'] == 'alice' and payload['exp'] == data['expires']
    assert 29 * 86400 < data['expires'] - time.time() <= 30 * 86400
    info = apikey.validate_bearer(data['token'], cfm)
    assert info == {'username': 'alice', 'tenant': None, 'kid': data['kid'], 'scopes': None,
                    'expires': data['expires']}
    assert apikey.validate_bearer_token(data['token'], cfm) == 'alice'


async def test_list_and_show_never_return_secrets(cfm):
    a = await _create(cfm, description='one')
    b = await _create(cfm, scopes='readonly')
    status, listing = await apikey.handle_v2_request(V2, 'alice', cfm, b'', 'retrieve')
    assert status == 200
    assert sorted(k['kid'] for k in listing['apikeys']) == sorted([a['kid'], b['kid']])
    text = json.dumps(listing)
    assert 'token' not in text and a['token'] not in text
    status, shown = await apikey.handle_v2_request(V2 + '/' + b['kid'], 'alice', cfm, b'', 'retrieve')
    assert status == 200 and shown['scopes'] == apikey.SCOPE_PRESETS['readonly']
    status, _ = await apikey.handle_v2_request(V2 + '/' + b['kid'], 'bob', cfm, b'', 'retrieve')
    assert status == 404  # another user's key is not visible
    status, _ = await apikey.handle_v2_request(V2 + '/../x', 'alice', cfm, b'', 'retrieve')
    assert status == 404


async def test_revoking_one_key_leaves_others(cfm):
    a = await _create(cfm)
    b = await _create(cfm)
    status, data = await apikey.handle_v2_request(V2 + '/' + a['kid'], 'alice', cfm, b'', 'delete')
    assert status == 200 and data == {'revoked': True, 'kid': a['kid']}
    assert apikey.validate_bearer(a['token'], cfm) is None
    assert apikey.validate_bearer(b['token'], cfm)['kid'] == b['kid']
    status, _ = await apikey.handle_v2_request(V2 + '/' + a['kid'], 'alice', cfm, b'', 'delete')
    assert status == 404


async def test_revokeall_revokes_v2_and_legacy_keys(cfm):
    v2 = await _create(cfm)
    legacy = await _legacy_token(cfm)
    status, _ = await apikey.handle_api_request(
        '/sessions/current/apikey/revokeall', 'alice', cfm, b'', 'create')
    assert status == 200
    assert apikey.validate_bearer(v2['token'], cfm) is None
    assert apikey.validate_bearer(legacy, cfm) is None
    assert cfm.get_user('alice').get('apikeys') == {}


@pytest.mark.parametrize('body', [
    {}, {'expiration': 0}, {'expiration': -1}, {'expiration': 366},
    {'expiration': True}, {'expiration': 'ten'}, {'expiration': float('nan')},
    {'expiration': 1, 'unknown': 1}, {'expiration': 1, 'description': 'x' * 201},
    {'expiration': 1, 'scopes': 'admin'}, {'expiration': 1, 'scopes': []},
    {'expiration': 1, 'scopes': [{'ops': ['retrieve']}]},
    {'expiration': 1, 'scopes': [{'ops': ['explode'], 'paths': ['/*']}]},
    {'expiration': 1, 'scopes': [{'ops': ['retrieve'], 'paths': ['nodes']}]},
])
async def test_invalid_create_requests(cfm, body):
    status, data = await apikey.handle_v2_request(
        V2, 'alice', cfm, json.dumps(body).encode(), 'create')
    assert status == 400, data
    assert cfm.get_user('alice').get('apikeys', {}) == {}


async def test_site_maximum_lifetime(cfm):
    configmanager.set_global('apikey.max_lifetime_days', 7)
    status, _ = await apikey.handle_v2_request(
        V2, 'alice', cfm, json.dumps({'expiration': 8}).encode(), 'create')
    assert status == 400
    assert (await _create(cfm, expiration=7))['kid']


async def test_expired_key_is_rejected(cfm, monkeypatch):
    data = await _create(cfm, expiration=1)
    later = time.time() + 2 * 86400
    monkeypatch.setattr(apikey.time, 'time', lambda: later)
    assert apikey.validate_bearer(data['token'], cfm) is None


async def test_expired_records_are_pruned_and_count_is_capped(cfm, monkeypatch):
    stale = await _create(cfm, expiration=1)
    later = time.time() + 2 * 86400
    monkeypatch.setattr(apikey.time, 'time', lambda: later)
    for _ in range(apikey.MAX_KEYS_PER_USER):
        await _create(cfm)
    records = cfm.get_user('alice')['apikeys']
    assert stale['kid'] not in records
    assert len(records) == apikey.MAX_KEYS_PER_USER
    status, _ = await apikey.handle_v2_request(
        V2, 'alice', cfm, json.dumps({'expiration': 1}).encode(), 'create')
    assert status == 409


async def test_tampered_tokens_are_rejected(cfm):
    data = await _create(cfm)
    head, payload, sig = _parts(data['token'])
    other = await _create(cfm, user='bob')
    forged = [
        # different subject with alice's signature
        '.'.join([_enc(head), _enc(dict(payload, sub='bob')), sig]),
        # later expiry than the record
        '.'.join([_enc(head), _enc(dict(payload, exp=payload['exp'] + 86400)), sig]),
        # bob's kid presented as alice
        '.'.join([_enc(dict(head, kid=other['kid'])), _enc(payload), sig]),
        # extra header field, and alg none
        '.'.join([_enc(dict(head, x=1)), _enc(payload), sig]),
        '.'.join([_enc(dict(head, alg='none')), _enc(payload), '']),
        # malformed kid and junk
        '.'.join([_enc(dict(head, kid='../x')), _enc(payload), sig]),
        'not-a-token', '', 'a.b.c',
    ]
    for token in forged:
        assert apikey.validate_bearer(token, cfm) is None, token


async def test_v2_keys_survive_restart_and_dump_reload(cfm, confluent_config):
    data = await _create(cfm, scopes='readonly')
    confluent_config.restart()
    cfm = confluent_config.manager()
    assert apikey.validate_bearer(data['token'], cfm)['kid'] == data['kid']

    dump = cfm._real_dump_to_json()
    await cfm._load_from_json(dump)
    info = apikey.validate_bearer(data['token'], confluent_config.manager())
    assert info['scopes'] == apikey.SCOPE_PRESETS['readonly']


# ------------------------------------------------------------ scopes

@pytest.mark.parametrize('scopes,operation,path,expected', [
    (None, 'delete', '/nodes/n1', True),
    ('readonly', 'retrieve', '/nodes/n1/power/state', True),
    ('readonly', 'retrieve', '/nodes/n1/power/state.json', True),
    ('readonly', 'update', '/nodes/n1/power/state', False),
    ('readonly', 'retrieve', '/sessions/current/apikeys', False),
    ([{'ops': ['retrieve', 'update'], 'paths': ['/nodes/*/power/state']}],
     'update', '/nodes/n1/power/state', True),
    ([{'ops': ['retrieve', 'update'], 'paths': ['/nodes/*/power/state']}],
     'update', '/nodes/n1/boot/nextdevice', False),
    ([{'ops': ['create'], 'paths': ['/noderange/*']}], 'create', '/sessions/current/apikey/create', False),
])
def test_request_allowed(scopes, operation, path, expected):
    keyinfo = {'username': 'alice', 'kid': 'k' + 'a' * 26,
               'scopes': apikey.parse_scopes(scopes), 'expires': None}
    assert apikey.request_allowed(keyinfo, operation, path) is expected


# ------------------------------------------------------------ legacy keys

async def test_legacy_keys_still_work(cfm):
    token = await _legacy_token(cfm, expiration=False)
    info = apikey.validate_bearer(token, cfm)
    assert info == {'username': 'alice', 'tenant': None, 'kid': None, 'scopes': None, 'expires': None}


async def test_legacy_keys_can_be_disabled(cfm):
    legacy = await _legacy_token(cfm)
    v2 = await _create(cfm)
    configmanager.set_global('apikey.legacy', False)
    assert apikey.validate_bearer(legacy, cfm) is None
    assert apikey.validate_bearer(v2['token'], cfm) is not None
    status, _ = await apikey.handle_api_request(
        '/sessions/current/apikey/create', 'alice', cfm,
        json.dumps({'expiration': 1}).encode(), 'create')
    assert status == 403


# ------------------------------------------------------------ HTTP layer

class _AuditLog(object):
    def __init__(self):
        self.entries = []

    def log(self, entry):
        self.entries.append(entry)


@pytest.fixture
def http(cfm, monkeypatch):
    import confluent.httpapi as httpapi
    monkeypatch.setattr(httpapi, 'auditlog', _AuditLog())
    monkeypatch.setattr(httpapi, 'httpsessions', {})
    return httpapi


async def _request(httpapi, method, path, token=None, session=None):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if session:
        headers['ConfluentSession'] = session
    req = make_mocked_request(method, path, headers=headers)
    return await httpapi._authorize_request(req, httpapi.opmap[method], b'')


async def test_http_scoped_key_and_its_session(http, cfm):
    data = await _create(cfm, scopes='readonly')
    first = await _request(http, 'GET', '/nodes/', token=data['token'])
    assert first['code'] == 200 and first['username'] == 'alice'
    session = first['sessionid']
    assert (await _request(http, 'POST', '/nodes/', token=data['token'])) == {'code': 403}
    # the session the key opened is held to the same scopes...
    assert (await _request(http, 'GET', '/nodes/', session=session))['code'] == 200
    assert (await _request(http, 'POST', '/nodes/', session=session)) == {'code': 403}
    assert (await _request(http, 'GET', V2, session=session)) == {'code': 403}
    # ...and ends when the key is revoked
    await apikey.handle_v2_request(V2 + '/' + data['kid'], 'alice', cfm, b'', 'delete')
    assert (await _request(http, 'GET', '/nodes/', session=session)) == {'code': 401}
    assert session not in http.httpsessions
    assert (await _request(http, 'GET', '/nodes/', token=data['token'])) == {'code': 401}


async def test_http_session_ends_when_key_expires(http, cfm, monkeypatch):
    data = await _create(cfm, expiration=1)
    session = (await _request(http, 'GET', '/nodes/', token=data['token']))['sessionid']
    later = time.time() + 2 * 86400
    monkeypatch.setattr(apikey.time, 'time', lambda: later)
    assert (await _request(http, 'GET', '/nodes/', session=session)) == {'code': 401}


async def test_http_unscoped_and_legacy_keys(http, cfm):
    v2 = await _create(cfm)
    assert (await _request(http, 'POST', '/nodes/', token=v2['token']))['code'] == 200
    legacy = await _legacy_token(cfm)
    session = (await _request(http, 'GET', '/nodes/', token=legacy))['sessionid']
    assert (await _request(http, 'POST', '/nodes/', session=session))['code'] == 200
    configmanager.set_global('apikey.legacy', False)
    assert (await _request(http, 'GET', '/nodes/', session=session)) == {'code': 401}


async def test_http_bad_token_is_unauthorized(http, cfm):
    assert (await _request(http, 'GET', '/nodes/', token='junk')) == {'code': 401}
