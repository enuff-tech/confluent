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

"""Platform and tenant principals, tenant enrollment, the /tenants API and
tenant-scoped sessions and API keys."""

import asyncio
import base64
import json
import time

import pytest
from aiohttp.test_utils import make_mocked_request

import confluent.apikey as apikey
import confluent.auth as auth
import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.exceptions as exc
import confluent.tenancy as tenancy

PASSWORD = 'correct horse battery'
V2 = '/sessions/current/apikeys'


@pytest.fixture
async def mt(confluent_config):
    configmanager.init_masterkey()
    configmanager.set_global('tenancy.schema', configmanager.TENANCY_SCHEMA)
    configmanager.set_global('multitenancy.enabled', True)
    return confluent_config


async def _tenant(name, admin='admin'):
    record = await tenancy.create(name)
    if admin:
        await tenancy.redeem_enrollment(name, record['enrollment_token'], admin, PASSWORD)
    return record['id']


async def _api(path, operation, inputdata=None):
    rsp = await core.handle_path(path, operation, configmanager.ConfigManager(None), inputdata)
    return [getattr(r, 'kvpairs', None) or r for r in rsp]


def _ok(result):
    return bool(result) and result is not False


# ------------------------------------------------------- tenants API

async def test_tenants_api_needs_multitenancy(confluent_config):
    with pytest.raises(exc.NotFoundException):
        await _api('/tenants/', 'retrieve')


async def test_create_returns_token_once_and_hides_it_afterwards(mt):
    created = (await _api('/tenants/', 'create', {'name': 'acme'}))[0]
    assert created['name'] == 'acme' and created['enrollment_token']
    assert created['enrollment_pending'] is True
    shown = (await _api('/tenants/acme', 'retrieve'))[0]
    assert shown['id'] == created['id']
    text = json.dumps(shown)
    assert created['enrollment_token'] not in text and 'hash' not in text
    assert shown['nodes'] == 0 and shown['users'] == 0
    listing = await _api('/tenants/', 'retrieve')
    assert [c.kvpairs if hasattr(c, 'kvpairs') else c for c in listing]


async def test_state_and_delete_through_api(mt):
    tid = await _tenant('acme')
    with pytest.raises(exc.InvalidArgumentException):
        await _api('/tenants/' + tid, 'delete', {'confirm': 'acme'})  # still active
    assert (await _api('/tenants/acme', 'update', {'state': 'disabled'}))[0]['state'] == 'disabled'
    with pytest.raises(exc.InvalidArgumentException):
        await _api('/tenants/' + tid, 'delete', {'confirm': 'wrong'})
    await _api('/tenants/' + tid, 'delete', {'confirm': ['acme']})
    assert configmanager.list_tenants() == []
    with pytest.raises(exc.NotFoundException):
        await _api('/tenants/acme', 'retrieve')


async def test_multitenancy_switch_requires_migration(confluent_config):
    with pytest.raises(exc.InvalidArgumentException):
        await _api('/platform/multitenancy', 'update', {'enabled': True})
    configmanager.set_global('tenancy.schema', configmanager.TENANCY_SCHEMA)
    assert (await _api('/platform/multitenancy', 'update', {'enabled': 'true'}))[0]['enabled'] is True
    assert (await _api('/platform/multitenancy', 'update', {'enabled': False}))[0]['enabled'] is False


async def test_multitenancy_switch_is_replicated(mt, monkeypatch):
    sent = []

    async def followers(fnname, *args):
        sent.append((fnname, args))
    monkeypatch.setattr(configmanager, 'cfgstreams', {'peer': {}})
    monkeypatch.setattr(configmanager, 'exec_on_followers', followers)
    await configmanager.set_multitenancy_enabled(False)
    assert sent == [('_rpc_set_multitenancy_enabled', (False,))]
    assert not configmanager.multitenancy_enabled()


# ------------------------------------------------------------- enrollment

async def test_enrollment_creates_the_first_administrator_once(mt):
    record = await tenancy.create('acme')
    result = await tenancy.redeem_enrollment('acme', record['enrollment_token'], 'admin', PASSWORD)
    assert result == {'tenant': 'acme', 'username': 'admin'}
    tenant = configmanager.ConfigManager(record['id'])
    assert tenant.get_user('admin')['role'] == 'Administrator'
    assert configmanager.ConfigManager(None).get_user('admin') is None
    with pytest.raises(exc.ForbiddenRequest):
        await tenancy.redeem_enrollment('acme', record['enrollment_token'], 'other', PASSWORD)
    # with an administrator, no new token is issued
    with pytest.raises(exc.InvalidArgumentException):
        await _api('/tenants/acme/enrollment', 'create')


@pytest.mark.parametrize('case', ['wrong-token', 'unknown-tenant', 'disabled', 'expired', 'multitenancy-off'])
async def test_enrollment_refused(mt, monkeypatch, case):
    record = await tenancy.create('acme')
    token, tenant = record['enrollment_token'], 'acme'
    if case == 'wrong-token':
        token = token[:-2] + 'xx'
    elif case == 'unknown-tenant':
        tenant = 'globex'
    elif case == 'disabled':
        await configmanager.set_tenant_state(record['id'], 'disabled')
    elif case == 'expired':
        later = time.time() + tenancy.ENROLLMENT_LIFETIME + 1
        monkeypatch.setattr(configmanager.time, 'time', lambda: later)
    elif case == 'multitenancy-off':
        configmanager.set_global('multitenancy.enabled', False)
    with pytest.raises(exc.ForbiddenRequest):
        await tenancy.redeem_enrollment(tenant, token, 'admin', PASSWORD)
    assert configmanager.ConfigManager(record['id']).list_users() == []


async def test_bad_credentials_do_not_use_up_the_token(mt):
    record = await tenancy.create('acme')
    for username, password in (('bad/name', PASSWORD), ('admin', 'short'), ('', PASSWORD)):
        with pytest.raises(exc.InvalidArgumentException):
            await tenancy.redeem_enrollment('acme', record['enrollment_token'], username, password)
    await tenancy.redeem_enrollment('acme', record['enrollment_token'], 'admin', PASSWORD)


async def test_concurrent_redemption_succeeds_once(mt):
    record = await tenancy.create('acme')
    results = await asyncio.gather(*[
        tenancy.redeem_enrollment('acme', record['enrollment_token'], 'admin%d' % i, PASSWORD)
        for i in range(5)], return_exceptions=True)
    assert len([r for r in results if isinstance(r, dict)]) == 1
    assert len(configmanager.ConfigManager(record['id']).list_users()) == 1


async def test_reissued_token_replaces_the_old_one(mt):
    record = await tenancy.create('acme')
    new = (await _api('/tenants/acme/enrollment', 'create'))[0]
    with pytest.raises(exc.ForbiddenRequest):
        await tenancy.redeem_enrollment('acme', record['enrollment_token'], 'admin', PASSWORD)
    await tenancy.redeem_enrollment('acme', new['enrollment_token'], 'admin', PASSWORD)


async def test_enrollment_http_body(mt):
    record = await tenancy.create('acme')
    status, body = await tenancy.redeem_enrollment_request(b'not json')
    assert status == 400
    status, body = await tenancy.redeem_enrollment_request(json.dumps({'tenant': 'acme'}).encode())
    assert status == 400
    status, body = await tenancy.redeem_enrollment_request(json.dumps(
        {'tenant': 'acme', 'token': 'nope', 'username': 'admin', 'password': PASSWORD}).encode())
    assert status == 403 and 'token' not in json.dumps(body)
    status, body = await tenancy.redeem_enrollment_request(json.dumps(
        {'tenant': 'acme', 'token': record['enrollment_token'], 'username': 'admin',
         'password': PASSWORD}).encode())
    assert status == 200


# ------------------------------------------------------------ authorization

@pytest.mark.parametrize('path,operation,expected', [
    ('/nodes/', 'create', True),
    ('/nodes/c1/attributes/current', 'update', True),
    ('/nodegroups/compute/attributes/current', 'update', True),
    ('/noderange/c1/attributes/all', 'retrieve', True),
    ('/users/', 'create', True),
    ('/usergroups/ops', 'delete', True),
    (None, 'retrieve', True),
    ('/nodes/c1/power/state', 'update', True),
    ('/nodes/c1/sensors/hardware/all/all', 'retrieve', True),
    ('/nodes/c1/configuration/management_controller/users/1', 'update', True),
    ('/nodes/c1/power/reseat', 'update', False),
    ('/nodes/c1/power/inlets/1', 'update', False),
    ('/nodes/c1/inventory/firmware/updates/active', 'create', False),
    ('/nodes/c1/configuration/management_controller/certificate/sign', 'update', False),
    ('/nodes/c1/configuration/management_controller/save_licenses', 'update', False),
    ('/nodes/c1/media/attach', 'update', False),
    ('/nodes/c1/console/session', 'create', False),
    ('/noderange/c1/power/state', 'update', True),
    ('/discovery/rescan', 'update', True),
    ('/discovery/by-mac/02-00-00-aa-34-02', 'delete', True),
    ('/networking/macs/rescan', 'update', True),
    ('/networking/neighbors/by-switch/', 'retrieve', True),
    ('/events/decode', 'update', True),
    ('/nodes/c1/events/hardware/decode', 'update', True),
    ('/deployment/profiles/', 'retrieve', False),
    ('/events/hardware/decode', 'update', False),
    ('/tenants/', 'retrieve', False),
    ('/platform/multitenancy', 'update', False),
])
async def test_tenant_administrator_paths(mt, path, operation, expected):
    await _tenant('acme')
    assert _ok(auth.authorize('acme/admin', path, operation=operation)) is expected


async def test_tenant_operator_cannot_manage_users(mt):
    tid = await _tenant('acme')
    await configmanager.ConfigManager(tid).create_user('op', role='Operator')
    assert not _ok(auth.authorize('acme/op', '/users/', operation='create'))
    assert _ok(auth.authorize('acme/op', '/nodes/c1/attributes/current', operation='update'))


@pytest.mark.parametrize('path,operation', [
    ('/nodes/', 'retrieve'), ('/nodes/n1/power/state', 'update'),
    ('/users/', 'retrieve'), ('/discovery/', 'retrieve'),
])
async def test_platform_admin_has_no_infrastructure_access(mt, path, operation):
    await configmanager.ConfigManager(None).create_user('plat', role='PlatformAdmin')
    assert not _ok(auth.authorize('plat', path, operation=operation))


async def test_platform_paths_only_for_platform_admins(mt):
    main = configmanager.ConfigManager(None)
    await main.create_user('plat', role='PlatformAdmin')
    await main.create_user('root', role='Administrator')
    for op in ('retrieve', 'create', 'update', 'delete'):
        assert _ok(auth.authorize('plat', '/tenants/', operation=op))
        assert not _ok(auth.authorize('root', '/tenants/', operation=op))
    assert _ok(auth.authorize('plat', '/platform/multitenancy', operation='update'))
    assert not _ok(auth.authorize('root', '/platform/multitenancy', operation='update'))


async def test_platform_role_cannot_exist_in_a_tenant(mt):
    tid = await _tenant('acme')
    cfm = configmanager.ConfigManager(tid)
    with pytest.raises(ValueError):
        await cfm.create_user('plat', role='PlatformAdmin')
    with pytest.raises(ValueError):
        await cfm.set_user('admin', {'role': 'PlatformAdmin'})
    with pytest.raises(ValueError):
        await cfm.create_usergroup('plats', role='PlatformAdmin')


async def test_main_store_user_management_stays_local_only(mt):
    await configmanager.ConfigManager(None).create_user('root', role='Administrator')
    assert not _ok(auth.authorize('root', '/users/', operation='create'))


async def test_same_user_name_in_default_and_tenant(mt):
    tid = await _tenant('acme', admin='bob')
    await configmanager.ConfigManager(None).create_user('bob', role='Monitor')
    assert not _ok(auth.authorize('bob', '/nodes/', operation='create'))
    granted = auth.authorize('acme/bob', '/nodes/', operation='create')
    assert granted[1].tenant == tid and granted[3] == tid
    assert auth.authorize('bob', '/nodes/', operation='retrieve')[1].tenant is None
    # the id works as well as the name
    assert auth.authorize(tid + '/bob', '/nodes/', operation='create')[3] == tid


@pytest.mark.parametrize('case', ['multitenancy-off', 'disabled', 'deleted', 'unknown'])
async def test_tenant_principals_fail_closed(mt, case):
    tid = await _tenant('acme')
    name = 'acme/admin'
    if case == 'multitenancy-off':
        configmanager.set_global('multitenancy.enabled', False)
    elif case == 'disabled':
        await configmanager.set_tenant_state(tid, 'disabled')
    elif case == 'deleted':
        await configmanager.set_tenant_state(tid, 'disabled')
        await configmanager.delete_tenant(tid)
    else:
        name = 'globex/admin'
    assert not _ok(auth.authorize(name, '/nodes/', operation='retrieve'))
    assert await auth.check_user_passphrase(name, PASSWORD) is None


async def test_tenant_password_login(mt):
    tid = await _tenant('acme')
    granted = await auth.check_user_passphrase('acme/admin', PASSWORD, operation='retrieve',
                                               element='/nodes/')
    assert granted[3] == tid and granted[2] == 'admin'
    assert await auth.check_user_passphrase('acme/admin', 'wrong password') is None


async def test_host_accounts_never_authenticate_tenant_users(mt, monkeypatch):
    # PAM accepts any password for 'root' and root's OS group is mapped in
    # both stores; only the main store may honour that.
    monkeypatch.setattr(auth, 'pam', object())
    monkeypatch.setattr(auth, 'pam_check', lambda pwe, user, passphrase: True)
    monkeypatch.setattr(auth, 'authworkers', None)  # run the fake in a thread
    monkeypatch.setattr(auth.userutil, 'grouplist', lambda user: ['root'])
    await configmanager.ConfigManager(None).create_usergroup('root', role='Administrator')
    tid = await _tenant('acme')
    await configmanager.ConfigManager(tid).create_usergroup('root', role='Administrator')
    assert await auth.check_user_passphrase('root', 'anything') is not None
    assert await auth.check_user_passphrase('acme/root', 'anything') is None
    assert not _ok(auth.authorize('acme/root', '/nodes/', operation='retrieve'))


async def test_tenant_consoles_are_not_started(mt, monkeypatch):
    import confluent.consoleserver as consoleserver
    tid = await _tenant('acme')
    await configmanager.ConfigManager(tid).set_node_attributes(
        {'c1': {'console.method': 'ipmi'}}, autocreate=True)

    async def refuse(*args, **kwargs):
        raise AssertionError('a tenant console was started from the host network')
    monkeypatch.setattr(consoleserver, 'connect_node', refuse)
    await consoleserver._start_tenant_sessions(configmanager.ConfigManager(tid))


# --------------------------------------------------------------- API keys

def _payload(token):
    part = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))


def _replace_payload(token, payload):
    head, _, sig = token.split('.')
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).rstrip(b'=').decode()
    return '.'.join([head, body, sig])


async def _tenant_key(tid, user='admin', **body):
    body.setdefault('expiration', 30)
    status, data = await apikey.handle_v2_request(
        V2, user, configmanager.ConfigManager(tid), json.dumps(body).encode(), 'create')
    assert status == 200, data
    return data


async def test_tenant_api_keys_carry_and_keep_their_tenant(mt):
    acme = await _tenant('acme')
    globex = await _tenant('globex')
    await configmanager.ConfigManager(None).create_user('admin', role='Administrator')
    data = await _tenant_key(acme)
    assert _payload(data['token'])['tnt'] == acme
    info = apikey.validate_bearer(data['token'])
    assert info['tenant'] == acme and info['username'] == 'admin'
    payload = _payload(data['token'])
    assert apikey.validate_bearer(_replace_payload(data['token'], dict(payload, tnt=globex))) is None
    without = dict(payload)
    del without['tnt']
    assert apikey.validate_bearer(_replace_payload(data['token'], without)) is None
    assert apikey.validate_bearer(_replace_payload(data['token'], dict(payload, tnt='../x'))) is None


async def test_tenant_api_keys_follow_tenant_state(mt):
    acme = await _tenant('acme')
    data = await _tenant_key(acme)
    keyinfo = apikey.validate_bearer(data['token'])
    await configmanager.set_tenant_state(acme, 'disabled')
    assert apikey.validate_bearer(data['token']) is None
    assert not apikey.key_is_current(None, keyinfo)
    await configmanager.set_tenant_state(acme, 'active')
    assert apikey.key_is_current(None, keyinfo)


async def test_tenants_get_no_legacy_keys(mt):
    acme = await _tenant('acme')
    status, _ = await apikey.handle_api_request(
        '/sessions/current/apikey/create', 'admin', configmanager.ConfigManager(acme),
        json.dumps({'expiration': 1}).encode(), 'create')
    assert status == 403


# ------------------------------------------------------------------ HTTP

class _AuditLog(object):
    def log(self, entry):
        pass


@pytest.fixture
def http(mt, monkeypatch):
    import confluent.httpapi as httpapi
    monkeypatch.setattr(httpapi, 'auditlog', _AuditLog())
    monkeypatch.setattr(httpapi, 'httpsessions', {})
    return httpapi


async def _request(httpapi, method, path, basic=None, token=None, session=None):
    headers = {}
    if basic:
        headers['Authorization'] = 'Basic ' + base64.b64encode(basic.encode()).decode()
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if session:
        headers['ConfluentSession'] = session
    req = make_mocked_request(method, path, headers=headers)
    return await httpapi._authorize_request(req, httpapi.opmap[method], b'')


async def test_http_tenant_login_and_session(http):
    acme = await _tenant('acme')
    await configmanager.ConfigManager(None).create_user('admin', role='Monitor')
    first = await _request(http, 'POST', '/nodes/', basic='acme/admin:' + PASSWORD)
    assert first['code'] == 200 and first['cfgmgr'].tenant == acme
    session = first['sessionid']
    assert http.httpsessions[session]['tenant'] == acme
    reused = await _request(http, 'POST', '/nodes/', session=session)
    assert reused['cfgmgr'].tenant == acme  # not the default tenant's Monitor 'admin'
    assert (await _request(http, 'POST', '/nodes/c1/console/session', session=session)) == {'code': 403}
    await configmanager.set_tenant_state(acme, 'disabled')
    assert (await _request(http, 'GET', '/nodes/', session=session))['code'] == 403


async def test_http_tenant_bearer_key(http):
    acme = await _tenant('acme')
    data = await _tenant_key(acme)
    first = await _request(http, 'POST', '/nodes/', token=data['token'])
    assert first['code'] == 200 and first['cfgmgr'].tenant == acme
    assert (await _request(http, 'GET', '/tenants/', token=data['token'])) == {'code': 403}


async def test_http_platform_admin(http):
    main = configmanager.ConfigManager(None)
    await main.create_user('plat', role='PlatformAdmin')
    await main.set_user('plat', {'password': PASSWORD})
    ok = await _request(http, 'POST', '/tenants/', basic='plat:' + PASSWORD)
    assert ok['code'] == 200 and ok['cfgmgr'].tenant is None
    assert (await _request(http, 'GET', '/nodes/', session=ok['sessionid'])) == {'code': 403}


# ------------------------------------------------------- collective join

async def test_collective_join_receives_tenancy_settings(mt):
    await _tenant('acme')
    keys = configmanager._dump_keys(None, False)
    payload = await configmanager.dump_collective_payload()
    assert json.loads(payload)['_tenancy']['multitenancy.enabled'] is True

    mt.switch('follower')
    configmanager.set_global('multitenancy.enabled', False)
    await configmanager.clear_configuration()
    configmanager._restore_keys(keys, None, sync=False)
    await configmanager.ConfigManager(None)._load_from_json(payload, sync=False)
    await configmanager.load_collective_tenants(payload)
    configmanager.commit_clear()

    assert configmanager.multitenancy_enabled()
    assert configmanager.get_global('tenancy.schema') == configmanager.TENANCY_SCHEMA
    assert _ok(auth.authorize('acme/admin', '/nodes/', operation='retrieve'))
