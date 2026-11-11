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

"""The requirements of multi-tenancy, one test each.

Two tenants, acme and globex, are created the way an installation creates
them (by a platform administrator, each with an administrator enrolled by
token) and used through authorization and the API as their users would.
The numbers are those of the requirement list this work started from;
the other test files go deeper into each area.
"""

import asyncio
import os

import pytest

import confluent.alerts as alerts
import confluent.auth as auth
import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.discovery.core as disco
import confluent.discovery.protocols.pxe as pxe
import confluent.exceptions as exc
import confluent.log as log
import confluent.networking.macmap as macmap
import confluent.networking.tenantnetcfg as netcfg
import confluent.netutil as netutil
import confluent.tasks as tasks
import confluent.tenancy as tenancy
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
import confluent.tenantservices as services
import confluent.tenantstate as tenantstate
import tenanttopo

PASSWORD = 'correct horse battery'
MAC = '02:00:00:aa:34:02'
UUID = '6a1e4c8e-2b6f-4b8e-9d3c-6f1f0c7a5e11'
SERIAL = 'J30ABC12'
ADDRESS = '10.241.34.2'


class Forbidden(Exception):
    pass


@pytest.fixture
async def shared(confluent_config, monkeypatch):
    configmanager.init_masterkey()
    configmanager.set_global('tenancy.schema', configmanager.TENANCY_SCHEMA)
    monkeypatch.setattr(configmanager, '_ready', True)
    if not core.pluginmap:
        core.load_plugins()
    # listeners need tenant networks, which these tests do not have
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    monkeypatch.setattr(netcfg, 'start', lambda tenant: False)
    main = configmanager.ConfigManager(None)
    await main.create_user('plat', role='PlatformAdmin')
    await main.create_user('root', role='Administrator')
    await configmanager.set_multitenancy_enabled(True)
    ids = {}
    for name in ('acme', 'globex'):
        record = await tenancy.create(name)
        await tenancy.redeem_enrollment(name, record['enrollment_token'], 'admin', PASSWORD)
        ids[name] = record['id']
    yield ids
    tenantnet.enter(None)


async def api(user, path, operation='retrieve', inputdata=None):
    """A request as the HTTP API handles it: authorize the user for the
    path, then act with the configuration authorization returned, as the
    tenant it returned."""
    granted = auth.authorize(user, path, operation=operation)
    if not granted:
        raise Forbidden(path)
    cfm = granted[1]
    tenantnet.enter(cfm.tenant)
    try:
        result = await core.handle_path(path, operation, cfm, inputdata)
        if hasattr(result, '__aiter__'):
            result = [r async for r in result]
        return [r.href if hasattr(r, 'href') else getattr(r, 'kvpairs', r)
                for r in result]
    finally:
        tenantnet.enter(None)


def cfg(tenant):
    return configmanager.ConfigManager(tenant)


async def define(tenant, nodes):
    groups = set(g for attrs in nodes.values() for g in attrs.get('groups', []))
    missing = groups - set(cfg(tenant).get_groups())
    if missing:
        await cfg(tenant).add_group_attributes(dict((g, {}) for g in missing))
    await cfg(tenant).set_node_attributes(nodes, autocreate=True)


def values(tenant, node, *names):
    attrs = cfg(tenant).get_node_attributes(node, names, decrypt=True).get(node, {})
    return dict((k, v.get('value')) for k, v in attrs.items())


def pxe_info(model='7X21'):
    return {'hwaddr': MAC, 'uuid': UUID, 'services': ['pxe-client'],
            'modelnumber': model, 'serialnumber': SERIAL}


async def detect(tenant, info):
    tenantnet.enter(tenant)
    try:
        await disco.detected(info)
    finally:
        tenantnet.enter(None)


def scoped_state(tenant):
    """Everything kept per tenant in memory, for one tenant."""
    return [repr(s._stores.get(tenant, {})) for s in tenantstate._scoped]


# 1 ------------------------------------------------------------------

async def test_req_01_same_node_names(shared, confluent_config):
    acme, globex = shared['acme'], shared['globex']
    await api('acme/admin', '/nodes/', 'create', {'name': 'c1', 'location.rack': 'acme-r1'})
    await api('globex/admin', '/nodes/', 'create', {'name': 'c1', 'location.rack': 'globex-r9'})
    await api('acme/admin', '/nodes/', 'create', {'name': 'c2'})
    assert await api('acme/admin', '/nodes/') == ['c1/', 'c2/']
    assert await api('globex/admin', '/nodes/') == ['c1/']
    assert await api('root', '/nodes/') == []
    confluent_config.restart()  # as a restart of the service does
    configmanager.init_masterkey()
    assert values(acme, 'c1', 'location.rack') == {'location.rack': 'acme-r1'}
    assert values(globex, 'c1', 'location.rack') == {'location.rack': 'globex-r9'}
    assert sorted(cfg(acme).list_nodes()) == ['c1', 'c2']
    assert sorted(cfg(None).list_nodes()) == []


# 2 ------------------------------------------------------------------

async def test_req_02_same_addresses(shared):
    import confluent.lookuptools as lookuptools
    acme, globex = shared['acme'], shared['globex']
    for tenant, node in ((acme, 'a-node'), (globex, 'g-node')):
        await define(tenant, {node: {'net.ipv4_address': ADDRESS + '/24',
                                     'hardwaremanagement.manager': ADDRESS}})
    for tenant, node in ((acme, 'a-node'), (globex, 'g-node'), (None, None)):
        tenantnet.enter(tenant)
        assert await lookuptools.node_by_manager(ADDRESS, cfg(tenant)) == node
        tenantnet.enter(None)


# 3 ------------------------------------------------------------------

async def test_req_03_same_networks(shared):
    acme, globex = shared['acme'], shared['globex']
    network = {'net.ipv4_gateway': '10.241.34.254', 'net.ipv4_method': 'static'}
    await define(acme, {'c1': dict(network, **{'net.ipv4_address': '10.241.34.10/24'})})
    await define(globex, {'c1': dict(network, **{'net.ipv4_address': '10.241.34.10/24'})})
    for tenant in (acme, globex):
        assert values(tenant, 'c1', 'net.ipv4_address', 'net.ipv4_gateway') == {
            'net.ipv4_address': '10.241.34.10/24', 'net.ipv4_gateway': '10.241.34.254'}
    # and the same addresses on their own uplinks, each kept in its own store
    for name in ('acme', 'globex'):
        stored = netcfg._stored(cfg(shared[name]))
        stored['interfaces']['up0'] = {'addresses': ['10.241.34.1/24']}
        cfg(shared[name]).set_scoped_global('netcfg', stored)
    assert cfg(acme).get_scoped_global('netcfg') == cfg(globex).get_scoped_global('netcfg')
    assert cfg(None).get_scoped_global('netcfg') is None


# 4 ------------------------------------------------------------------

async def test_req_04_attributes_do_not_leak(shared):
    acme, globex = shared['acme'], shared['globex']
    await define(acme, {'c1': {'location.rack': 'acme-rack',
                               'secret.hardwaremanagementpassword': 'acme-secret',
                               'custom.where': {'expression': 'rack {location.rack}'}}})
    await define(globex, {'c1': {'location.rack': 'globex-rack',
                                 'custom.where': {'expression': 'rack {location.rack}'}}})
    # reads, filters and expressions see the tenant's own values only
    assert values(globex, 'c1', 'custom.where') == {'custom.where': 'rack globex-rack'}
    assert list(cfg(globex).filter_node_attributes('location.rack=acme-rack')) == []
    assert list(cfg(acme).filter_node_attributes('location.rack=acme-rack')) == ['c1']
    everything = await api('globex/admin', '/nodes/c1/attributes/all')
    assert 'acme' not in repr(everything)
    assert values(globex, 'c1', 'secret.hardwaremanagementpassword') == {}
    # writing in one does not write the other
    await api('globex/admin', '/nodes/c1/attributes/current', 'update',
              {'location.rack': 'moved'})
    assert values(acme, 'c1', 'location.rack') == {'location.rack': 'acme-rack'}
    # secrets are encrypted with a key of the tenant's own
    stored = cfg(acme)._cfgstore['nodes']['c1']['secret.hardwaremanagementpassword']['cryptvalue']
    assert configmanager.decrypt_value(stored, key=cfg(acme)._cryptkey()) == b'acme-secret'
    assert cfg(acme)._cryptkey() != cfg(globex)._cryptkey()
    for key in (cfg(globex)._cryptkey(), configmanager._masterkey):
        with pytest.raises(Exception):  # noqa: B017 (any failure to decrypt)
            configmanager.decrypt_value(stored, key=key)


# 5 ------------------------------------------------------------------

async def test_req_05_groups_and_membership(shared):
    acme, globex = shared['acme'], shared['globex']
    await define(acme, {'a1': {'groups': ['compute']}, 'a2': {'groups': ['compute']}})
    await define(globex, {'g1': {'groups': ['compute']}})
    await define(None, {'h1': {}})
    assert sorted(cfg(acme).get_nodegroup_attributes('compute')['nodes']) == ['a1', 'a2']
    assert sorted(cfg(globex).get_nodegroup_attributes('compute')['nodes']) == ['g1']
    assert sorted(cfg(acme).get_nodegroup_attributes('everything')['nodes']) == ['a1', 'a2']
    assert sorted(cfg(None).get_nodegroup_attributes('everything')['nodes']) == ['h1']
    assert await api('globex/admin', '/noderange/compute/nodes/') == ['g1/']
    assert await api('acme/admin', '/noderange/everything/nodes/') == ['a1/', 'a2/']
    assert 'compute' not in cfg(None).get_groups()


# 6, 7, 8 ------------------------------------------------------------

async def test_req_06_07_08_discovery_identity_is_per_tenant(shared):
    acme, globex = shared['acme'], shared['globex']
    await define(acme, {'n1': {'id.uuid': UUID, 'discovery.policy': 'pxe',
                               'net.hwaddr': MAC}})
    await detect(acme, pxe_info('acme-model'))
    await detect(globex, pxe_info('globex-model'))
    # 6: the same MAC, UUID and serial is two records; neither overwrote the other
    assert disco.known_info.for_tenant(acme)[MAC]['modelnumber'] == 'acme-model'
    assert disco.known_info.for_tenant(globex)[MAC]['modelnumber'] == 'globex-model'
    assert MAC not in disco.known_info.for_tenant(None)
    path = '/discovery/by-mac/' + MAC.replace(':', '-')
    seen = {}
    for user in ('acme/admin', 'globex/admin'):
        merged = {}
        for part in await api(user, path):
            merged.update(part)
        seen[user] = (merged['modelnumber'], await api(user, '/discovery/by-node/'))
    # and each is identified against its own tenant's nodes
    assert seen == {'acme/admin': ('acme-model', ['n1/']), 'globex/admin': ('globex-model', [])}
    with pytest.raises(exc.NotFoundException):
        await api('root', path)
    # 7: MAC lookups
    pxe.remap_nodes(['n1'], cfg(acme))
    for tenant, expected in ((acme, 'n1'), (globex, None), (None, None)):
        tenantnet.enter(tenant)
        assert disco.get_node_by_uuid_or_mac(MAC) == expected
        assert pxe.macmap.get(MAC) == expected
        assert MAC not in macmap._nodesbymac
        tenantnet.enter(None)
    # 8: serial and UUID lookups
    assert disco.known_serials.for_tenant(acme)[SERIAL]['modelnumber'] == 'acme-model'
    assert disco.known_serials.for_tenant(globex)[SERIAL]['modelnumber'] == 'globex-model'
    assert disco.nodes_by_uuid.for_tenant(acme) == {UUID: 'n1'}
    assert disco.nodes_by_uuid.for_tenant(globex) == {}
    assert disco.known_pxe_uuids.for_tenant(acme) == {UUID: 'n1'}
    assert disco.known_pxe_uuids.for_tenant(globex) == {}
    assert list(disco.known_uuids.for_tenant(globex)[UUID]) == [MAC]


# 9 ------------------------------------------------------------------

async def test_req_09_rescan_and_clear_stay_in_the_tenant(shared):
    acme, globex = shared['acme'], shared['globex']
    await detect(acme, pxe_info())
    await detect(globex, pxe_info())
    before = scoped_state(globex)
    assert await api('acme/admin', '/discovery/rescan', 'update', {'rescan': 'start'}) == [
        {'rescan': 'started'}]
    scan = disco._tenant_scan.for_tenant(acme).get('scanner')
    if scan is not None:
        await scan
    await api('acme/admin', '/discovery/by-mac/' + MAC.replace(':', '-'), 'delete')
    assert MAC not in disco.known_info.for_tenant(acme)
    assert disco.scanner is None  # the host's scanner was not started
    assert scoped_state(globex) == before
    assert MAC in disco.known_info.for_tenant(globex)


# 10 -----------------------------------------------------------------

async def test_req_10_events_and_logs(shared, monkeypatch):
    acme, globex = shared['acme'], shared['globex']
    await define(acme, {'a-bmc': {'hardwaremanagement.manager': ADDRESS}})
    await define(globex, {'g-bmc': {'hardwaremanagement.manager': ADDRESS}})
    decoded = []

    async def handle_path(path, operation, cfm, inputdata=None, autostrip=True):
        decoded.append((cfm.tenant, path))
        return []
    # an alert from the same address is each tenant's own node
    real = core.handle_path
    monkeypatch.setattr(core, 'handle_path', handle_path)
    for tenant in (acme, globex):
        tenantnet.enter(tenant)
        await alerts.decode_alert({'1.3.6.1.6.3.18.1.3.0': ADDRESS}, cfg(tenant))
        tenantnet.enter(None)
    monkeypatch.setattr(core, 'handle_path', real)
    assert decoded == [(acme, '/nodes/a-bmc/events/hardware/decode'),
                       (globex, '/nodes/g-bmc/events/hardware/decode')]
    # events, audit and console logs are written under the tenant's path
    logdir = configmanager.get_global('logdirectory')
    for tenant, text in ((acme, 'acme event'), (globex, 'globex event')):
        tenantnet.enter(tenant)
        log.log({'info': text}, flush=True)
        tenantnet.enter(None)
        log.AuditLog().log({'operation': 'update', 'user': 'admin', 'tenant': tenant,
                            'target': '/nodes/' + text.split()[0]})
        log.tenant_logger('audit', tenant).writedata()
        assert log.Logger('n1', console=True, tenant=tenant).handler.textpath == \
            os.path.join(logdir, 'tenants', tenant, 'consoles', 'n1')
    for tenant, mine, other in ((acme, 'acme', 'globex'), (globex, 'globex', 'acme')):
        for name in ('events', 'audit'):
            with open(os.path.join(logdir, 'tenants', tenant, name)) as f:
                text = f.read()
            assert mine in text and other not in text, (tenant, name)
    service = os.path.join(logdir, 'events')
    if os.path.exists(service):
        with open(service) as f:
            assert 'acme event' not in f.read()


# 11 -----------------------------------------------------------------

async def test_req_11_background_work_keeps_its_tenant(shared):
    acme, globex = shared['acme'], shared['globex']
    await define(acme, {'only-acme': {}})
    ran = []

    async def job():
        tenant = tenantguard.current_tenant.get()
        ran.append((tenant, sorted(cfg(tenant).list_nodes())))
    tenantnet.enter(acme)
    later = tasks.spawn_task_after(0.05, job)
    pool = tasks.TaskPool(max_concurrent=2)
    pool.schedule(job)
    await disco.rescan()  # starts this tenant's scan in the background
    tenantnet.enter(globex)  # the next request is another tenant's
    await later
    for _ in range(100):
        if len(ran) == 2:
            break
        await asyncio.sleep(0.02)
    assert ran == [(acme, ['only-acme'])] * 2
    assert 'scanner' not in disco._tenant_scan.for_tenant(globex)
    scan = disco._tenant_scan.for_tenant(acme).get('scanner')
    if scan is not None:
        await scan
    tenantnet.enter(None)
    assert disco.scanner is None


# 12 -----------------------------------------------------------------

async def test_req_12_no_access_across_tenants(shared):
    acme, globex = shared['acme'], shared['globex']
    await define(acme, {'acme-only': {'groups': ['acme-group'], 'location.rack': 'r1'}})
    await cfg(acme).create_user('acme-user', role='Operator')
    await detect(acme, pxe_info())
    for path, operation, data in (
            ('/nodes/acme-only', 'retrieve', None),
            ('/nodes/acme-only/attributes/current', 'update', {'location.rack': 'stolen'}),
            ('/nodes/acme-only', 'delete', None),
            ('/nodegroups/acme-group', 'retrieve', None),
            ('/nodegroups/acme-group', 'delete', None),
            ('/discovery/by-mac/' + MAC.replace(':', '-'), 'retrieve', None),
            ('/discovery/by-mac/' + MAC.replace(':', '-'), 'delete', None),
            ('/users/acme-user', 'retrieve', None),
            ('/users/acme-user', 'delete', None)):
        try:
            got = await api('globex/admin', path, operation, data)
        except (exc.NotFoundException, exc.InvalidArgumentException, Forbidden):
            continue
        # Deleting a group that does not exist is answered as done, in any
        # tenant and without tenants: it is globex's own (absent) group
        # that was "deleted". Anything else must have been refused.
        assert (operation, path) == ('delete', '/nodegroups/acme-group'), (operation, path, got)
    # all of it is still there, unchanged
    assert values(acme, 'acme-only', 'location.rack') == {'location.rack': 'r1'}
    assert cfg(acme).get_nodegroup_attributes('acme-group')['nodes'] == {'acme-only'} or         list(cfg(acme).get_nodegroup_attributes('acme-group')['nodes']) == ['acme-only']
    assert 'acme-group' not in cfg(globex).get_groups()
    assert 'acme-user' in cfg(acme).list_users() and MAC in disco.known_info.for_tenant(acme)
    # a user is its tenant's: the right password under the other tenant's name is nobody
    assert await auth.check_user_passphrase('globex/admin', PASSWORD) is not None
    assert await auth.check_user_passphrase('acme/acme-user', PASSWORD) is None
    assert not auth.authorize('globex/acme-user', '/nodes/', operation='retrieve')
    # an API key names its tenant; it is that tenant's key and no other's
    import confluent.apikey as apikey
    import json
    status, body = await apikey.handle_v2_request(
        '/sessions/current/apikeys', 'admin', cfg(globex),
        json.dumps({'expiration': 30}).encode(), 'create')
    assert status in (200, 201), body
    token = body['token']
    info = apikey.validate_bearer(token)
    assert info and info['tenant'] == globex and info['username'] == 'admin'
    # changed in any way, it is nobody's
    forged = token[:-2] + ('AA' if token[-2:] != 'AA' else 'BB')
    assert apikey.validate_bearer(forged) is None
    # and it is no key of the other tenant's user of the same name
    assert apikey.validate_bearer(token, cfg(acme)) is None or         apikey.validate_bearer(token, cfg(acme))['tenant'] == globex


# 13 -----------------------------------------------------------------

async def test_req_13_platform_administrators_have_no_tenant_access(shared):
    await define(shared['acme'], {'c1': {}})
    for path in ('/nodes/', '/nodes/c1', '/nodegroups/', '/discovery/', '/networking/',
                 '/networking/interfaces/', '/events/decode', '/users/',
                 '/nodes/c1/console/session', '/nodes/c1/power/state'):
        for operation in ('retrieve', 'update', 'create', 'delete'):
            assert not auth.authorize('plat', path, operation=operation), (path, operation)
    # it manages tenants, and only that
    assert sorted(await api('plat', '/tenants/')) == sorted(t + '/' for t in shared.values())
    assert not auth.authorize('root', '/tenants/', operation='retrieve')
    assert not auth.authorize('acme/admin', '/tenants/', operation='retrieve')
    # it cannot make itself a user of a tenant: it can only issue a token,
    # which works once, for whoever holds it
    with pytest.raises(Forbidden):
        await api('plat', '/users/', 'create', {'name': 'mole', 'role': 'Administrator'})
    assert 'mole' not in cfg(shared['acme']).list_users()
    # (not even that, once the tenant has an administrator)
    with pytest.raises(exc.InvalidArgumentException):
        await api('plat', '/tenants/acme/enrollment', 'create')
    created = (await api('plat', '/tenants/', 'create', {'name': 'initech'}))[0]
    await tenancy.redeem_enrollment('initech', created['enrollment_token'], 'first', PASSWORD)
    with pytest.raises(Exception):  # noqa: B017 (used up)
        await tenancy.redeem_enrollment('initech', created['enrollment_token'], 'second', PASSWORD)
    assert sorted(cfg(created['id']).list_users()) == ['first']


# 14 -----------------------------------------------------------------

async def test_req_14_no_leasing_or_assignment(shared):
    acme, globex = shared['acme'], shared['globex']
    await define(acme, {'c1': {}})
    await define(globex, {'g1': {'custom.peer': 'acme/c1', 'groups': ['mine']}})
    # a value that looks like a reference to another tenant is only a string
    assert values(globex, 'g1', 'custom.peer') == {'custom.peer': 'acme/c1'}
    # no name reaches another tenant's node, whatever its form
    for name in ('acme/c1', acme + '/c1', '../' + acme + '/c1', 'c1'):
        assert not cfg(globex).is_node(name)
        with pytest.raises((exc.NotFoundException, exc.InvalidArgumentException, Forbidden)):
            await api('globex/admin', '/nodes/' + name)
    with pytest.raises(Exception):  # noqa: B017 (not a node it can be given)
        await cfg(globex).set_group_attributes({'mine': {'nodes': ['g1', 'c1']}})
    assert sorted(cfg(globex).list_nodes()) == ['g1']
    # there is no way to list or move a tenant's nodes from outside it
    for path in ('/tenants/acme/nodes', '/tenants/acme/nodes/c1', '/tenants/acme/users'):
        with pytest.raises((exc.NotFoundException, exc.InvalidArgumentException)):
            await api('plat', path)
        with pytest.raises((exc.NotFoundException, exc.InvalidArgumentException)):
            await api('plat', path, 'update', {'tenant': 'globex'})
    assert sorted(cfg(acme).list_nodes()) == ['c1']


# 15 -----------------------------------------------------------------

async def test_req_15_single_tenant_installations_are_unchanged(confluent_config):
    configmanager.init_masterkey()
    main = cfg(None)
    await main.create_user('root', role='Administrator')
    await define(None, {'n1': {'groups': ['compute'], 'location.rack': 'r1',
                               'secret.hardwaremanagementpassword': 'pw'}})
    # the API of the installation works as before, with no tenant anywhere
    assert await api('root', '/nodes/') == ['n1/']
    assert await api('root', '/noderange/compute/nodes/') == ['n1/']
    assert values(None, 'n1', 'location.rack') == {'location.rack': 'r1'}
    assert not configmanager.multitenancy_enabled()
    assert configmanager.list_tenants() == []
    # no tenant can be used or created until it is turned on
    assert await auth.check_user_passphrase('acme/admin', PASSWORD) is None
    assert not auth.authorize('acme/admin', '/nodes/', operation='retrieve')
    with pytest.raises(Exception):  # noqa: B017 (multi-tenancy is off)
        await tenancy.create('acme')
    # nothing of tenancy appears in its files or state
    assert not os.path.exists(os.path.join(confluent_config.cfgdir, 'tenants'))
    assert tenantguard.current_tenant.get() is None
    # migration leaves it as it is, however often it is run
    before = main._real_dump_to_json()
    first = await configmanager.migrate_tenancy()
    assert await configmanager.migrate_tenancy() == []
    assert main._real_dump_to_json() == before
    assert all('store' not in change for change in first)


# C ------------------------------------------------------------------

async def test_req_c_concurrent_work_in_two_tenants(shared):
    acme, globex = shared['acme'], shared['globex']
    count = 40

    async def populate(user, mark):
        for index in range(count):
            await api(user, '/nodes/', 'create', {
                'name': 'c{0}'.format(index), 'location.rack': '{0}-{1}'.format(mark, index)})
            await asyncio.sleep(0)

    async def discover(tenant, mark):
        for index in range(count):
            info = pxe_info('{0}-{1}'.format(mark, index))
            info['hwaddr'] = '02:00:00:00:{0:02x}:01'.format(index)
            info['uuid'] = UUID[:-2] + '{0:02x}'.format(index)
            await detect(tenant, info)

    async def rescan(user):
        for _ in range(5):
            await api(user, '/discovery/rescan', 'update', {'rescan': 'start'})
            await asyncio.sleep(0)
    await asyncio.gather(
        populate('acme/admin', 'acme'), populate('globex/admin', 'globex'),
        discover(acme, 'acme'), discover(globex, 'globex'),
        rescan('acme/admin'), rescan('globex/admin'))
    for tenant, mark in ((acme, 'acme'), (globex, 'globex')):
        assert len(list(cfg(tenant).list_nodes())) == count
        for index in range(count):
            node = 'c{0}'.format(index)
            assert values(tenant, node, 'location.rack') == {
                'location.rack': '{0}-{1}'.format(mark, index)}
        records = disco.known_info.for_tenant(tenant)
        assert len(records) == count
        assert all(r['modelnumber'].startswith(mark + '-') for r in records.values())
        scan = disco._tenant_scan.for_tenant(tenant).get('scanner')
        if scan is not None:
            await scan
    assert sorted(cfg(None).list_nodes()) == []
    assert dict(disco.known_info.for_tenant(None)) == {}


# N: in real tenant networks ------------------------------------------

SOAK_TENANTS = int(os.environ.get('CONFLUENT_SOAK_TENANTS', '6'))
SOAK_ROUNDS = int(os.environ.get('CONFLUENT_SOAK_ROUNDS', '25'))


def _label(sock):
    import json
    sock.settimeout(5)
    data = b''
    while not data.endswith(b'\n'):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    sock.close()
    return json.loads(data.decode())['label']


@pytest.mark.netns
async def test_req_n_many_tenants_with_identical_networks(netns, confluent_config, monkeypatch):
    """Every tenant has the same network and the same hardware address;
    each reaches its own, however often, and nothing is left open."""
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    monkeypatch.setattr(netcfg, 'start', lambda tenant: False)
    tenants = dict(('t{0:012x}'.format(index + 1), ('soak{0}-hw'.format(index), 64))
                   for index in range(SOAK_TENANTS))
    monkeypatch.setattr(tenanttopo, 'TENANTS', tenants)
    topology = tenanttopo.Topology(netns)
    try:
        hits = topology.decoy_hits()
        for tenant, (label, _) in tenants.items():
            configmanager._true_create_tenant(
                tenant, label, configmanager._wrap_tenant_key(os.urandom(32)), 0)
            topology.network(tenant)
        tenantguard.recent_violations.clear()
        baseline = None
        for round_ in range(SOAK_ROUNDS):
            for tenant, (label, _) in tenants.items():
                net = tenantnet.network_for(tenant)
                assert _label(net.connect_tcp(tenanttopo.HW_IP, 7000)) == label
                udp = net.udp_socket()
                udp.close()
                # the same address through the tenant-aware helpers
                tenantnet.enter(tenant)
                assert await netutil.my_ip_facing(tenanttopo.HW_IP) == tenanttopo.UP_IP
                tenantnet.enter(None)
            if round_ == 1:
                baseline = len(os.listdir('/proc/self/fd'))
        # descriptors do not accumulate with use
        assert len(os.listdir('/proc/self/fd')) <= baseline + 2
        for tenant in tenants:
            # (every socket it was given has been closed)
            assert all(s.fileno() == -1 for s in tenantnet.network_for(tenant).broker.sockets)
        assert list(tenantguard.recent_violations) == []
        assert topology.decoy_hits() == hits
        # one tenant going away leaves the others working
        first = sorted(tenants)[0]
        tenantnet.close_tenant(first)
        topology.stop_broker(first)
        for tenant, (label, _) in tenants.items():
            if tenant != first:
                assert _label(tenantnet.network_for(tenant).connect_tcp(
                    tenanttopo.HW_IP, 7000)) == label
    finally:
        tenantnet.enter(None)
        topology.cleanup()
