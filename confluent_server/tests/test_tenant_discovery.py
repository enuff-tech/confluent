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

"""Each tenant discovers its own hardware.

Two tenants see the very same hardware identity (MAC, UUID, serial,
address); each keeps a record of its own, identifies it against its own
nodes only, and never sees the other's records or the host's.
"""

import os
import socket

import pytest

import confluent.auth as auth
import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.discovery.core as disco
import confluent.exceptions as exc
import confluent.netutil as netutil
import confluent.tenantnet as tenantnet
import confluent.tenantstate as tenantstate
from tenanttopo import HW_IP, TENANTS, UP_IP, Topology

A = 't00000000000a'
B = 't00000000000b'
MAC = '02:00:00:aa:34:02'
UUID = '6a1e4c8e-2b6f-4b8e-9d3c-6f1f0c7a5e11'


def _pxe_info(model):
    # the same PXE client as both tenants' networks see it
    return {'hwaddr': MAC, 'uuid': UUID, 'services': ['pxe-client'],
            'modelnumber': model}


@pytest.fixture
async def tenants(confluent_config, monkeypatch):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    for tid, name in ((A, 'acme'), (B, 'globex')):
        configmanager._true_create_tenant(
            tid, name, configmanager._wrap_tenant_key(os.urandom(32)), 0)
    for scoped in tenantstate._scoped:
        scoped._stores.clear()
    yield
    tenantnet.enter(None)
    for scoped in tenantstate._scoped:
        scoped._stores.clear()


async def _as(tid, path, operation='retrieve', inputdata=None):
    """A discovery request made by tenant tid (None: the host)."""
    tenantnet.enter(tid)
    try:
        result = await core.handle_path(
            path, operation, configmanager.ConfigManager(tid), inputdata)
        if hasattr(result, '__aiter__'):
            return [r async for r in result]
        return list(result)
    finally:
        tenantnet.enter(None)


async def _detect(tid, info):
    tenantnet.enter(tid)
    try:
        await disco.detected(info)
    finally:
        tenantnet.enter(None)


def _kv(results):
    merged = {}
    for r in results:
        merged.update(getattr(r, 'kvpairs', {}) or {})
    return merged


async def test_identical_hardware_is_two_records(tenants):
    await _detect(A, _pxe_info('7X21'))
    await _detect(B, _pxe_info('7Y98'))
    assert disco.known_info.for_tenant(A)[MAC]['modelnumber'] == '7X21'
    assert disco.known_info.for_tenant(B)[MAC]['modelnumber'] == '7Y98'
    assert MAC not in disco.known_info.for_tenant(None)
    assert list(disco.known_uuids.for_tenant(A)[UUID]) == [MAC]
    assert list(disco.known_uuids.for_tenant(B)[UUID]) == [MAC]
    # through the API, each tenant reads only its own
    path = '/discovery/by-mac/{0}'.format(MAC.replace(':', '-'))
    assert _kv(await _as(A, path)).get('modelnumber') == '7X21'
    assert _kv(await _as(B, path)).get('modelnumber') == '7Y98'
    with pytest.raises(exc.NotFoundException):
        await _as(None, path)
    alldata = _kv(await _as(A, '/discovery/alldata'))
    assert list(alldata) == [MAC]


async def test_identification_uses_the_tenants_own_nodes(tenants):
    # both tenants call a node n1, only tenant a's carries the UUID
    await configmanager.ConfigManager(A).set_node_attributes(
        {'n1': {'id.uuid': UUID, 'discovery.policy': 'pxe'}}, autocreate=True)
    await configmanager.ConfigManager(B).set_node_attributes(
        {'n1': {'discovery.policy': 'pxe'}}, autocreate=True)
    await configmanager.ConfigManager(None).set_node_attributes(
        {'n1': {'id.uuid': UUID, 'discovery.policy': 'pxe'}}, autocreate=True)
    await _detect(A, _pxe_info('7X21'))
    await _detect(B, _pxe_info('7X21'))
    assert disco.known_info.for_tenant(A)[MAC]['discostatus'] == 'identified'
    assert disco.known_info.for_tenant(B)[MAC].get('discostatus') != 'identified'
    assert list(disco.known_nodes.for_tenant(A)) == ['n1']
    assert list(disco.known_nodes.for_tenant(B)) == []
    assert disco.nodes_by_uuid.for_tenant(A) == {UUID: 'n1'}
    assert disco.nodes_by_uuid.for_tenant(B) == {}
    assert disco.known_pxe_uuids.for_tenant(A) == {UUID: 'n1'}
    assert disco.known_pxe_uuids.for_tenant(B) == {}
    # PXE discovery recorded what it learned on tenant a's n1 only; the
    # host's node with that UUID was never considered
    model = {}
    for tid in (A, B, None):
        attrs = configmanager.ConfigManager(tid).get_node_attributes('n1', 'id.model')
        model[tid] = attrs.get('n1', {}).get('id.model', {}).get('value')
    assert model == {A: '7X21', B: None, None: None}
    assert MAC not in disco.known_info.for_tenant(None)
    assert [r.href for r in await _as(A, '/discovery/by-node/')] == ['n1/']
    assert await _as(B, '/discovery/by-node/') == []
    assert await _as(None, '/discovery/by-node/') == []


async def test_clearing_a_record_keeps_the_other_tenants(tenants):
    await _detect(A, _pxe_info('7X21'))
    await _detect(B, _pxe_info('7X21'))
    await _as(A, '/discovery/by-mac/{0}'.format(MAC.replace(':', '-')), 'delete')
    assert MAC not in disco.known_info.for_tenant(A)
    assert MAC in disco.known_info.for_tenant(B)


async def test_rescan_stays_within_the_tenant(tenants, monkeypatch):
    started = []
    monkeypatch.setattr(disco, 'blocking_scan', lambda *a, **k: started.append(a),
                        raising=False)
    monkeypatch.setattr(disco, 'scanner', None)
    rechecked = []

    async def recheck(cfg, mac):
        rechecked.append((cfg.tenant, mac))
    monkeypatch.setattr(disco, '_recheck_single_unknown', recheck)
    disco.unknown_info.for_tenant(A)[MAC] = _pxe_info('7X21')
    disco.unknown_info.for_tenant(B)['02:00:00:00:00:0b'] = _pxe_info('7X21')
    result = _kv(await _as(A, '/discovery/rescan', 'update', {'rescan': 'start'}))
    assert result == {'rescan': 'started'}
    assert rechecked == [(A, MAC)]
    assert disco.scanner is None and not started
    # its own networks are searched instead (here it has none: the search
    # ends at once)
    scan = disco._tenant_scan.for_tenant(A).get('scanner')
    if scan is not None:
        await scan
    assert _kv(await _as(A, '/discovery/rescan')) == {'scanning': False}
    assert _kv(await _as(B, '/discovery/rescan')) == {'scanning': False}


async def test_subscriptions_are_the_hosts(tenants):
    assert await _as(A, '/discovery/subscriptions/') == []
    with pytest.raises(exc.ForbiddenRequest):
        await _as(A, '/discovery/subscriptions/switch1', 'update', {})
    with pytest.raises(exc.ForbiddenRequest):
        await _as(A, '/discovery/subscriptions/switch1', 'delete')


async def test_autosense_is_per_tenant(tenants):
    assert _kv(await _as(A, '/discovery/autosense')) == {'enabled': True}
    await _as(A, '/discovery/autosense', 'update', {'enabled': 'false'})
    assert _kv(await _as(A, '/discovery/autosense')) == {'enabled': False}
    assert _kv(await _as(B, '/discovery/autosense')) == {'enabled': True}
    assert configmanager.get_global('discovery.autosense') is None


async def test_deleted_tenant_leaves_no_discovery_state(tenants):
    await _detect(A, _pxe_info('7X21'))
    await _detect(B, _pxe_info('7X21'))
    await configmanager.set_tenant_state(B, 'disabled')
    await configmanager.delete_tenant(B)
    for scoped in tenantstate._scoped:
        assert B not in scoped._stores
    assert MAC in disco.known_info.for_tenant(A)


def test_tenants_may_use_discovery_paths():
    for path in ('/discovery', '/discovery/by-mac/02-00-00-aa-34-02',
                 '/discovery/register', '/discovery/rescan',
                 '/discovery/autosense'):
        assert auth._tenant_path_allowed(path), path


def test_tenant_scoped_mapping_follows_the_task(tenants):
    scoped = tenantstate.TenantScoped()
    scoped['k'] = 'host'
    tenantnet.enter(A)
    assert 'k' not in scoped
    scoped['k'] = 'a'
    tenantnet.enter(B)
    assert dict(scoped) == {}
    tenantnet.enter(None)
    assert scoped['k'] == 'host' and scoped.for_tenant(A) == {'k': 'a'}
    tenantstate.drop_tenant(A)
    assert scoped.for_tenant(A) == {}


async def test_host_only_network_helpers_are_refused_for_tenants(tenants):
    tenantnet.enter(A)
    for call in (netutil.list_viable_nics, lambda: list(netutil.inametonets('eth0'))):
        with pytest.raises(tenantnet.TenantNetworkUnsupported):
            call()
    for coro in (netutil.mac2ip(MAC), netutil.ping6('ff02::1'),
                 netutil.myiptonets('10.0.0.1')):
        with pytest.raises(tenantnet.TenantNetworkUnsupported):
            await coro


# ------------------------------------------- within the tenant networks



@pytest.fixture
def topo(netns, tenants):
    topology = Topology(netns)
    for tid in TENANTS:
        topology.network(tid)
    yield topology
    tenantnet.enter(None)
    topology.cleanup()


@pytest.mark.netns
async def test_addresses_are_the_tenants_own(topo):
    host = {socket.inet_ntop(f, a) for f, a, _, _ in await netutil.get_my_addresses()}
    for tid in TENANTS:
        tenantnet.enter(tid)
        mine = await netutil.get_my_addresses()
        assert [(f, socket.inet_ntop(f, a), p) for f, a, p, _ in mine] == \
            [(socket.AF_INET, UP_IP, 24)]
        assert await netutil.get_my_addresses(family=socket.AF_INET6) == []
        assert await netutil.get_addresses_by_serverip(UP_IP) == mine
        assert await netutil.my_ip_facing(HW_IP) == UP_IP
        assert await netutil.address_is_local('10.241.34.77')
        for other in host - {UP_IP}:
            assert not await netutil.address_is_local(other), other
        prefix = [x async for x in netutil.get_prefix_len_for_ip(HW_IP)]
        assert prefix == [(socket.AF_INET, 24)]
        tenantnet.enter(None)


@pytest.mark.netns
async def test_names_resolve_within_the_tenant(topo):
    expected = {A: '10.241.34.2', B: '10.241.34.99'}
    for tid in TENANTS:
        tenantnet.enter(tid)
        found = await netutil._getaddrinfo('bmc-a', 443, family=socket.AF_INET)
        assert [ai[4][0] for ai in found] == [expected[tid]]
        assert await netutil.addresses_match('bmc-a', expected[tid])
        tenantnet.enter(None)


@pytest.mark.netns
async def test_reachability_is_probed_in_the_tenants_network(topo):
    a, b = sorted(TENANTS)
    topo.start_https(a)
    hits = topo.decoy_hits()
    tenantnet.enter(a)
    assert await netutil.peer_reachable(HW_IP) == [443]
    await disco.wait_for_connection(HW_IP)
    tenantnet.enter(b)
    assert await netutil.peer_reachable(HW_IP) == []
    tenantnet.enter(None)
    assert topo.decoy_hits() == hits
