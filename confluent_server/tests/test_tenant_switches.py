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

"""Each tenant's switches are its own.

Both tenants have a switch called sw1 at the same address, and both see
the same MAC address on it, on different ports. MAC tables and LLDP
neighbors are read through each tenant's own network with its own SNMP
community, kept per tenant, and used to identify that tenant's nodes
only. Alerts are decoded for the node of the tenant that asks.
"""

import os

import pytest

import confluent.alerts as alerts
import confluent.auth as auth
import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.discovery.core as disco
import confluent.exceptions as exc
import confluent.lookuptools as lookuptools
import confluent.networking.lldp as lldp
import confluent.networking.macmap as macmap
import confluent.snmputil as snmputil
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
import confluent.util as util
from tenanttopo import HW_IP, TENANTS, Topology

A, B = sorted(TENANTS)
SHARED = '02:00:00:5e:00:01'    # seen by both tenants' switches
ONLY_A = '02:00:00:5e:00:0a'
ONLY_B = '02:00:00:5e:00:0b'
COMMUNITY = {A: 'community-of-a', B: 'community-of-b'}


def _create(tid):
    configmanager._true_create_tenant(
        tid, TENANTS[tid][0], configmanager._wrap_tenant_key(os.urandom(32)), 0)


@pytest.fixture
async def tenants(confluent_config, monkeypatch):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    # discovery listeners are not what is being tested here
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    for tid in (A, B):
        _create(tid)
        await configmanager.ConfigManager(tid).set_node_attributes({
            'sw1': {'type': 'switch', 'secret.snmpcommunity': COMMUNITY[tid]},
            'n1': {'net.switch': 'sw1', 'net.switchport': 'Ethernet1'},
        }, autocreate=True)
    yield
    tenantnet.enter(None)


async def _as(tid, path, operation='retrieve', inputdata=None):
    tenantnet.enter(tid)
    try:
        result = await core.handle_path(
            path, operation, configmanager.ConfigManager(tid), inputdata)
        if hasattr(result, '__aiter__'):
            return [r async for r in result]
        return list(result)
    finally:
        tenantnet.enter(None)


async def _node_of(tid, mac):
    tenantnet.enter(tid)
    try:
        return await macmap.find_nodeinfo_by_mac(mac, configmanager.ConfigManager(tid))
    finally:
        tenantnet.enter(None)


# ----------------------------------------------- without tenant networks

FAKE_TABLES = {
    # switch tables as _snmp_map_switch returns them:
    # mac -> bridge port, interface index -> name, bridge port -> interface
    A: ({SHARED: 1, ONLY_A: 2}, {1: 'Ethernet1', 2: 'Ethernet2'}, {1: 1, 2: 2}),
    B: ({SHARED: 2, ONLY_B: 1}, {1: 'Ethernet1', 2: 'Ethernet2'}, {1: 1, 2: 2}),
}


@pytest.fixture
def fake_switches(tenants, monkeypatch):
    walked = []

    async def no_fast_backend(args):
        raise Exception('not an API switch')

    async def walk(switch, password, user, privprotocol=None):
        tenant = tenantguard.current_tenant.get()
        walked.append((tenant, switch, password))
        return FAKE_TABLES[tenant]

    async def offload(*args):
        raise AssertionError('the offload process is the host network')
    monkeypatch.setattr(macmap, '_fast_map_switch', no_fast_backend)
    monkeypatch.setattr(macmap, '_snmp_map_switch', walk)
    monkeypatch.setattr(macmap, '_offload_map_switch', offload)
    return walked


async def test_mac_maps_are_per_tenant(fake_switches):
    assert await _node_of(A, SHARED) == ('n1', {'maccount': 1})
    assert await _node_of(B, SHARED) == (None, {'maccount': 0})
    assert await _node_of(B, ONLY_B) == ('n1', {'maccount': 1})
    assert await _node_of(A, ONLY_B) == (None, {'maccount': 0})
    # each tenant's switch was walked with that tenant's own secret, in
    # this process (never the offload process)
    assert {(t, s, util.stringify(p)) for t, s, p in fake_switches} == {
        (A, 'sw1', COMMUNITY[A]), (B, 'sw1', COMMUNITY[B])}
    assert macmap._macmap.for_tenant(A)[SHARED] == [('sw1', 'Ethernet1', 1)]
    assert macmap._macmap.for_tenant(B)[SHARED] == [('sw1', 'Ethernet2', 1)]
    assert macmap._macmap.for_tenant(None) == {}
    assert macmap._macsbyswitch.for_tenant(A) == {
        'sw1': {'Ethernet1': [SHARED], 'Ethernet2': [ONLY_A]}}


async def test_mac_api_shows_the_tenants_own_switches(fake_switches):
    for tid in (A, B):
        assert [r.kvpairs for r in await _as(
            tid, '/networking/macs/rescan', 'update', {'rescan': 'start'})] == [
                {'rescan': 'started'}]
    for tid in (A, B):
        tenantnet.enter(tid)
        await macmap.rescan(configmanager.ConfigManager(tid))
        tenantnet.enter(None)
    path = '/networking/macs/by-mac/' + SHARED.replace(':', '-')
    seen = {}
    for tid in (A, B):
        merged = {}
        for r in await _as(tid, path):
            merged.update(r.kvpairs)
        seen[tid] = (merged['possiblenode'], merged['ports'])
    assert seen[A] == ('n1', [{'switch': 'sw1', 'port': 'Ethernet1', 'macsonport': 1}])
    assert seen[B] == (None, [{'switch': 'sw1', 'port': 'Ethernet2', 'macsonport': 1}])
    assert [r.href for r in await _as(A, '/networking/macs/by-switch/')] == ['sw1/']
    assert [r.href for r in await _as(
        A, '/networking/macs/by-switch/sw1/by-port/Ethernet2/by-mac/')] == [
            ONLY_A.replace(':', '-')]
    alldata = (await _as(B, '/networking/macs/alldata'))[0].kvpairs
    assert sorted(alldata) == sorted([SHARED, ONLY_B])
    # the host has no switches, and sees none of the tenants'
    with pytest.raises(exc.NotFoundException):
        await _as(None, path)
    assert await _as(None, '/networking/macs/by-switch/') == []


async def test_a_tenants_map_is_built_only_by_its_own_tasks(fake_switches):
    tenantnet.enter(A)
    with pytest.raises(exc.ForbiddenRequest):
        await macmap.find_nodeinfo_by_mac(SHARED, configmanager.ConfigManager(B))
    with pytest.raises(exc.ForbiddenRequest):
        await macmap.find_nodeinfo_by_mac(SHARED, configmanager.ConfigManager(None))
    tenantnet.enter(None)
    with pytest.raises(exc.ForbiddenRequest):
        await macmap.rescan(configmanager.ConfigManager(A))
    assert fake_switches == []


async def test_expiry_is_per_tenant(fake_switches):
    await _node_of(A, SHARED)
    await _node_of(B, SHARED)
    tenantnet.enter(A)
    macmap.expire()
    tenantnet.enter(None)
    assert macmap._scan.for_tenant(A)['vintage'] == 0
    assert macmap._scan.for_tenant(B)['vintage'] > 0
    assert 'vintage' not in macmap._scan.for_tenant(None)


async def test_lldp_state_is_per_tenant(tenants):
    tenantnet.enter(A)
    lldp._neighbypeerid['peer'] = {'switch': 'sw1'}
    lldp._fastbackends['sw1'] = 'affluent'
    tenantnet.enter(B)
    assert 'peer' not in lldp._neighbypeerid and 'sw1' not in lldp._fastbackends
    tenantnet.enter(None)
    assert dict(lldp._neighbypeerid) == {} and dict(lldp._fastbackends) == {}


async def test_alerts_are_decoded_for_the_tenants_own_node(tenants, monkeypatch):
    # the same BMC address is a different node in each tenant
    for tid, node in ((A, 'bmc-of-a'), (B, 'bmc-of-b')):
        await configmanager.ConfigManager(tid).set_node_attributes(
            {node: {'hardwaremanagement.manager': HW_IP}}, autocreate=True)
    found = {}
    for tid in (A, B, None):
        tenantnet.enter(tid)
        found[tid] = await lookuptools.node_by_manager(
            HW_IP, configmanager.ConfigManager(tid))
        tenantnet.enter(None)
    assert found == {A: 'bmc-of-a', B: 'bmc-of-b', None: None}
    assert lookuptools.manager_to_nodemap.for_tenant(A) == {HW_IP: 'bmc-of-a'}
    assert lookuptools.manager_to_nodemap.for_tenant(None) == {}
    decoded = []

    async def handle_path(path, operation, cfg, inputdata=None, autostrip=True):
        decoded.append((cfg.tenant, path, operation))
        return []
    monkeypatch.setattr(core, 'handle_path', handle_path)
    varbinds = {'1.3.6.1.6.3.18.1.3.0': HW_IP}
    for tid in (A, B):
        tenantnet.enter(tid)
        await alerts.decode_alert(varbinds, configmanager.ConfigManager(tid))
        tenantnet.enter(None)
    assert decoded == [
        (A, '/nodes/bmc-of-a/events/hardware/decode', 'update'),
        (B, '/nodes/bmc-of-b/events/hardware/decode', 'update')]
    with pytest.raises(exc.InvalidArgumentException):
        await alerts.decode_alert(varbinds, configmanager.ConfigManager(None))


def test_tenants_may_use_networking_and_alert_paths():
    for path in ('/networking/', '/networking/macs/by-mac/02-00-00-5e-00-01',
                 '/networking/macs/rescan', '/networking/neighbors/by-switch/sw1/',
                 '/events/', '/events/decode',
                 '/nodes/n1/events/hardware/decode'):
        assert auth._tenant_path_allowed(path), path
    assert not auth._tenant_path_allowed('/events/other')


# ------------------------------------------- within the tenant networks

def _mac_oid(prefix, mac):
    return prefix + '.' + '.'.join(str(int(x, 16)) for x in mac.split(':'))


def _switch_table(macs, peer):
    """What a switch reports: interface names, the MAC table (Q-BRIDGE,
    VLAN 1) and one LLDP neighbor on Ethernet1."""
    table = {
        '1.3.6.1.2.1.1.2.0': ['o', '1.3.6.1.4.1.99999.1'],
        '1.3.6.1.2.1.31.1.1.1.1.1': ['s', 'Ethernet1'],
        '1.3.6.1.2.1.31.1.1.1.1.2': ['s', 'Ethernet2'],
        '1.3.6.1.2.1.17.1.4.1.2.1': ['i', 1],
        '1.3.6.1.2.1.17.1.4.1.2.2': ['i', 2],
        '1.0.8802.1.1.2.1.3.2.0': ['s', 'chassis-' + peer],
        '1.0.8802.1.1.2.1.3.7.1.3.1': ['s', 'Ethernet1'],
        '1.0.8802.1.1.2.1.3.7.1.4.1': ['s', 'Ethernet1'],
        '1.0.8802.1.1.2.1.4.1.1.5.0.1.1': ['s', 'id-' + peer],
        '1.0.8802.1.1.2.1.4.1.1.7.0.1.1': ['s', 'eth0'],
        '1.0.8802.1.1.2.1.4.1.1.9.0.1.1': ['s', peer],
        '1.0.8802.1.1.2.1.4.1.1.10.0.1.1': ['s', 'a server'],
    }
    for mac, port in macs.items():
        table[_mac_oid('1.3.6.1.2.1.17.7.1.2.2.1.2.1', mac)] = ['i', port]
    return table


@pytest.fixture
async def topo(netns, tenants):
    topology = Topology(netns)
    topology.asked = {}
    for tid in TENANTS:
        topology.network(tid)
    topology.asked[A] = topology.start_snmp(
        A, COMMUNITY[A], _switch_table({SHARED: 1, ONLY_A: 2}, 'peer-of-a'))
    topology.asked[B] = topology.start_snmp(
        B, COMMUNITY[B], _switch_table({SHARED: 2, ONLY_B: 1}, 'peer-of-b'))
    tenantguard.recent_violations.clear()
    yield topology
    tenantnet.enter(None)
    # nothing was refused: nothing tried the host's network
    assert list(tenantguard.recent_violations) == []
    topology.cleanup()


def _asked(topo, tid):
    with open(topo.asked[tid]) as f:
        return set(f.read().split())


@pytest.mark.netns
async def test_snmp_walks_the_tenants_own_switch(topo):
    hits = topo.decoy_hits()
    names = {}
    for tid in TENANTS:
        tenantnet.enter(tid)
        session = snmputil.Session('sw1', COMMUNITY[tid])
        names[tid] = [str(vb[1]) async for vb in session.walk('1.3.6.1.2.1.31.1.1.1.1')]
        peer = [str(vb[1]) async for vb in session.walk('1.0.8802.1.1.2.1.4.1.1.9')]
        assert peer == ['peer-of-a' if tid == A else 'peer-of-b']
        session.close()
        tenantnet.enter(None)
    assert names == {A: ['Ethernet1', 'Ethernet2'], B: ['Ethernet1', 'Ethernet2']}
    assert _asked(topo, A) == {COMMUNITY[A]} and _asked(topo, B) == {COMMUNITY[B]}
    assert topo.decoy_hits() == hits


@pytest.mark.netns
async def test_switch_mac_tables_identify_each_tenants_own_nodes(topo):
    hits = topo.decoy_hits()
    assert await _node_of(A, SHARED) == ('n1', {'maccount': 1})
    assert await _node_of(B, SHARED) == (None, {'maccount': 0})
    assert await _node_of(B, ONLY_B) == ('n1', {'maccount': 1})
    assert macmap._macsbyswitch.for_tenant(A) == {
        'sw1': {'Ethernet1': [SHARED], 'Ethernet2': [ONLY_A]}}
    assert macmap._macsbyswitch.for_tenant(B) == {
        'sw1': {'Ethernet1': [ONLY_B], 'Ethernet2': [SHARED]}}
    assert macmap._macmap.for_tenant(None) == {}
    assert macmap._offloader is None  # no helper process was started
    # each switch was only ever asked with its own tenant's community
    assert _asked(topo, A) == {COMMUNITY[A]} and _asked(topo, B) == {COMMUNITY[B]}
    assert topo.decoy_hits() == hits


@pytest.mark.netns
async def test_lldp_neighbors_are_each_tenants_own(topo):
    hits = topo.decoy_hits()
    for tid, peer in ((A, 'peer-of-a'), (B, 'peer-of-b')):
        listing = await _as(tid, '/networking/neighbors/by-peername/')
        assert [r.href for r in listing] == [peer + '/']
        ports = await _as(tid, '/networking/neighbors/by-switch/sw1/by-port/')
        assert [r.href for r in ports] == ['Ethernet1/']
    neighbors = lldp._neighdata.for_tenant(A)['sw1']['Ethernet1']
    assert neighbors['peername'] == 'peer-of-a' and neighbors['peerportid'] == 'eth0'
    assert lldp._neighdata.for_tenant(B)['sw1']['Ethernet1']['peername'] == 'peer-of-b'
    assert dict(lldp._neighdata.for_tenant(None)) == {}
    assert _asked(topo, A) == {COMMUNITY[A]} and _asked(topo, B) == {COMMUNITY[B]}
    assert topo.decoy_hits() == hits
