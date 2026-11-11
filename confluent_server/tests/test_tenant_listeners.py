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

"""Discovery listens in each tenant's own networks.

The two tenant networks are identical (same subnet, same addresses, same
MACs). A packet belongs to the tenant whose socket it arrived on: the same
PXE client, DHCP client or SSDP announcement in both networks is two
separate events, each handled with its own tenant's configuration, and
nothing is heard on, or answered through, the host's network.
"""

import asyncio
import json
import os
import subprocess
import sys

import pytest

import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.discovery.core as disco
import confluent.discovery.protocols.pxe as pxe
import confluent.discovery.protocols.ssdp as ssdp
import confluent.neighutil as neighutil
import confluent.netutil as netutil
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
import confluent.tenantstate as tenantstate
from tenanttopo import HW_IP, HW_MAC, TENANTS, UP_IP, Topology

A, B = sorted(TENANTS)
MAC = '02:00:00:5e:00:07'           # the same client in both tenants
RAW_UUID = bytes(range(0x30, 0x40))
UUID = pxe.decode_uuid(RAW_UUID)
PORTS = (':67 ', ':427 ', ':547 ', ':1900 ')


async def _until(cond, timeout=10):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return
        await asyncio.sleep(0.05)
    raise AssertionError('timed out')


def _create(tid):
    configmanager._true_create_tenant(
        tid, TENANTS[tid][0], configmanager._wrap_tenant_key(os.urandom(32)), 0)


@pytest.fixture
async def tenancy(confluent_config, monkeypatch):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(disco, 'TENANT_LISTENER_RETRY', 0.2)
    yield
    for tid in list(disco._tenant_listeners):
        disco.stop_tenant_detection(tid)
    tenantnet.enter(None)


# ----------------------------------------------- without tenant networks

async def test_only_active_autosensing_tenants_are_listened_for(tenancy):
    assert disco.start_tenant_detection(None) is False
    assert disco.start_tenant_detection('t0000000000ff') is False
    _create(A)  # announced as active: discovery starts listening
    assert disco.tenant_detection_status(A) is False  # no network yet
    assert disco.start_tenant_detection(A) is True    # already set up
    cfg = configmanager.ConfigManager(A)
    cfg.set_scoped_global('discovery.autosense', False)
    disco.stop_tenant_detection(A)
    assert disco.start_tenant_detection(A) is False
    cfg.set_scoped_global('discovery.autosense', True)
    assert disco.start_tenant_detection(A) is True
    await configmanager.set_tenant_state(A, 'disabled')
    assert disco.tenant_detection_status(A) is None
    assert disco.start_tenant_detection(A) is False
    await configmanager.set_tenant_state(A, 'active')
    assert disco.tenant_detection_status(A) is False
    await configmanager.set_tenant_state(A, 'disabled')
    await configmanager.delete_tenant(A)
    assert disco.tenant_detection_status(A) is None


async def test_listening_waits_for_the_tenants_network(tenancy):
    _create(A)
    await asyncio.sleep(0.5)  # several retries: there is no broker
    state = disco._tenant_listeners[A]
    assert state['listening'] is False and state['sockets'] == []
    assert not state['tasks'][0].done()
    disco.stop_tenant_detection(A)
    await asyncio.sleep(0)
    assert state['tasks'][0].cancelled() or state['tasks'][0].done()


async def test_periodic_recheck_is_per_tenant(tenancy):
    _create(A)
    tenantnet.enter(A)
    disco._recheck['time'] = 1
    tenantnet.enter(None)
    assert 'time' not in disco._recheck
    assert disco._recheck.for_tenant(A) == {'time': 1}


async def test_pxe_node_maps_are_per_tenant(tenancy):
    _create(A)
    _create(B)
    cfga, cfgb = configmanager.ConfigManager(A), configmanager.ConfigManager(B)
    await cfga.set_node_attributes(
        {'n1': {'net.hwaddr': MAC, 'id.uuid': UUID}}, autocreate=True)
    await cfgb.set_node_attributes({'other': {'net.hwaddr': MAC}}, autocreate=True)
    pxe.remap_nodes(['n1'], cfga)
    pxe.remap_nodes(['other'], cfgb)
    assert pxe.macmap.for_tenant(A) == {MAC: 'n1'}
    assert pxe.uuidmap.for_tenant(A) == {UUID: 'n1'}
    assert pxe.macmap.for_tenant(B) == {MAC: 'other'}
    assert pxe.macmap.for_tenant(None) == {}
    pxe.clear_nodes(['n1'], A)
    assert pxe.macmap.for_tenant(A) == {} and pxe.macmap.for_tenant(B) == {MAC: 'other'}


def test_host_interface_helpers_are_unchanged():
    assert all(isinstance(idx, int) for idx in netutil.interface_indexes())
    for entry in netutil.ipv4_interfaces():
        assert 'addr' in entry


# ------------------------------------------- within the tenant networks

def _udp_listeners(ns=None):
    cmd = ['ss', '-Hlun']
    if ns is not None:
        cmd = ['ip', 'netns', 'exec', ns] + cmd
    return subprocess.run(cmd, capture_output=True, check=True).stdout.decode()


def _own_host_udp():
    """UDP sockets this process holds in the host's network (other
    services of the host come and go, and are not ours to judge)."""
    listing = subprocess.run(['ss', '-Hlunp'], capture_output=True, check=True)
    mine = 'pid={0},'.format(os.getpid())
    return sorted(line.split()[3] for line in listing.stdout.decode().splitlines()
                  if mine in line)


@pytest.fixture
async def topo(netns, tenancy):
    topology = Topology(netns)
    topology.host_udp = _own_host_udp()
    tenantguard.recent_violations.clear()
    for tid in TENANTS:
        topology.network(tid)
        _create(tid)
    for tid in TENANTS:
        await _until(lambda tid=tid: disco.tenant_detection_status(tid))
    yield topology
    # nothing discovery did for a tenant was refused: it never tried
    # the host's network
    assert list(tenantguard.recent_violations) == []
    for tid in TENANTS:
        disco.stop_tenant_detection(tid)
    tenantnet.enter(None)
    topology.cleanup()


async def _dhcp(topo, tid, mode='plain', patience=3):
    out = topo.dhcp_client(tid, MAC, mode, RAW_UUID.hex(), patience)
    await _until(lambda: os.path.exists(out), timeout=3 * patience + 10)
    with open(out) as f:
        return json.load(f)


async def _restart(tid):
    disco.stop_tenant_detection(tid)
    assert disco.start_tenant_detection(tid)
    await _until(lambda tid=tid: disco.tenant_detection_status(tid))


@pytest.mark.netns
async def test_listeners_are_bound_in_the_tenant_namespaces(topo):
    for tid in TENANTS:
        bound = _udp_listeners(topo.ns[tid])
        for port in PORTS:
            assert port in bound, (tid, port, bound)
        assert all(s.fileno() != -1 for s in disco._tenant_listeners[tid]['sockets'])
    # nothing was opened in the host's network for them
    assert _own_host_udp() == topo.host_udp


@pytest.mark.netns
async def test_broker_reports_the_tenants_neighbors(topo):
    net = topo.network(A)
    net.connect_tcp(HW_IP, 7000).close()
    assert net.neighbor(HW_IP) == HW_MAC
    assert net.neighbor('10.241.34.200') is None
    for bad in ('bmc-a', '10.241.34', 7, ''):
        with pytest.raises(tenantnet.BrokerError):
            net.neighbor(bad)
    tenantnet.enter(A)
    assert await neighutil.get_hwaddr(HW_IP) == HW_MAC
    assert await neighutil.get_hwaddr('192.0.2.9') is False  # not on its networks


@pytest.mark.netns
async def test_pxe_client_is_detected_by_the_tenant_it_boots_in(topo):
    hits = topo.decoy_hits()
    await configmanager.ConfigManager(A).set_node_attributes(
        {'n1': {'id.uuid': UUID, 'discovery.policy': 'pxe'}}, autocreate=True)
    await configmanager.ConfigManager(None).set_node_attributes(
        {'n1': {'id.uuid': UUID, 'discovery.policy': 'pxe'}}, autocreate=True)
    result = await _dhcp(topo, A, 'pxe', patience=1.5)
    await _until(lambda: MAC in disco.known_info.for_tenant(A))
    info = disco.known_info.for_tenant(A)[MAC]
    assert info['uuid'] == UUID and tuple(info['services']) == ('pxe-client',)
    await _until(lambda: 'n1' in disco.known_nodes.for_tenant(A))
    assert MAC not in disco.known_info.for_tenant(B)
    assert MAC not in disco.known_info.for_tenant(None)
    # network boot is not offered within tenants yet
    assert result['offer'] is None
    # the very same client in tenant b's network is tenant b's own event,
    # and b has no node for it
    await _dhcp(topo, B, 'pxe', patience=1.5)
    await _until(lambda: MAC in disco.known_info.for_tenant(B))
    assert disco.known_info.for_tenant(B)[MAC] is not info
    assert list(disco.known_nodes.for_tenant(B)) == []
    assert MAC not in disco.known_info.for_tenant(None)
    assert topo.decoy_hits() == hits


@pytest.mark.netns
async def test_tenants_choose_static_or_dhcp_addressing(topo):
    hits = topo.decoy_hits()
    cfga, cfgb = configmanager.ConfigManager(A), configmanager.ConfigManager(B)
    # the same node (same MAC) in both tenants: a assigns it a static
    # address, b leaves it to its own DHCP service
    await cfga.set_node_attributes({'n1': {
        'net.hwaddr': MAC, 'net.ipv4_address': '10.241.34.50/24',
        'net.ipv4_method': 'static', 'net.lease_time': '600'}}, autocreate=True)
    await cfgb.set_node_attributes({'n1': {
        'net.hwaddr': MAC, 'net.ipv4_address': '10.241.34.60/24',
        'net.ipv4_method': 'dhcp', 'net.lease_time': '600'}}, autocreate=True)
    await _until(lambda: MAC in pxe.macmap.for_tenant(A) and MAC in pxe.macmap.for_tenant(B))
    ra, rb = await asyncio.gather(_dhcp(topo, A), _dhcp(topo, B, patience=2))
    assert ra['offer'] == {
        'yiaddr': '10.241.34.50', 'server': UP_IP, 'lease': 600,
        'netmask': '255.255.255.0', 'gateway': '0.0.0.0', 'vendor': '',
        'bootfile': ''}
    assert ra['ack'] and ra['ack']['yiaddr'] == '10.241.34.50'
    assert rb == {'offer': None, 'ack': None}
    rawmac = bytes.fromhex(MAC.replace(':', ''))
    assert rawmac in pxe.staticassigns.for_tenant(A)
    assert rawmac not in pxe.staticassigns.for_tenant(B)
    assert not pxe.staticassigns.for_tenant(None)
    # each tenant changes its mind independently
    await cfgb.set_node_attributes({'n1': {'net.ipv4_method': 'static',
                                           'net.ipv4_gateway': '10.241.34.254'}})
    await cfga.set_node_attributes({'n1': {'net.ipv4_method': 'dhcp'}})
    ra, rb = await asyncio.gather(_dhcp(topo, A, patience=2), _dhcp(topo, B))
    assert ra == {'offer': None, 'ack': None}
    assert rb['offer']['yiaddr'] == '10.241.34.60'
    assert rb['offer']['gateway'] == '10.241.34.254'
    assert rb['ack'] and rb['ack']['yiaddr'] == '10.241.34.60'
    # firmwarenone: nothing at all from this service
    await cfgb.set_node_attributes({'n1': {'net.ipv4_method': 'firmwarenone'}})
    assert await _dhcp(topo, B, patience=2) == {'offer': None, 'ack': None}
    assert topo.decoy_hits() == hits


@pytest.mark.netns
async def test_ssdp_announcement_belongs_to_the_network_it_was_heard_in(topo, monkeypatch):
    seen = []

    def record(info):
        seen.append((tenantguard.current_tenant.get(), info.get('hwaddr'),
                     info['addresses'][0][0]))

    async def fish(urldata, port=443, verifycallback=None):
        return dict(urldata[1], services=['generic-redfish'])
    monkeypatch.setattr(disco, 'safe_detected', record)
    monkeypatch.setattr(ssdp, 'check_fish', fish)
    for tid in TENANTS:
        await _restart(tid)
    topo.ssdp_notify(A)
    await _until(lambda: seen, timeout=15)
    await asyncio.sleep(0.5)
    # heard once, by tenant a, with the MAC from tenant a's neighbor table
    assert seen == [(A, HW_MAC, HW_IP)]
    del seen[:]
    topo.ssdp_notify(B)
    await _until(lambda: seen, timeout=15)
    await asyncio.sleep(0.5)
    assert seen == [(B, HW_MAC, HW_IP)]


SNIFF = r'''
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 1900))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
             socket.inet_aton('239.255.255.250') + socket.inet_aton(sys.argv[1]))
open(sys.argv[2] + '.ready', 'w').close()
while True:
    data, peer = s.recvfrom(4096)
    if data.startswith(b'M-SEARCH'):
        with open(sys.argv[2], 'a') as f:
            f.write(peer[0] + '\n')
'''


@pytest.mark.netns
async def test_rescan_searches_the_tenants_own_networks(topo):
    # no listeners (they search once when they start): only the rescan
    # asked for below sends anything
    for tid in TENANTS:
        disco.stop_tenant_detection(tid)
    await asyncio.sleep(0.2)
    heard = {}
    for tid in TENANTS:
        heard[tid] = os.path.join(topo.dir, 'msearch-' + tid)
        topo.netns.spawn(topo.lan[tid], sys.executable, '-c', SNIFF, HW_IP, heard[tid])
        await _until(lambda tid=tid: os.path.exists(heard[tid] + '.ready'))

    async def api(tid, operation, inputdata=None):
        tenantnet.enter(tid)
        try:
            rsp = await core.handle_path('/discovery/rescan', operation,
                                         configmanager.ConfigManager(tid), inputdata)
            return [r.kvpairs for r in rsp]
        finally:
            tenantnet.enter(None)

    assert await api(A, 'retrieve') == [{'scanning': False}]
    assert await api(A, 'update', {'rescan': 'start'}) == [{'rescan': 'started'}]
    assert await api(A, 'retrieve') == [{'scanning': True}]
    assert await api(B, 'retrieve') == [{'scanning': False}]
    assert disco.scanner is None  # the host's scanner was not started
    await _until(lambda: os.path.exists(heard[A]), timeout=30)
    with open(heard[A]) as f:
        assert set(f.read().split()) == {UP_IP}
    scanner = disco._tenant_scan.for_tenant(A).get('scanner')
    if scanner is not None:
        await asyncio.wait_for(scanner, 60)
    assert await api(A, 'retrieve') == [{'scanning': False}]
    assert not os.path.exists(heard[B])


@pytest.mark.netns
async def test_listeners_follow_autosense_and_tenant_state(topo):
    async def autosense(tid, enabled):
        tenantnet.enter(tid)
        try:
            await core.handle_path('/discovery/autosense', 'update',
                                   configmanager.ConfigManager(tid), {'enabled': enabled})
        finally:
            tenantnet.enter(None)

    def listening(tid):
        bound = _udp_listeners(topo.ns[tid])
        return [port for port in PORTS if port in bound]

    await configmanager.ConfigManager(A).set_node_attributes({'n1': {
        'net.hwaddr': MAC, 'net.ipv4_address': '10.241.34.50/24',
        'net.lease_time': '600'}}, autocreate=True)
    await _until(lambda: MAC in pxe.macmap.for_tenant(A))
    assert (await _dhcp(topo, A))['offer']
    sockets = list(disco._tenant_listeners[A]['sockets'])
    await autosense(A, False)
    assert disco.tenant_detection_status(A) is None
    assert all(s.fileno() == -1 for s in sockets)
    assert listening(A) == [] and listening(B) == list(PORTS)
    assert await _dhcp(topo, A, patience=1.5) == {'offer': None, 'ack': None}
    await autosense(A, True)
    await _until(lambda: disco.tenant_detection_status(A))
    assert listening(A) == list(PORTS)
    assert (await _dhcp(topo, A))['offer']
    # a disabled tenant is not listened for; its network is closed
    await configmanager.set_tenant_state(A, 'disabled')
    assert disco.tenant_detection_status(A) is None and listening(A) == []
    # enabled again, discovery waits until its network is back
    await configmanager.set_tenant_state(A, 'active')
    await asyncio.sleep(0.6)
    assert disco.tenant_detection_status(A) is False and listening(A) == []
    topo.network(A)
    await _until(lambda: disco.tenant_detection_status(A))
    assert listening(A) == list(PORTS)
    # a deleted tenant leaves nothing behind
    await configmanager.set_tenant_state(B, 'disabled')
    await configmanager.delete_tenant(B)
    assert disco.tenant_detection_status(B) is None and listening(B) == []
    for scoped in tenantstate._scoped:
        assert B not in scoped._stores
    assert _own_host_udp() == topo.host_udp
