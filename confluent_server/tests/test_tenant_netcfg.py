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

"""The network a tenant manages for itself.

Two tenants give their uplink the same addresses and the same routes.
Each change lands in the changing tenant's own namespace only, made by a
helper that holds one capability and can act on nothing else; it is kept
in the tenant's store and applied again when the namespace is new.
"""

import asyncio
import os
import subprocess

import pytest

import confluent.auth as auth
import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.discovery.core as disco
import confluent.exceptions as exc
import confluent.networking.tenantnetcfg as netcfg
import confluent.tenancy as tenancy
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
import confluent.tenantservices as services
from tenanttopo import TENANTS, UP_IP, Topology

A, B = sorted(TENANTS)
UPLINK = UP_IP + '/24'          # what the uplink has to begin with
EXTRA = '10.250.1.1/24'         # the same in both tenants
ROUTES = [{'destination': '10.99.0.0/16', 'gateway': '10.250.1.254'},
          {'destination': 'default', 'gateway': '10.250.1.254', 'metric': 50}]


async def _until(cond, timeout=10):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return
        await asyncio.sleep(0.05)
    raise AssertionError('timed out')


@pytest.fixture
async def tenancy_on(confluent_config, monkeypatch):
    configmanager.init_masterkey()
    configmanager.set_global('tenancy.schema', configmanager.TENANCY_SCHEMA)
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(netcfg, 'POLL', 0.2)
    restarted = []
    # what is restarted when a tenant's addresses change, without running it
    monkeypatch.setattr(disco, 'start_tenant_detection',
                        lambda tenant: restarted.append(('discovery', tenant)))
    monkeypatch.setattr(services, 'start',
                        lambda tenant: restarted.append(('services', tenant)))
    yield restarted
    for tid in list(netcfg._monitors):
        netcfg.stop(tid)
    tenantnet.enter(None)


def _create(tid):
    configmanager._true_create_tenant(
        tid, TENANTS[tid][0], configmanager._wrap_tenant_key(os.urandom(32)), 0)


async def _as(tid, path, operation='retrieve', inputdata=None):
    tenantnet.enter(tid)
    try:
        result = await core.handle_path(
            path, operation, configmanager.ConfigManager(tid), inputdata)
        return [r.href if hasattr(r, 'href') else r.kvpairs for r in result]
    finally:
        tenantnet.enter(None)


# ----------------------------------------------- without tenant networks

def test_input_is_validated():
    assert netcfg._addresses('10.1.1.1/24, fd00::1/64') == ['10.1.1.1/24', 'fd00::1/64']
    for bad in (['10.1.1.1'], ['127.0.0.1/8'], ['224.0.0.1/4'], ['0.0.0.0/0'],
                ['not-an-address/24'], [7], 5):
        with pytest.raises(exc.InvalidArgumentException):
            netcfg._addresses(bad)
    assert netcfg._routes([{'destination': '10.9.0.0/16', 'gateway': '10.1.1.254'}]) == [
        {'destination': '10.9.0.0/16', 'gateway': '10.1.1.254'}]
    assert netcfg._routes([{'destination': '10.9.0.0/16', 'interface': 'up0', 'metric': '5'}]) == [
        {'destination': '10.9.0.0/16', 'ifname': 'up0', 'metric': 5}]
    for bad in ([{'destination': 'default'}], [{'destination': '10.9.0.0/16'}],
                [{'destination': '10.9.0.1/16', 'gateway': '10.1.1.254'}],  # not a network
                [{'destination': 'bogus', 'gateway': '10.1.1.1'}],
                [{'destination': '10.9.0.0/16', 'gateway': 'gw.example'}],
                [{'destination': '10.9.0.0/16', 'gateway': '10.1.1.1', 'table': 5}],
                'default via 10.1.1.1', [5]):
        with pytest.raises(exc.InvalidArgumentException):
            netcfg._routes(bad)
    assert netcfg._dns({'nameservers': '10.1.1.53 10.1.1.54', 'search': ['a.example']}) == {
        'nameservers': ['10.1.1.53', '10.1.1.54'], 'search': ['a.example']}
    for bad in ({'nameservers': ['ns.example']}, {'nameservers': 5}, {'options': 'rotate'}):
        with pytest.raises(exc.InvalidArgumentException):
            netcfg._dns(bad)


async def test_only_a_tenants_network_is_managed(tenancy_on):
    _create(A)
    # the network of the default tenant is the host's: not managed here
    for path in ('/networking/interfaces/', '/networking/routes', '/networking/dns'):
        with pytest.raises(exc.NotFoundException):
            await _as(None, path)
        with pytest.raises(exc.NotFoundException):
            await _as(None, path, 'update', {})
    assert set(await _as(None, '/networking/')) == {'macs/', 'neighbors/'}
    assert set(await _as(A, '/networking/')) == {
        'macs/', 'neighbors/', 'interfaces/', 'routes', 'dns'}
    # a tenant without a configuration helper: said so, nothing changed
    with pytest.raises(exc.TargetEndpointUnreachable):
        await _as(A, '/networking/interfaces/')
    assert await _as(A, '/networking/dns') == [{}]
    with pytest.raises(exc.TargetEndpointUnreachable):
        await _as(A, '/networking/dns', 'update', {'nameservers': ['10.1.1.53']})
    # (it is kept, to be applied when the helper is there)
    assert configmanager.ConfigManager(A).get_scoped_global('netcfg')['dns'] == {
        'nameservers': ['10.1.1.53'], 'search': []}
    assert configmanager.ConfigManager(None).get_scoped_global('netcfg') is None


async def test_only_the_tenants_administrators_change_its_network(tenancy_on):
    record = await tenancy.create('acme')
    await tenancy.redeem_enrollment('acme', record['enrollment_token'], 'admin', 'Passw0rd!x')
    cfm = configmanager.ConfigManager(record['id'])
    await cfm.create_user('op', role='Operator')
    await cfm.create_user('mon', role='Monitor')
    await configmanager.ConfigManager(None).create_user('plat', role='PlatformAdmin')

    def allowed(user, path, operation):
        result = auth.authorize(user, path, operation=operation)
        return bool(result) and result is not False
    for path in ('/networking/interfaces/up0', '/networking/routes', '/networking/dns'):
        assert allowed('acme/admin', path, 'update')
        assert allowed('acme/admin', path, 'retrieve')
        assert not allowed('acme/op', path, 'update')
        assert not allowed('acme/mon', path, 'update')
        assert not allowed('acme/op', path, 'delete')
        # the platform's administrators do not manage a tenant's network
        assert not allowed('plat', path, 'update')
        assert not allowed('plat', path, 'retrieve')


async def test_configuration_is_kept_only_while_the_tenant_is_in_use(tenancy_on):
    assert netcfg.start(None) is False
    assert netcfg.start('t0000000000ff') is False
    _create(A)  # announced as active
    assert A in netcfg._monitors
    await configmanager.set_tenant_state(A, 'disabled')
    assert A not in netcfg._monitors and netcfg.start(A) is False
    await configmanager.set_tenant_state(A, 'active')
    assert A in netcfg._monitors


# ------------------------------------------- within the tenant networks

def _ip(ns, *args):
    cmd = ['ip'] + (['-n', ns] if ns else []) + list(args)
    return subprocess.run(cmd, capture_output=True, check=True).stdout.decode()


def _addrs(topo, tid):
    return sorted(line.split()[3] for line in
                  _ip(topo.ns[tid], '-4', '-o', 'addr', 'show', 'up0').splitlines())


def _host_addrs():
    # interface and address only: flags such as tentative come and go
    return sorted((line.split()[1], line.split()[3])
                  for line in _ip(None, '-o', 'addr').splitlines())


def _static_routes(ns):
    return sorted(' '.join(line.split()) for line in
                  _ip(ns, 'route', 'show', 'proto', 'static').splitlines())


@pytest.fixture
async def topo(netns, tenancy_on):
    topology = Topology(netns)
    topology.host_routes = _ip(None, 'route')
    topology.host_addrs = _host_addrs()
    tenantguard.recent_violations.clear()
    for tid in TENANTS:
        _create(tid)
        topology.network(tid)
        topology.start_netcfg(tid)
        topology.netcfg(tid)
    yield topology
    for tid in list(netcfg._monitors):
        netcfg.stop(tid)
    tenantnet.enter(None)
    assert list(tenantguard.recent_violations) == []
    # whatever the tenants did, the host's own network is as it was
    assert _ip(None, 'route') == topology.host_routes
    assert _host_addrs() == topology.host_addrs
    topology.cleanup()


@pytest.mark.netns
async def test_helper_changes_its_own_namespace_and_nothing_else(topo):
    helper = tenantnet.netcfg_for(A)
    hello = helper.call('hello', {})[0]
    # one capability (CAP_NET_ADMIN is bit 12), no way to gain more
    assert int(hello['proc']['CapEff'], 16) == 1 << 12
    assert int(hello['proc']['CapBnd'], 16) == 1 << 12
    assert hello['proc']['NoNewPrivs'] == '1' and hello['uid'] != 0
    assert hello['netns_ino'] == os.stat('/run/netns/' + topo.ns[A]).st_ino
    # only what the platform attached to this tenant exists for it
    links = helper.call('link_list', {})[0]['interfaces']
    assert sorted(i['name'] for i in links) == ['lo', 'up0']
    hostlinks = [line.split(':')[1].strip().split('@')[0]
                 for line in _ip(None, '-o', 'link').splitlines()]
    for name in set(hostlinks) - {'lo', 'up0'}:
        with pytest.raises(tenantnet.BrokerError) as refused:
            helper.call('addr_add', {'ifname': name, 'address': EXTRA})
        assert refused.value.code in ('ENODEV', 'EINVAL'), name
    # the operation set is closed: it creates and moves nothing, hands out
    # no sockets, and is not the broker
    for op, args in (('link_add', {'ifname': 'new0'}), ('link_del', {'ifname': 'up0'}),
                     ('link_set', {'ifname': 'up0', 'netns': 1}),
                     ('link_set', {'ifname': 'up0', 'name': 'eth9'}),
                     ('udp_socket', {'family': 'inet'}), ('packet_socket', {}),
                     ('exec', {'argv': ['ip', 'link']})):
        with pytest.raises(tenantnet.BrokerError) as refused:
            helper.call(op, args)
        assert refused.value.code in ('EOPNOTSUPP', 'EINVAL'), op
    for op, args in (('addr_add', {'ifname': 'up0', 'address': '127.0.0.1/8'}),
                     ('addr_add', {'ifname': 'up0', 'address': '10.1.1.1'}),
                     ('route_add', {'destination': 'default'}),
                     ('route_add', {'destination': '10.9.0.0/16', 'gateway': 'gw.example'}),
                     ('link_set', {'ifname': 'up0', 'mtu': 10}),
                     ('dns_set', {'nameservers': ['ns.example']}),
                     ('dns_set', {'nameservers': ['10.1.1.53'], 'search': ['a b; rm']})):
        with pytest.raises(tenantnet.BrokerError) as refused:
            helper.call(op, args)
        assert refused.value.code == 'EINVAL', (op, args)
    # what it does, it does in tenant a's namespace only
    helper.call('addr_add', {'ifname': 'up0', 'address': EXTRA})
    assert _addrs(topo, A) == sorted([UPLINK, EXTRA]) and _addrs(topo, B) == [UPLINK]
    helper.call('addr_del', {'ifname': 'up0', 'address': EXTRA})
    assert _addrs(topo, A) == [UPLINK]
    with pytest.raises(tenantnet.TenantNetworkError):
        helper.call('link_list', {}, True)  # it never hands out a socket


@pytest.mark.netns
async def test_helper_without_its_capability_changes_nothing(topo):
    topo.stop_netcfg(B)
    tenantnet.close_tenant(B)
    topo.network(B)
    topo.start_netcfg(B, caps='-all')
    helper = topo.netcfg(B)
    assert int(helper.call('hello', {})[0]['proc']['CapEff'], 16) == 0
    with pytest.raises(tenantnet.BrokerError) as refused:
        helper.call('addr_add', {'ifname': 'up0', 'address': EXTRA})
    assert refused.value.code in ('EPERM', 'EACCES')
    assert _addrs(topo, B) == [UPLINK]
    # and a helper that is not the tenant's own account is not trusted
    topo.netcfg(B, uid=12345)
    with pytest.raises(tenantnet.BrokerRejected):
        tenantnet.netcfg_for(B).call('link_list', {})


@pytest.mark.netns
async def test_two_tenants_use_the_same_networks_and_routes(topo, tenancy_on):
    wanted = {'addresses': [UPLINK, EXTRA], 'mtu': 1400}
    for tid in TENANTS:
        del tenancy_on[:]
        view = (await _as(tid, '/networking/interfaces/up0', 'update', dict(wanted)))[0]
        assert view['errors'] == [] and view['mtu'] == 1400
        assert sorted(a for a in view['addresses'] if '.' in a) == sorted([UPLINK, EXTRA])
        # its discovery and node services were restarted on the new addresses
        assert sorted(tenancy_on) == [('discovery', tid), ('services', tid)]
        routes = (await _as(tid, '/networking/routes', 'update', {'routes': ROUTES}))[0]
        assert routes['errors'] == []
        dns = {'nameservers': ['10.250.1.53'], 'search': [TENANTS[tid][0] + '.example']}
        assert (await _as(tid, '/networking/dns', 'update', dns))[0]['errors'] == []
    for tid in TENANTS:
        assert _addrs(topo, tid) == sorted([UPLINK, EXTRA])
        assert 'mtu 1400' in _ip(topo.ns[tid], 'link', 'show', 'up0')
        assert _static_routes(topo.ns[tid]) == [
            '10.99.0.0/16 via 10.250.1.254 dev up0',
            'default via 10.250.1.254 dev up0 metric 50']
        with open(topo.resolv_conf(tid)) as f:
            resolv = f.read()
        assert 'nameserver 10.250.1.53' in resolv
        assert 'search {0}.example'.format(TENANTS[tid][0]) in resolv
        # kept in the tenant's own store
        stored = configmanager.ConfigManager(tid).get_scoped_global('netcfg')
        assert stored['interfaces'] == {'up0': {'addresses': sorted([UPLINK, EXTRA]),
                                                'mtu': 1400}}
        assert len(stored['routes']) == 2
        assert sorted(await _as(tid, '/networking/interfaces/')) == ['up0']
        active = (await _as(tid, '/networking/routes'))[0]['active']
        assert {r['destination'] for r in active if r['protocol'] == 'static'} == {
            '10.99.0.0/16', 'default'}
    assert configmanager.ConfigManager(None).get_scoped_global('netcfg') is None
    # one tenant changing its mind does not touch the other
    await _as(A, '/networking/interfaces/up0', 'update', {'addresses': [UPLINK]})
    await _as(A, '/networking/routes', 'delete')
    assert _addrs(topo, A) == [UPLINK] and _static_routes(topo.ns[A]) == []
    assert _addrs(topo, B) == sorted([UPLINK, EXTRA])
    assert len(_static_routes(topo.ns[B])) == 2


@pytest.mark.netns
async def test_a_tenant_cannot_name_what_is_not_in_its_network(topo):
    hostlinks = [line.split(':')[1].strip().split('@')[0]
                 for line in _ip(None, '-o', 'link').splitlines()]
    for name in sorted(set(hostlinks) - {'lo', 'up0'})[:3] + ['hw0', '../etc', 'lo']:
        with pytest.raises((exc.NotFoundException, exc.InvalidArgumentException)):
            await _as(A, '/networking/interfaces/' + name, 'update', {'addresses': [EXTRA]})
    with pytest.raises(exc.InvalidArgumentException):
        await _as(A, '/networking/interfaces/up0', 'update', {'master': 'br0'})
    with pytest.raises(exc.InvalidArgumentException):
        await _as(A, '/networking/interfaces/up0', 'update', {'mtu': 9})
    # a route through an interface it does not have is reported, not made
    result = (await _as(A, '/networking/routes', 'update', {'routes': [
        {'destination': '10.77.0.0/16', 'interface': hostlinks[-1] if hostlinks[-1] not in
         ('lo', 'up0') else 'nosuch0'}]}))[0]
    assert result['errors'] and _static_routes(topo.ns[A]) == []
    assert _addrs(topo, A) == [UPLINK]


@pytest.mark.netns
async def test_configuration_is_applied_again_after_a_restart(topo, tenancy_on):
    await _as(A, '/networking/interfaces/up0', 'update', {'addresses': [UPLINK, EXTRA]})
    await _as(A, '/networking/routes', 'update', {'routes': ROUTES})
    assert netcfg.start(A)
    await asyncio.sleep(0.5)
    # something removes it behind the service's back (an interface that
    # went away and came back)
    del tenancy_on[:]
    _ip(topo.ns[A], 'addr', 'del', EXTRA, 'dev', 'up0')
    await _until(lambda: _addrs(topo, A) == sorted([UPLINK, EXTRA]))
    await _until(lambda: len(_static_routes(topo.ns[A])) == 2)
    await _until(lambda: ('services', A) in tenancy_on)
    # a new helper, as after a reboot of the host, with the network bare
    topo.stop_netcfg(A)
    tenantnet.close_tenant(A)
    _ip(topo.ns[A], 'route', 'flush', 'proto', 'static')
    _ip(topo.ns[A], 'addr', 'del', EXTRA, 'dev', 'up0')
    assert _addrs(topo, A) == [UPLINK] and _static_routes(topo.ns[A]) == []
    topo.network(A)
    topo.start_netcfg(A)
    topo.netcfg(A)
    await _until(lambda: _addrs(topo, A) == sorted([UPLINK, EXTRA]))
    await _until(lambda: len(_static_routes(topo.ns[A])) == 2)
    # tenant b, which configured nothing, is as the platform left it
    assert _addrs(topo, B) == [UPLINK] and _static_routes(topo.ns[B]) == []
