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

"""Hardware management of tenants through their own networks.

Both tenants have a BMC at the same address with the same credentials;
tenant a's reports power on, tenant b's power off. Every request must
reach its own tenant's BMC, and nothing may reach the host's network.
"""

import asyncio
import os

import pytest

import aiohmi.ipmi.command as ipmicommand
import aiohmi.util.webclient as webclient
import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.tenantnet as tenantnet
from tenanttopo import BMC_PASSWORD, BMC_USER, HW_IP, TENANTS, Topology, wait

pytestmark = pytest.mark.netns

A, B = sorted(TENANTS)
POWER = {A: 'on', B: 'off'}


@pytest.fixture
def topo(netns, confluent_config):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    for tid, (label, _) in TENANTS.items():
        configmanager._true_create_tenant(
            tid, label, configmanager._wrap_tenant_key(os.urandom(32)), 0)
    topology = Topology(netns)
    for tid in TENANTS:
        topology.network(tid)
        topology.start_bmc(tid, POWER[tid])
    yield topology
    tenantnet.enter(None)
    topology.cleanup()


async def _power(tid, explicit=True, attempts=20):
    """Power state of tenant tid's BMC; the fake BMC may still be starting."""
    net = tenantnet.TenantNetworkRef(tid) if explicit else None
    for attempt in range(attempts):
        try:
            cmd = await ipmicommand.Command.create(
                bmc=HW_IP, userid=BMC_USER, password=BMC_PASSWORD, net=net)
            return (await cmd.get_power())['powerstate']
        except Exception:
            if attempt == attempts - 1:
                raise
            await asyncio.sleep(0.5)


async def test_ipmi_sessions_stay_in_their_own_network(topo):
    hits = topo.decoy_hits()
    assert await _power(A) == 'on'
    assert await _power(B) == 'off'
    # cached sessions are reused per network, never across
    for _ in range(3):
        assert await _power(A) == 'on'
        assert await _power(B) == 'off'
    assert topo.decoy_hits() == hits


async def test_ipmi_follows_the_task_tenant(topo):
    tenantnet.enter(A)
    assert await _power(None, explicit=False) == 'on'
    tenantnet.enter(B)
    assert await _power(None, explicit=False) == 'off'


async def test_web_connections_stay_in_their_own_network(topo):
    for tid in TENANTS:
        topo.start_https(tid)
    hits = topo.decoy_hits()
    for tid, (label, _) in TENANTS.items():
        wc = webclient.WebConnection(HW_IP, 443, verifycallback=lambda cert: True,
                                     net=tenantnet.TenantNetworkRef(tid))
        assert (await wc.grab_json_response('/redfish/v1/'))['label'] == label
        # a duplicate keeps the network
        assert (await wc.dupe().grab_json_response('/x'))['label'] == label
        # and the task's tenant is used when none is given
        tenantnet.enter(tid)
        wc = webclient.WebConnection(HW_IP, 443, verifycallback=lambda cert: True)
        assert (await wc.grab_json_response('/redfish/v1/'))['label'] == label
        tenantnet.enter(None)
    assert topo.decoy_hits() == hits


async def _node_power(tid, node='c1'):
    cfm = configmanager.ConfigManager(tid)
    tenantnet.enter(tid)
    try:
        results = await core.handle_path('/nodes/{0}/power/state'.format(node),
                                         'retrieve', cfm)
        if hasattr(results, '__aiter__'):
            results = [r async for r in results]
        return [r.raw() for r in results]
    finally:
        tenantnet.enter(None)


@pytest.fixture
async def nodes(topo):
    if not core.pluginmap:
        core.load_plugins()
    for tid in TENANTS:
        await configmanager.ConfigManager(tid).set_node_attributes({
            'c1': {'hardwaremanagement.manager': HW_IP,
                   'hardwaremanagement.method': 'ipmi',
                   'secret.hardwaremanagementuser': BMC_USER,
                   'secret.hardwaremanagementpassword': BMC_PASSWORD},
            'p1': {'hardwaremanagement.manager': HW_IP,
                   'hardwaremanagement.method': 'proxmox'},
        }, autocreate=True)
    return topo


async def test_power_state_through_confluent(nodes):
    hits = nodes.decoy_hits()
    for tid in TENANTS:
        for attempt in range(20):
            raw = await _node_power(tid)
            # a single node's reply is not keyed by the node name
            state = raw[0].get('c1', raw[0]).get('state', {}).get('value')
            if state:
                break
            await asyncio.sleep(0.5)
        assert state == POWER[tid], raw
    assert nodes.decoy_hits() == hits


async def test_plugins_not_ported_are_refused_for_tenants(nodes):
    hits = nodes.decoy_hits()
    with pytest.raises(Exception, match='proxmox is not yet available within a tenant'):
        await _node_power(A, 'p1')
    assert nodes.decoy_hits() == hits


async def test_fixed_handlers_are_refused_for_tenants(nodes):
    import confluent.exceptions as exc
    tenantnet.enter(A)
    try:
        with pytest.raises(exc.ForbiddenRequest):
            await core.handle_path('/nodes/c1/power/reseat', 'update',
                                   configmanager.ConfigManager(A), {'reseat': 'reseat'})
    finally:
        tenantnet.enter(None)


async def test_broker_down_fails_closed(nodes):
    hits = nodes.decoy_hits()
    nodes.stop_broker(A)
    tenantnet.close_tenant(A)  # drop sockets handed out before the crash
    nodes.network(A)
    with pytest.raises(tenantnet.TenantNetworkError):
        await _power(A, attempts=1)
    assert await _power(B) == 'off'
    assert nodes.decoy_hits() == hits
    nodes.start_broker(A)
    wait(lambda: os.path.exists(nodes.socket_path(A)))
    assert await _power(A) == 'on'
