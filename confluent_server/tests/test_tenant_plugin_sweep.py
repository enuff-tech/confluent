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

"""Every hardware management plugin, run for a tenant.

All plugins are temporarily allowed for tenants, then asked for a few
read-only things about a node whose management address is the tenant's
hardware address. A plugin may only be in core.TENANT_PLUGINS if, while
doing so, it never tried anything the guard refused (a socket not from
the tenant's broker, a host name lookup, a process) and never reached the
same-CIDR decoy on the host.
"""

import asyncio
import os

import pytest

import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
from tenanttopo import HW_IP, TENANTS, Topology

pytestmark = pytest.mark.netns

A = sorted(TENANTS)[0]
ELEMENTS = ('power/state', 'health/hardware', 'inventory/hardware/all/all',
            'sensors/hardware/all/all', 'events/hardware/log')
# Covered with real BMCs by test_tenant_hardware.py, and slow to time out
# without one.
SKIP = frozenset(['ipmi', 'null'])
# Console plugins have no hardware elements: they are swept by connecting.
CONSOLE = frozenset(['openbmc', 'tsmsol'])


def _hardware_plugins():
    if not core.pluginmap:
        core.load_plugins()
    names = []
    for name, module in core.pluginmap.items():
        if getattr(module, '__name__', '').endswith('.null'):
            continue
        path = getattr(module, '__file__', '') or ''
        if os.sep + 'hardwaremanagement' + os.sep in path and name not in SKIP:
            names.append(name)
    return sorted(names)


async def _collect(path, cfm):
    results = await core.handle_path(path, 'retrieve', cfm)
    if hasattr(results, '__aiter__'):
        return [r async for r in results]
    return list(results)


@pytest.fixture
async def sweep(netns, confluent_config, monkeypatch):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    configmanager._true_create_tenant(A, 'acme', configmanager._wrap_tenant_key(os.urandom(32)), 0)
    topology = Topology(netns)
    topology.network(A)
    tenantguard.install(asyncio.get_running_loop())
    plugins = _hardware_plugins()
    allowed = core.TENANT_PLUGINS
    monkeypatch.setattr(core, 'TENANT_PLUGINS', frozenset(plugins) | allowed)
    cfm = configmanager.ConfigManager(A)
    await cfm.set_node_attributes(dict(
        ('n-' + p, {'hardwaremanagement.method': p, 'hardwaremanagement.manager': HW_IP,
                    'secret.hardwaremanagementuser': 'admin',
                    'secret.hardwaremanagementpassword': 'secret'})
        for p in plugins), autocreate=True)
    yield topology, plugins, cfm, allowed
    tenantnet.enter(None)
    topology.cleanup()


async def test_tenant_plugins_never_use_the_host_network(sweep):
    topology, plugins, cfm, allowed = sweep
    hits = topology.decoy_hits()
    unsafe = {}
    outcome = {}
    for plugin in plugins:
        tenantguard.recent_violations.clear()
        tenantnet.enter(A)
        try:
            for element in ELEMENTS:
                try:
                    await asyncio.wait_for(
                        _collect('/nodes/n-{0}/{1}'.format(plugin, element), cfm), 20)
                    outcome.setdefault(plugin, set()).add('ran')
                except tenantguard.TenantNetworkViolation:
                    pass  # recorded below
                except tenantnet.TenantNetworkUnsupported:
                    outcome.setdefault(plugin, set()).add('refused')
                except asyncio.TimeoutError:
                    outcome.setdefault(plugin, set()).add('timeout')
                except Exception:
                    outcome.setdefault(plugin, set()).add('error')
        finally:
            tenantnet.enter(None)
        if tenantguard.recent_violations:
            unsafe[plugin] = sorted(set(e for _, e in tenantguard.recent_violations))
    print('plugin outcomes:', dict((p, sorted(o)) for p, o in outcome.items()))
    print('refused by the guard:', unsafe)
    assert topology.decoy_hits() == hits
    assert not set(allowed) & set(unsafe), 'unsafe plugins allowed for tenants: {0}'.format(
        sorted(set(allowed) & set(unsafe)))
    assert set(allowed) - SKIP - CONSOLE - set(['null']) <= set(plugins)  # all were exercised
    assert outcome  # the sweep did run plugins


async def test_tenant_console_plugins_never_use_the_host_network(sweep):
    topology, plugins, cfm, allowed = sweep
    assert CONSOLE <= set(allowed) and CONSOLE <= set(core.pluginmap)
    topology.start_https(A)  # something to talk to, in the tenant's network
    hits = topology.decoy_hits()
    await cfm.set_node_attributes(dict(
        ('c-' + p, {'console.method': p, 'hardwaremanagement.manager': HW_IP,
                    'secret.hardwaremanagementuser': 'admin',
                    'secret.hardwaremanagementpassword': 'secret'})
        for p in CONSOLE), autocreate=True)
    outcome = {}

    async def output(data):
        pass
    for plugin in sorted(CONSOLE):
        tenantguard.recent_violations.clear()
        tenantnet.enter(A)
        try:
            consoles = await core.handle_path(
                '/nodes/c-{0}/_console/session'.format(plugin), 'create', cfm)
            async for console in consoles:
                try:
                    await asyncio.wait_for(console.connect(output), 20)
                    outcome[plugin] = 'connected'
                except tenantguard.TenantNetworkViolation:
                    outcome[plugin] = 'violation'
                except Exception as e:
                    # the fake endpoint is no BMC: what matters is where
                    # the attempt went
                    outcome[plugin] = type(e).__name__
                finally:
                    await console.close()
        finally:
            tenantnet.enter(None)
        assert list(tenantguard.recent_violations) == [], plugin
    print('console plugin outcomes:', outcome)
    assert set(outcome) == set(CONSOLE)
    assert topology.decoy_hits() == hits
