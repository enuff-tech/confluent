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

"""Consoles of, and shells on, a tenant's own nodes.

Both tenants have a node n1. Each has its own console: connected in its
own tenant's network (whoever asks for the connection), with its own
terminal buffer and its own log, seen only by its own tenant's sessions,
and closed with its tenant.
"""

import asyncio
import os
import types

import pytest

import confluent.config.configmanager as configmanager
import confluent.consoleserver as consoleserver
import confluent.core as core
import confluent.discovery.core as disco
import confluent.exceptions as exc
import confluent.interface.console as conapi
import confluent.log as log
import confluent.shellserver as shellserver
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
import confluent.tenantservices as services
from tenanttopo import BMC_PASSWORD, BMC_USER, TENANTS, Topology

A = 't00000000000a'
B = 't00000000000b'


async def _until(cond, timeout=10):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError('timed out')


class FakeConsole(conapi.Console):
    """A console that remembers which tenant each use of it worked for."""
    made = []

    def __init__(self, node, config):
        self.node = node
        self.tenant = config.tenant
        self.connected_as = []
        self.written = []
        self.closed = False
        self.output = None
        FakeConsole.made.append(self)

    async def connect(self, callback):
        net = tenantnet.current_network()
        self.connected_as.append((tenantguard.current_tenant.get(),
                                  None if net is None else net.tenant))
        self.output = callback
        await callback('console of {0} in {1}\r\n'.format(self.node, self.tenant))

    async def write(self, data):
        self.written.append(data)

    async def close(self):
        self.closed = True


async def _create(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield FakeConsole(node, configmanager)


@pytest.fixture
async def consoles(confluent_config, monkeypatch):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    if not core.pluginmap:
        core.load_plugins()
    # console and shell plugins that connect nowhere
    fake = types.SimpleNamespace(create=_create)
    monkeypatch.setitem(core.pluginmap, 'ipmi', fake)
    monkeypatch.setitem(core.pluginmap, 'ssh', fake)
    monkeypatch.setitem(core.pluginmap, 'notfortenants', fake)
    # the terminal buffer daemon, in memory
    buffers = {}

    async def send_output(name, output):
        buffers[name] = buffers.get(name, b'') + output

    async def get_buffer_output(name):
        return buffers.get(name, b'')
    monkeypatch.setattr(consoleserver, 'send_output', send_output)
    monkeypatch.setattr(consoleserver, 'get_buffer_output', get_buffer_output)
    monkeypatch.setattr(consoleserver, '_tracelog', log.Logger('trace'))
    monkeypatch.setattr(consoleserver, '_handled_consoles', {})
    monkeypatch.setattr(consoleserver, '_tenant_nodewatchers', {})
    monkeypatch.setattr(shellserver, 'activesessions', {})
    FakeConsole.made = []
    for tid, name in ((A, 'acme'), (B, 'globex')):
        configmanager._true_create_tenant(
            tid, name, configmanager._wrap_tenant_key(os.urandom(32)), 0)
        await configmanager.ConfigManager(tid).set_node_attributes(
            {'n1': {'console.method': 'ipmi'}}, autocreate=True)
    await configmanager.ConfigManager(None).set_node_attributes(
        {'n1': {'console.method': 'ipmi'}}, autocreate=True)
    yield buffers
    tenantnet.enter(None)


async def _session(tid, node='n1', kind=consoleserver.ConsoleSession):
    """A session as a request of tenant tid opens it; returns it and the
    list its output is appended to."""
    seen = []

    async def output(data):
        seen.append(data)
    tenantnet.enter(tid)
    try:
        session = await kind.create(node, configmanager.ConfigManager(tid),
                                    username='admin', datacallback=output)
    finally:
        tenantnet.enter(None)
    return session, seen


def _text(seen):
    return b''.join(d if isinstance(d, bytes) else d.encode()
                    for d in seen if isinstance(d, (bytes, str)))


def _console(tid):
    return [c for c in FakeConsole.made if c.tenant == tid][-1]


async def test_each_tenants_node_has_its_own_console(consoles):
    sessions = {}
    for tid in (A, B, None):
        sessions[tid] = await _session(tid)
    for tid in (A, B, None):
        await _until(lambda tid=tid: b'console of n1' in _text(sessions[tid][1]))
    for tid in (A, B, None):
        assert 'console of n1 in {0}'.format(tid).encode() in _text(sessions[tid][1])
    assert b'in ' + B.encode() not in _text(sessions[A][1])
    assert b'in ' + A.encode() not in _text(sessions[B][1])
    assert len({id(sessions[t][0].conshdl) for t in sessions}) == 3
    # what a tenant's user types goes to that tenant's console only
    await sessions[A][0].write(b'typed in a')
    assert _console(A).written == [b'typed in a']
    assert _console(B).written == [] and _console(None).written == []
    # separate terminal buffers, named by tenant
    assert set(consoles) == {'c_n1', A + '/c_n1', B + '/c_n1'}
    assert A.encode() in consoles[A + '/c_n1'] and A.encode() not in consoles[B + '/c_n1']
    # and separate console logs
    for tid in (A, B, None):
        sessions[tid][0].conshdl.logger.writedata()
    logdir = configmanager.get_global('logdirectory')
    for tid in (A, B):
        with open(os.path.join(logdir, 'tenants', tid, 'consoles', 'n1')) as f:
            text = f.read()
        assert 'console of n1 in ' + tid in text
        assert 'in ' + (B if tid == A else A) not in text
    with open(os.path.join(logdir, 'consoles', 'n1')) as f:
        assert A not in f.read()


async def test_consoles_connect_in_their_tenants_network(consoles):
    # started by the service itself (as at startup), outside any tenant
    for tid in (A, B):
        await consoleserver._start_tenant_sessions(configmanager.ConfigManager(tid))
    await _until(lambda: len(FakeConsole.made) == 2 and all(
        c.connected_as for c in FakeConsole.made))
    for console in FakeConsole.made:
        assert console.connected_as == [(console.tenant, console.tenant)]
    # a reconnect asked for from another context (a configuration change
    # replicated from another member, another tenant's request)
    handler = consoleserver._handled_consoles[('n1', A)]
    tenantnet.enter(B)
    handler._connect()
    tenantnet.enter(None)
    await _until(lambda: len([c for c in FakeConsole.made if c.tenant == A]) == 2
                 and _console(A).connected_as)
    assert _console(A).connected_as == [(A, A)]
    # the default tenant's consoles stay in the host's network
    await consoleserver.connect_node('n1', configmanager.ConfigManager(None))
    await _until(lambda: [c for c in FakeConsole.made if c.tenant is None]
                 and _console(None).connected_as)
    assert _console(None).connected_as == [(None, None)]


async def test_a_tenants_consoles_close_with_it(consoles):
    monkeypatch_started = consoleserver._started
    consoleserver._started = True
    try:
        for tid in (A, B):
            await consoleserver._start_tenant_sessions(configmanager.ConfigManager(tid))
        await _until(lambda: len(FakeConsole.made) == 2 and all(
            c.connected_as for c in FakeConsole.made))
        session, seen = await _session(A)
        await configmanager.set_tenant_state(A, 'disabled')
        await _until(lambda: _console(A).closed)
        assert ('n1', A) not in consoleserver._handled_consoles
        assert ('n1', B) in consoleserver._handled_consoles and not _console(B).closed
        assert {'deleting': True} in seen
        assert A not in consoleserver._tenant_nodewatchers
        # in use again: its consoles are started again
        made = len(FakeConsole.made)
        await configmanager.set_tenant_state(A, 'active')
        await _until(lambda: len(FakeConsole.made) > made and _console(A).connected_as)
        assert _console(A).connected_as == [(A, A)]
        # nodes added to a tenant get a console in that tenant
        await configmanager.ConfigManager(B).set_node_attributes(
            {'n2': {'console.method': 'ipmi'}}, autocreate=True)
        await _until(lambda: ('n2', B) in consoleserver._handled_consoles)
        assert ('n2', A) not in consoleserver._handled_consoles
        assert ('n2', None) not in consoleserver._handled_consoles
    finally:
        consoleserver._started = monkeypatch_started


async def test_shell_sessions_are_per_tenant(consoles):
    sessions = {tid: await _session(tid, kind=shellserver.ShellSession) for tid in (A, B)}
    for tid in (A, B):
        await _until(lambda tid=tid: b'console of n1' in _text(sessions[tid][1]))
        assert 'in {0}'.format(tid).encode() in _text(sessions[tid][1])
    assert set(shellserver.activesessions) == {(A, 'n1', 'admin'), (B, 'n1', 'admin')}
    assert shellserver.get_sessions(A, 'n1', 'admin').keys() != set()
    assert shellserver.get_sessions(None, 'n1', 'admin') == {}
    for console in FakeConsole.made:
        assert console.connected_as == [(console.tenant, console.tenant)]
    # terminal buffers of shells are named by tenant too
    assert all(name.startswith((A + '/s_', B + '/s_')) for name in consoles)
    await configmanager.set_tenant_state(A, 'disabled')
    await _until(lambda: _console(A).closed)
    assert set(shellserver.activesessions) == {(B, 'n1', 'admin')}
    assert not _console(B).closed


async def test_console_plugins_not_ported_are_refused(consoles):
    await configmanager.ConfigManager(A).set_node_attributes(
        {'n1': {'console.method': 'notfortenants'}})
    session, seen = await _session(A)
    await _until(lambda: any(isinstance(d, dict) and d.get('error') for d in seen))
    assert not [c for c in FakeConsole.made if c.tenant == A]
    assert b'not yet available within a tenant' in _text(seen)
    # the default tenant can use the same plugin
    await configmanager.ConfigManager(None).set_node_attributes(
        {'n1': {'console.method': 'notfortenants'}})
    session, seen = await _session(None)
    await _until(lambda: b'console of n1' in _text(seen))


async def test_a_tenant_reaches_only_its_own_nodes_consoles(consoles):
    await configmanager.ConfigManager(B).set_node_attributes(
        {'only-in-b': {'console.method': 'ipmi'}}, autocreate=True)
    with pytest.raises(exc.NotFoundException):
        await _session(A, node='only-in-b')
    session, seen = await _session(B, node='only-in-b')
    await _until(lambda: b'console of only-in-b' in _text(seen))


async def test_buffer_daemon_is_started_outside_any_tenant(consoles, monkeypatch):
    started = []

    async def daemon():
        started.append(tenantguard.current_tenant.get())

    async def no_connection():
        raise OSError('not running')
    monkeypatch.setattr(consoleserver, 'run_buffer_daemon', daemon)
    monkeypatch.setattr(consoleserver, 'get_buffer_connection', no_connection)
    monkeypatch.setattr(consoleserver, '_bufferdaemon', None)
    monkeypatch.setattr(consoleserver, '_bufferstartuplock', None)
    tenantnet.enter(A)
    with pytest.raises(OSError):
        await consoleserver._ensure_buffer_daemon()
    tenantnet.enter(None)
    assert started == [None]


# ------------------------------------------- within the tenant networks



@pytest.fixture
async def topo(netns, confluent_config, monkeypatch):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    if not core.pluginmap:
        core.load_plugins()
    buffers = {}

    async def send_output(name, output):
        buffers[name] = buffers.get(name, b'') + output

    async def get_buffer_output(name):
        return buffers.get(name, b'')
    monkeypatch.setattr(consoleserver, 'send_output', send_output)
    monkeypatch.setattr(consoleserver, 'get_buffer_output', get_buffer_output)
    monkeypatch.setattr(consoleserver, '_tracelog', log.Logger('trace'))
    monkeypatch.setattr(shellserver, 'activesessions', {})
    topology = Topology(netns)
    tenantguard.recent_violations.clear()
    for tid, (label, _) in TENANTS.items():
        configmanager._true_create_tenant(
            tid, label, configmanager._wrap_tenant_key(os.urandom(32)), 0)
        topology.network(tid)
        topology.start_ssh(tid)
        # every tenant has a node sw1, at the same address
        await configmanager.ConfigManager(tid).set_node_attributes({'sw1': {}}, autocreate=True)
    yield topology
    tenantnet.enter(None)
    assert list(tenantguard.recent_violations) == []
    topology.cleanup()


async def _say(tid, session, seen, text, expect):
    """Type text into a session as the tenant's user, and wait for expect."""
    tenantnet.enter(tid)  # as the user's next request
    try:
        await session.write(text)
    finally:
        tenantnet.enter(None)
    try:
        await _until(lambda: expect in _text(seen), timeout=20)
    except AssertionError:
        raise AssertionError(_text(seen)[-600:])


@pytest.mark.netns
async def test_shell_reaches_the_node_in_its_own_tenants_network(topo):
    hits = topo.decoy_hits()
    for tid, (label, _) in TENANTS.items():
        session, seen = await _session(tid, node='sw1', kind=shellserver.ShellSession)
        await _until(lambda seen=seen: b'login as: ' in _text(seen))
        await _say(tid, session, seen, BMC_USER.encode() + b'\r', b'Enter password: ')
        # logged on, the node says which tenant's network it is in
        await _say(tid, session, seen, BMC_PASSWORD.encode() + b'\r', label.encode())
        assert b'Connecting to sw1...Connected' in _text(seen)
        other = [name for name, _ in TENANTS.values() if name != label][0]
        assert other.encode() not in _text(seen)
    assert not configmanager.ConfigManager(None).is_node('sw1')
    assert topo.decoy_hits() == hits
