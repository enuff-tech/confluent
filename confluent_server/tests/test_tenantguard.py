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

"""The fail-closed guard: in a tenant's context only sockets from that
tenant's broker may reach the network."""

import asyncio
import json
import os
import socket
import subprocess
import threading

import pytest

import confluent.apikey as apikey
import confluent.config.configmanager as configmanager
import confluent.tenantguard as tenantguard

Violation = tenantguard.TenantNetworkViolation
TENANT = 't0123456789ab'


@pytest.fixture(autouse=True)
def guard():
    tenantguard.install()
    yield
    tenantguard.current_tenant.set(None)


def _closed_port():
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _connect(sock, port):
    try:
        sock.connect(('127.0.0.1', port))
    except ConnectionRefusedError:
        return 'refused'  # reached the (closed) port: the network was used
    finally:
        sock.close()
    return 'connected'


def test_default_tenant_is_unaffected():
    assert _connect(socket.socket(), _closed_port()) == 'refused'
    assert socket.getaddrinfo('localhost', 80)
    assert subprocess.run(['true']).returncode == 0


@pytest.mark.parametrize('action', ['connect', 'bind', 'sendto', 'udp-connect'])
def test_unbrokered_sockets_are_refused_in_tenant_context(action):
    with tenantguard.tenant_context(TENANT):
        with pytest.raises(Violation):
            if action == 'connect':
                _connect(socket.socket(), _closed_port())
            elif action == 'bind':
                socket.socket().bind(('127.0.0.1', 0))
            elif action == 'sendto':
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('127.0.0.1', 9))
            else:
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM).connect(('127.0.0.1', 9))


def test_unix_sockets_are_refused_unless_registered(tmp_path):
    path = str(tmp_path / 'sock')
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)
    with tenantguard.tenant_context(TENANT):
        with pytest.raises(Violation):
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect(path)
        control = tenantguard.register_control(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        control.connect(path)
        control.close()
    server.close()


def test_only_the_tenants_own_brokered_sockets_pass():
    port = _closed_port()
    mine = tenantguard.register(TENANT, socket.socket())
    theirs = tenantguard.register('t999999999999', socket.socket())
    with tenantguard.tenant_context(TENANT):
        assert _connect(mine, port) == 'refused'
        with pytest.raises(Violation):
            _connect(theirs, port)


def test_name_lookups_and_processes_are_refused():
    with tenantguard.tenant_context(TENANT):
        assert socket.getaddrinfo('127.0.0.1', 80)  # a literal is not looked up
        assert socket.getaddrinfo('::1', 80)
        for name in ('localhost', 'bmc1.example.com'):
            with pytest.raises(Violation):
                socket.getaddrinfo(name, 80)
        with pytest.raises(Violation):
            socket.gethostbyname('localhost')
        with pytest.raises(Violation):
            subprocess.run(['true'])
        with pytest.raises(Violation):
            os.system('true')


async def test_context_follows_tasks_and_executor_threads():
    loop = asyncio.get_running_loop()
    tenantguard.install(loop)
    port = _closed_port()
    with tenantguard.tenant_context(TENANT):
        child = asyncio.ensure_future(asyncio.sleep(0, result=tenantguard.current_tenant.get()))
        assert await child == TENANT
        with pytest.raises(Violation):
            await loop.run_in_executor(None, _connect, socket.socket(), port)
        with pytest.raises(Violation):
            await asyncio.to_thread(_connect, socket.socket(), port)
        with pytest.raises(Violation):
            await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), 5)
        with pytest.raises(Violation):
            await loop.getaddrinfo('localhost', 80)
    # outside the context everything works as before
    assert await loop.run_in_executor(None, _connect, socket.socket(), port) == 'refused'


def test_plain_threads_are_outside_tenant_context():
    # Background threads (such as the configuration writer) are service
    # work, never tenant work.
    seen = []
    with tenantguard.tenant_context(TENANT):
        thread = threading.Thread(target=lambda: seen.append(tenantguard.current_tenant.get()))
        thread.start()
        thread.join()
    assert seen == [None]


def test_enter_applies_to_the_rest_of_the_task():
    tenantguard.enter(TENANT)
    assert tenantguard.current_tenant.get() == TENANT
    tenantguard.enter(None)
    assert _connect(socket.socket(), _closed_port()) == 'refused'


async def test_configuration_work_of_a_tenant_passes_the_guard(confluent_config):
    """Everything tenant principals may do today is configuration only and
    must work with the guard in place."""
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    tid = await configmanager.create_tenant('acme')
    with tenantguard.tenant_context(tid):
        cfm = configmanager.ConfigManager(tid)
        await cfm.add_group_attributes({'compute': {'console.method': 'ipmi'}})
        await cfm.set_node_attributes({'c1': {
            'groups': ['compute'], 'net.ipv4_address': '10.241.34.2',
            'hardwaremanagement.manager': '10.241.35.2',
            'secret.hardwaremanagementpassword': 'pw'}}, autocreate=True)
        await cfm.create_user('admin', attributemap={'password': 'a long password'})
        status, data = await apikey.handle_v2_request(
            '/sessions/current/apikeys', 'admin', cfm,
            json.dumps({'expiration': 1}).encode(), 'create')
        assert status == 200
        assert apikey.validate_bearer(data['token'])['tenant'] == tid
        await cfm.del_nodes(['c1'])
    confluent_config.flush()
