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

"""Transports that cannot or need not reach a tenant network, unprivileged."""

import pytest

import confluent.snmputil as snmputil
import confluent.sshclient as sshclient
import confluent.tenantnet as tenantnet

TENANT = 't0123456789ab'


@pytest.fixture
def in_tenant():
    tenantnet.enter(TENANT)
    yield
    tenantnet.enter(None)


async def test_snmp_is_refused_for_tenants(in_tenant):
    with pytest.raises(tenantnet.TenantNetworkUnsupported):
        await snmputil._get_transport('10.241.34.2')


async def test_snmp_still_works_without_a_tenant():
    transport = await snmputil._get_transport('127.0.0.1')
    assert transport is not None


def test_refusal_helper(in_tenant):
    with pytest.raises(tenantnet.TenantNetworkUnsupported, match='Widgets'):
        tenantnet.refuse_for_tenant('Widgets')


def test_refusal_helper_without_a_tenant():
    tenantnet.refuse_for_tenant('Widgets')


def test_default_tenant_helpers_leave_the_host_path_alone():
    assert tenantnet.current_network() is None
    assert tenantnet.connect_blocking('127.0.0.1', 1) is None
    assert tenantnet.aiohttp_connector() is None


class _Cfg(object):
    def __init__(self, tenant):
        self.tenant = tenant


def test_tenants_do_not_trust_the_hosts_ssh_ca(monkeypatch):
    client = sshclient._MyClient()
    client.set_configmanager(_Cfg(TENANT))

    def no_file(*args, **kwargs):
        raise AssertionError('the host CA file must not be consulted for tenants')
    monkeypatch.setattr('builtins.open', no_file)
    assert client.validate_host_ca_key('c1', '10.241.34.2', 22, object()) is False


def test_tenant_ssh_connect_is_deferred_to_the_tenant_network(in_tenant):
    pending = sshclient.connect('10.241.34.2', username='admin', password='x')
    assert isinstance(pending, sshclient._TenantConnect)
    assert pending.port == 22
