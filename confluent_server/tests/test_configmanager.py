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

import pytest

import confluent.config.configmanager as configmanager


async def _make_cluster(cfm):
    await cfm.add_group_attributes({'compute': {'console.method': 'ipmi'},
                                    'storage': {}})
    nodes = dict(('n%d' % i, {'groups': ['compute']}) for i in range(1, 4))
    nodes['s1'] = {'groups': ['storage'], 'net.ipv4_address': '10.0.0.10'}
    await cfm.set_node_attributes(nodes, autocreate=True)


def _value(cfm, node, attr):
    return cfm.get_node_attributes([node], [attr]).get(node, {}).get(attr, {}).get('value')


async def test_create_nodes_and_read_attributes(confluent_config):
    cfm = confluent_config.manager()
    await _make_cluster(cfm)
    assert sorted(cfm.list_nodes()) == ['n1', 'n2', 'n3', 's1']
    assert _value(cfm, 's1', 'net.ipv4_address') == '10.0.0.10'
    assert cfm.get_node_attributes(['s1'], ['groups'])['s1']['groups'] == ['storage', 'everything']


async def test_group_inheritance_and_node_override(confluent_config):
    cfm = confluent_config.manager()
    await _make_cluster(cfm)
    attr = cfm.get_node_attributes(['n1'], ['console.method'])['n1']['console.method']
    assert attr == {'value': 'ipmi', 'inheritedfrom': 'compute'}

    await cfm.set_node_attributes({'n1': {'console.method': 'tsmsol'}})
    await cfm.set_group_attributes({'compute': {'console.method': 'openbmc'}})
    assert _value(cfm, 'n1', 'console.method') == 'tsmsol'   # node value wins
    assert _value(cfm, 'n2', 'console.method') == 'openbmc'  # follows the group


async def test_delete_node(confluent_config):
    cfm = confluent_config.manager()
    await _make_cluster(cfm)
    await cfm.del_nodes(['n3'])
    assert sorted(cfm.list_nodes()) == ['n1', 'n2', 's1']
    assert 'n3' not in cfm.get_nodegroup_attributes('compute')['nodes']


async def test_main_store_survives_restart(confluent_config):
    cfm = confluent_config.manager()
    await _make_cluster(cfm)
    await cfm.create_user('alice', role='Operator')

    confluent_config.restart()

    cfm = confluent_config.manager()
    assert sorted(cfm.list_nodes()) == ['n1', 'n2', 'n3', 's1']
    assert _value(cfm, 's1', 'net.ipv4_address') == '10.0.0.10'
    assert _value(cfm, 'n2', 'console.method') == 'ipmi'
    assert cfm.get_user('alice')['role'] == 'Operator'


async def test_tenant_users_are_separate_in_memory(confluent_config):
    main = confluent_config.manager()
    await main.create_user('alice')
    tenant = confluent_config.manager('acme', create_tenant=True)
    await tenant.create_user('bob')

    assert configmanager.is_tenant('acme')
    assert tenant.get_user('bob') is not None
    assert tenant.get_user('alice') is None
    assert main.get_user('bob') is None


@pytest.mark.xfail(strict=True, raises=KeyError, reason=(
    "a new tenant's 'everything' group is created without a 'nodes' set "
    '(ConfigManager.__init__), so adding a node to a tenant raises KeyError; '
    'to be fixed by the tenant storage change'))
async def test_tenant_nodes_are_separate_in_memory(confluent_config):
    main = confluent_config.manager()
    await _make_cluster(main)
    tenant = confluent_config.manager('acme', create_tenant=True)
    await tenant.set_node_attributes({'n1': {'net.ipv4_address': '10.0.0.10'}}, autocreate=True)

    assert configmanager.is_tenant('acme')
    assert sorted(tenant.list_nodes()) == ['n1']
    assert _value(tenant, 'n1', 'net.ipv4_address') == '10.0.0.10'
    assert _value(main, 'n1', 'net.ipv4_address') is None


@pytest.mark.xfail(strict=True, reason=(
    'tenant stores are written to <cfgdir>/tenants/<tenant>/ but read back from '
    '<cfgdir>/<tenant>/ into the wrong key (ConfigManager._read_from_path), so '
    'they are lost on restart; to be fixed by the tenant storage change'))
async def test_tenant_store_survives_restart(confluent_config):
    tenant = confluent_config.manager('acme', create_tenant=True)
    await tenant.create_user('bob')

    confluent_config.restart()

    assert configmanager.is_tenant('acme')
    assert confluent_config.manager('acme').get_user('bob') is not None


async def test_restart_does_not_touch_other_directories(confluent_config, tmp_path):
    cfm = confluent_config.manager()
    await _make_cluster(cfm)
    confluent_config.flush()
    assert sorted(p.name for p in tmp_path.iterdir()) == ['cfg']
