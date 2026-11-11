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

import confluent.noderange as noderange


@pytest.fixture
async def cluster(confluent_config):
    cfm = confluent_config.manager()
    await cfm.add_group_attributes({'compute': {'console.method': 'ipmi'}, 'storage': {}})
    nodes = dict(('n%d' % i, {'groups': ['compute']}) for i in range(1, 6))
    nodes['s1'] = {'groups': ['storage']}
    await cfm.set_node_attributes(nodes, autocreate=True)
    return cfm


@pytest.mark.parametrize('expression,expected', [
    ('n1-n3', ['n1', 'n2', 'n3']),
    ('n[1:3]', ['n1', 'n2', 'n3']),
    ('n1,n4', ['n1', 'n4']),
    ('compute', ['n1', 'n2', 'n3', 'n4', 'n5']),
    ('compute,storage', ['n1', 'n2', 'n3', 'n4', 'n5', 's1']),
    ('compute@n1-n2', ['n1', 'n2']),
    ('n1-n3,-n2', ['n1', 'n3']),
    ('console.method=ipmi', ['n1', 'n2', 'n3', 'n4', 'n5']),
    ('everything', ['n1', 'n2', 'n3', 'n4', 'n5', 's1']),
])
async def test_noderange_expressions(cluster, expression, expected):
    assert sorted(noderange.NodeRange(expression, cluster).nodes) == expected
