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

"""Checks for the namespace test helpers themselves.

Two "sites" are built with identical addressing (same CIDR, same interface
names, same MACs) to confirm the helpers can model overlapping networks.
"""

import pytest

pytestmark = pytest.mark.netns


def _build_site(netns):
    mgmt = netns.create()
    lan = netns.create()
    netns.veth(mgmt, 'up0', '10.241.34.1/24', lan, 'hw0', '10.241.34.2/24',
               mac_a='02:00:00:aa:34:01', mac_b='02:00:00:aa:34:02')
    return mgmt, lan


def test_identical_sites_are_independent(netns):
    a_mgmt, a_lan = _build_site(netns)
    b_mgmt, b_lan = _build_site(netns)
    assert netns.inode(a_mgmt) != netns.inode(b_mgmt)

    for mgmt in (a_mgmt, b_mgmt):
        netns.run(mgmt, 'ping', '-c', '1', '-W', '2', '10.241.34.2')
        addrs = netns.run(mgmt, 'ip', '-4', '-o', 'addr', 'show', 'dev', 'up0').stdout
        assert '10.241.34.1/24' in addrs

    # Taking one site's link down must not affect the other.
    netns.run(a_mgmt, 'ip', 'link', 'set', 'up0', 'down')
    assert netns.run(a_mgmt, 'ping', '-c', '1', '-W', '1', '10.241.34.2', check=False).returncode != 0
    netns.run(b_mgmt, 'ping', '-c', '1', '-W', '2', '10.241.34.2')


def test_cleanup_removes_only_own_namespaces(netns):
    import subprocess
    import netnsutil
    other = netnsutil.NetnsFactory()
    keep = other.create()
    try:
        mine = netns.create()
        netns.cleanup()
        listing = subprocess.run(['ip', 'netns', 'list'], capture_output=True, text=True).stdout
        assert mine not in listing
        assert keep in listing
    finally:
        other.cleanup()
