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

"""confluent-netns: namespace, broker account and uplinks of a tenant."""

import os
import pwd
import stat
import subprocess
import uuid

import pytest

import confluent.netnstool as netnstool

pytestmark = pytest.mark.netns


def _ip(*args):
    return subprocess.run(('ip',) + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True)


def _host_links():
    return netnstool._links_in()


@pytest.fixture
def tool(tmp_path, monkeypatch):
    for key in ('etc', 'run', 'resolv'):
        monkeypatch.setitem(netnstool.paths, key, str(tmp_path / key))
    monkeypatch.setattr(netnstool, 'SERVICE_GROUP', 'root')
    tenants = []
    devices = []

    class Tool(object):
        def tenant(self):
            tid = 't' + uuid.uuid4().hex[:12]
            tenants.append(tid)
            return tid

        def dummy(self):
            name = 'cfd' + uuid.uuid4().hex[:6]
            assert _ip('link', 'add', name, 'type', 'dummy').returncode == 0
            devices.append(name)
            return name
    yield Tool()
    for tid in tenants:
        netnstool.teardown(tid, purge=True)
    for name in devices:
        _ip('link', 'del', name)


def test_setup_is_repeatable(tool):
    tid = tool.tenant()
    netnstool.setup(tid)
    netnstool.setup(tid)
    assert netnstool.namespace_exists(tid)
    account = pwd.getpwnam('cfnsb-' + tid)
    rundir = os.path.join(netnstool.paths['run'], tid)
    info = os.stat(rundir)
    assert info.st_uid == account.pw_uid
    assert stat.S_IMODE(info.st_mode) == 0o2750
    state = netnstool.status(tid)
    assert state['namespace_exists'] and state['uplinks'] == []


def test_attach_and_detach_physical_uplink(tool):
    tid = tool.tenant()
    device = tool.dummy()
    netnstool.setup(tid)
    netnstool.attach(tid, device)
    assert device not in _host_links()
    assert device in netnstool._links_in(netnstool.netns_name(tid))
    assert netnstool.status(tid)['uplinks'] == [{'name': device, 'attached': True}]
    netnstool.detach(tid, device)
    assert device in _host_links()
    assert netnstool.load_config(tid)['uplinks'] == []


def test_vlan_uplink_is_created_and_removed(tool):
    tid = tool.tenant()
    parent = tool.dummy()
    netnstool.setup(tid)
    netnstool.attach(tid, parent, vlan=100)
    name = parent + '.100'
    assert name in netnstool._links_in(netnstool.netns_name(tid))
    assert parent in _host_links() and name not in _host_links()
    netnstool.detach(tid, name)
    assert name not in netnstool._links_in(netnstool.netns_name(tid))
    assert name not in _host_links()


def test_declared_uplinks_come_back_after_reboot(tool):
    # A reboot loses namespaces; setup from the declaration rebuilds them.
    tid = tool.tenant()
    device = tool.dummy()
    netnstool.setup(tid)
    netnstool.attach(tid, device)
    # As after a reboot: the interface is back on the host (a physical one
    # returns there when its namespace goes; a dummy would be destroyed, so
    # it is moved back first) and the namespace is gone.
    _ip('-n', netnstool.netns_name(tid), 'link', 'set', device, 'netns', '1')
    _ip('netns', 'del', netnstool.netns_name(tid))
    assert device in _host_links()
    netnstool.setup(tid)
    assert device in netnstool._links_in(netnstool.netns_name(tid))


def test_teardown_returns_physical_uplinks_and_purges(tool):
    tid = tool.tenant()
    other = tool.tenant()
    device = tool.dummy()
    netnstool.setup(tid)
    netnstool.setup(other)
    netnstool.attach(tid, device)
    netnstool.teardown(tid, purge=True)
    assert device in _host_links()
    assert not netnstool.namespace_exists(tid)
    assert not os.path.exists(os.path.join(netnstool.paths['run'], tid))
    with pytest.raises(KeyError):
        pwd.getpwnam('cfnsb-' + tid)
    # the other tenant is untouched
    assert netnstool.namespace_exists(other)
    assert os.path.isdir(os.path.join(netnstool.paths['run'], other))


def test_teardown_does_not_follow_symlinks(tool, tmp_path):
    tid = tool.tenant()
    outside = tmp_path / 'precious'
    outside.mkdir()
    (outside / 'data').write_text('keep')
    os.makedirs(netnstool.paths['run'])
    os.symlink(str(outside), os.path.join(netnstool.paths['run'], tid))
    netnstool.teardown(tid)
    assert (outside / 'data').read_text() == 'keep'


@pytest.mark.parametrize('tid', ['', 'acme', '../x', 't0123', 'T0123456789AB', 't0123456789ab/x'])
def test_invalid_tenant_ids_are_refused(tool, tid):
    with pytest.raises(netnstool.NetnsError):
        netnstool.setup(tid)


@pytest.mark.parametrize('uplink', [
    {'device': '../eth0'}, {'device': 'eth0', 'vlan': 0}, {'device': 'eth0', 'vlan': 4095},
    {'device': 'eth0', 'vlan': '100'}, {'device': 'eth0', 'mtu': 9000},
    {'device': 'averylongname0', 'vlan': 100}, 'eth0',
])
def test_invalid_uplinks_are_refused(uplink):
    with pytest.raises(netnstool.NetnsError):
        netnstool._check_uplink(uplink)


def test_attaching_a_missing_device_fails(tool):
    tid = tool.tenant()
    netnstool.setup(tid)
    with pytest.raises(netnstool.NetnsError):
        netnstool.attach(tid, 'cfdmissing0')


def test_command_line(tool, capsys):
    tid = tool.tenant()
    assert netnstool.main(['setup', tid]) == 0
    assert netnstool.main(['status', tid]) == 0
    assert 'namespace_exists: True' in capsys.readouterr().out
    assert netnstool.main(['detach', tid, 'nope0']) == 1
    assert netnstool.main(['teardown', tid, '--purge']) == 0
