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

"""Host plumbing of tenant networks (confluent-netns, run as root).

This is the one part of a tenant's networking that belongs to the
platform: creating the tenant's network namespace and its broker account,
and handing uplinks (a physical interface or a VLAN of one) to it. Which
uplinks a tenant has is declared in /etc/confluent/netns/<id>.yaml:

    uplinks:
      - device: eth2          # moved into the namespace as is
      - device: eth1          # VLAN 100 of eth1, created as eth1.100
        vlan: 100

Everything inside the namespace (addresses, routes, discovery) is the
tenant's own business and is not configured here.

Every name used (namespace cf-<id>, user cfnsb-<id>, directories) is
derived from the validated tenant id, and nothing else is ever removed.
"""

import argparse
import grp
import os
import pwd
import re
import shutil
import subprocess
import sys

import yaml

TENANT_ID_RE = re.compile(r'^t[0-9a-f]{12}$')
DEVICE_RE = re.compile(r'^[A-Za-z0-9_-][A-Za-z0-9_.:-]{0,14}$')
SERVICE_GROUP = 'confluent'

paths = {
    'etc': '/etc/confluent/netns',
    'run': '/run/confluent/ns',
    'netns': '/run/netns',
    'resolv': '/etc/netns',
}


class NetnsError(Exception):
    pass


def _check_id(tenantid):
    if not isinstance(tenantid, str) or not TENANT_ID_RE.match(tenantid):
        raise NetnsError('invalid tenant id: {0!r}'.format(tenantid))
    return tenantid


def netns_name(tenantid):
    return 'cf-' + _check_id(tenantid)


def broker_user(tenantid):
    return 'cfnsb-' + _check_id(tenantid)


def _run(*cmd, **kwargs):
    kwargs.setdefault('check', True)
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, **kwargs)
    except subprocess.CalledProcessError as e:
        raise NetnsError('{0} failed: {1}'.format(' '.join(cmd), e.stderr.strip()))


def _config_path(tenantid):
    return os.path.join(paths['etc'], _check_id(tenantid) + '.yaml')


def load_config(tenantid):
    try:
        with open(_config_path(tenantid)) as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        config = {}
    uplinks = config.get('uplinks', []) or []
    if not isinstance(uplinks, list):
        raise NetnsError('uplinks must be a list')
    checked = []
    for uplink in uplinks:
        checked.append(_check_uplink(uplink))
    return {'uplinks': checked}


def _check_uplink(uplink):
    if not isinstance(uplink, dict) or set(uplink) - {'device', 'vlan'}:
        raise NetnsError('an uplink has a device and optionally a vlan')
    device = uplink.get('device')
    if not isinstance(device, str) or not DEVICE_RE.match(device):
        raise NetnsError('invalid device name: {0!r}'.format(device))
    checked = {'device': device}
    if 'vlan' in uplink:
        vlan = uplink['vlan']
        if isinstance(vlan, bool) or not isinstance(vlan, int) or not 1 <= vlan <= 4094:
            raise NetnsError('vlan must be 1-4094')
        checked['vlan'] = vlan
        if len(uplink_name(checked)) > 15:
            raise NetnsError('VLAN interface name {0} is too long'.format(uplink_name(checked)))
    return checked


def uplink_name(uplink):
    if 'vlan' in uplink:
        return '{0}.{1}'.format(uplink['device'], uplink['vlan'])
    return uplink['device']


def save_config(tenantid, config):
    os.makedirs(paths['etc'], mode=0o755, exist_ok=True)
    tmp = _config_path(tenantid) + '.tmp'
    with open(tmp, 'w') as f:
        yaml.safe_dump({'uplinks': config['uplinks']}, f, default_flow_style=False)
    os.rename(tmp, _config_path(tenantid))


def namespace_exists(tenantid):
    return os.path.exists(os.path.join(paths['netns'], netns_name(tenantid)))


def _links_in(namespace=None):
    cmd = ['ip']
    if namespace:
        cmd += ['-n', namespace]
    out = _run(*(cmd + ['-o', 'link', 'show'])).stdout
    names = set()
    for line in out.splitlines():
        parts = line.split(':', 2)
        if len(parts) > 1:
            names.add(parts[1].strip().split('@', 1)[0])
    return names


def ensure_user(tenantid):
    user = broker_user(tenantid)
    try:
        pwd.getpwnam(user)
    except KeyError:
        _run('useradd', '--system', '--no-create-home', '--user-group',
             '--shell', '/sbin/nologin', '--comment',
             'confluent network broker for tenant ' + tenantid, user)
    return pwd.getpwnam(user)


def setup(tenantid):
    """Create (or complete) the tenant's namespace, broker account, broker
    directory and uplinks. Safe to repeat."""
    namespace = netns_name(tenantid)
    account = ensure_user(tenantid)
    if not namespace_exists(tenantid):
        _run('ip', 'netns', 'add', namespace)
    _run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
    os.makedirs(paths['run'], mode=0o755, exist_ok=True)
    rundir = os.path.join(paths['run'], tenantid)
    os.makedirs(rundir, exist_ok=True)
    # Owned by the broker, setgid to the service group: the broker's 0660
    # socket is reachable by the service and nobody else.
    os.chown(rundir, account.pw_uid, grp.getgrnam(SERVICE_GROUP).gr_gid)
    os.chmod(rundir, 0o2750)
    os.makedirs(os.path.join(paths['resolv'], namespace), mode=0o755, exist_ok=True)
    for uplink in load_config(tenantid)['uplinks']:
        attach_uplink(tenantid, uplink)


def attach_uplink(tenantid, uplink):
    namespace = netns_name(tenantid)
    name = uplink_name(uplink)
    if name in _links_in(namespace):
        _run('ip', '-n', namespace, 'link', 'set', name, 'up')
        return False
    host = _links_in()
    if uplink['device'] not in host:
        raise NetnsError('device {0} is not on the host'.format(uplink['device']))
    if 'vlan' in uplink:
        # A VLAN only carries traffic while the host interface under it is up.
        _run('ip', 'link', 'set', uplink['device'], 'up')
        if name not in host:
            _run('ip', 'link', 'add', 'link', uplink['device'], 'name', name,
                 'type', 'vlan', 'id', str(uplink['vlan']))
    _run('ip', 'link', 'set', name, 'netns', namespace)
    _run('ip', '-n', namespace, 'link', 'set', name, 'up')
    return True


def detach_uplink(tenantid, uplink):
    namespace = netns_name(tenantid)
    name = uplink_name(uplink)
    if not namespace_exists(tenantid) or name not in _links_in(namespace):
        return False
    if 'vlan' in uplink:
        _run('ip', '-n', namespace, 'link', 'del', name)
    else:
        _run('ip', '-n', namespace, 'link', 'set', name, 'netns', '1')
    return True


def attach(tenantid, device, vlan=None):
    uplink = {'device': device}
    if vlan is not None:
        uplink['vlan'] = vlan
    uplink = _check_uplink(uplink)
    config = load_config(tenantid)
    if uplink not in config['uplinks']:
        config['uplinks'].append(uplink)
        save_config(tenantid, config)
    if namespace_exists(tenantid):
        attach_uplink(tenantid, uplink)
    return uplink


def detach(tenantid, name):
    config = load_config(tenantid)
    for uplink in config['uplinks']:
        if uplink_name(uplink) == name:
            detach_uplink(tenantid, uplink)
            config['uplinks'].remove(uplink)
            save_config(tenantid, config)
            return uplink
    raise NetnsError('tenant {0} has no uplink {1}'.format(tenantid, name))


def teardown(tenantid, purge=False):
    """Remove the namespace (physical uplinks return to the host, VLAN
    interfaces disappear) and the broker directory; with purge also the
    uplink declaration and the broker account."""
    namespace = netns_name(tenantid)
    if namespace_exists(tenantid):
        for uplink in load_config(tenantid)['uplinks']:
            detach_uplink(tenantid, uplink)
        _run('ip', 'netns', 'del', namespace)
    _remove_dir(paths['run'], tenantid)
    if purge:
        _remove_dir(paths['resolv'], namespace)
        try:
            os.unlink(_config_path(tenantid))
        except FileNotFoundError:
            pass
        try:
            pwd.getpwnam(broker_user(tenantid))
            _run('userdel', broker_user(tenantid))
        except KeyError:
            pass


def _remove_dir(root, name):
    """Remove root/name if it is a real directory directly under root."""
    root = os.path.realpath(root)
    target = os.path.join(root, name)
    if os.path.islink(target) or not os.path.isdir(target):
        return
    if os.path.dirname(os.path.realpath(target)) != root:
        return
    shutil.rmtree(target)


def status(tenantid):
    namespace = netns_name(tenantid)
    exists = namespace_exists(tenantid)
    present = _links_in(namespace) if exists else set()
    return {
        'tenant': tenantid,
        'namespace': namespace,
        'namespace_exists': exists,
        'broker_socket': os.path.exists(os.path.join(paths['run'], tenantid, 'broker.sock')),
        'uplinks': [{'name': uplink_name(u), 'attached': uplink_name(u) in present}
                    for u in load_config(tenantid)['uplinks']],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='confluent-netns',
        description='Manage the network namespaces of confluent tenants (root only)')
    sub = parser.add_subparsers(dest='command')
    for name in ('setup', 'status'):
        sub.add_parser(name).add_argument('tenant')
    down = sub.add_parser('teardown')
    down.add_argument('tenant')
    down.add_argument('--purge', action='store_true',
                      help='also remove the uplink declaration and broker account')
    att = sub.add_parser('attach')
    att.add_argument('tenant')
    att.add_argument('device')
    att.add_argument('--vlan', type=int)
    det = sub.add_parser('detach')
    det.add_argument('tenant')
    det.add_argument('name', help='device, or device.vlan')
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    if os.geteuid() != 0:
        sys.stderr.write('confluent-netns must run as root\n')
        return 1
    try:
        if args.command == 'setup':
            setup(args.tenant)
        elif args.command == 'teardown':
            teardown(args.tenant, args.purge)
        elif args.command == 'attach':
            print('attached {0}'.format(uplink_name(attach(args.tenant, args.device, args.vlan))))
        elif args.command == 'detach':
            print('detached {0}'.format(uplink_name(detach(args.tenant, args.name))))
        elif args.command == 'status':
            for key, value in sorted(status(args.tenant).items()):
                print('{0}: {1}'.format(key, value))
    except NetnsError as e:
        sys.stderr.write('{0}\n'.format(e))
        return 1
    return 0
