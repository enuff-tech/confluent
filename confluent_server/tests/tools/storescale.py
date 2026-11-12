#!/usr/bin/env python3
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
"""Measure the configuration store of confluent at a given number of tenants
and nodes: memory, time to define, time until changes are on disk, restart.

  storescale.py populate --dir D --tenants T --nodes N
  storescale.py churn    --dir D [--changes C] [--burst B]
  storescale.py load     --dir D
  storescale.py fsync    --dir D

Each prints one JSON object. Run each as its own process: the memory
reported is that of the process (peak and current resident set).

It uses the source tree it is in, and only ever writes under --dir: it can
be run on a host that has a confluent of its own. See tests/README.md.
"""
import argparse
import asyncio
import json
import os
import random
import resource
import sys
import time

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))


def _paths(repo):
    server = os.path.join(repo, 'confluent_server')
    for path in (server, os.path.join(repo, 'confluent_client')):
        if path not in sys.path:
            sys.path.insert(0, path)


def _rss():
    with open('/proc/self/status') as status:
        for line in status:
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) // 1024
    return 0


def _peak():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024


def _disk(directory):
    files = 0
    size = 0
    for root, _, names in os.walk(directory):
        for name in names:
            files += 1
            size += os.path.getsize(os.path.join(root, name))
    return files, size // (1024 * 1024)


def _node(tenantindex, index):
    """What a deployed, managed node carries (about twenty attributes)."""
    octets = (index >> 8) & 255, index & 255
    return {
        'groups': ['compute', 'rack{0}'.format(index // 40)],
        'hardwaremanagement.manager': '10.{0}.{1}.{2}'.format(100 + tenantindex % 100, *octets),
        'hardwaremanagement.method': 'ipmi',
        'secret.hardwaremanagementuser': 'admin',
        'secret.hardwaremanagementpassword': 'bmc-password-{0}'.format(index),
        'console.method': 'ipmi',
        'console.logging': 'full',
        'net.hwaddr': '02:{0:02x}:{1:02x}:00:{2:02x}:{3:02x}'.format(
            tenantindex >> 8, tenantindex & 255, *octets),
        'net.ipv4_address': '10.{0}.{1}.{2}/16'.format(tenantindex % 100, *octets),
        'net.ipv4_method': 'static',
        'net.ipv4_gateway': '10.{0}.0.1'.format(tenantindex % 100),
        'net.bmc.hwaddr': '02:{0:02x}:{1:02x}:01:{2:02x}:{3:02x}'.format(
            tenantindex >> 8, tenantindex & 255, *octets),
        'id.uuid': '{0:08x}-0000-4000-8000-{1:012x}'.format(tenantindex, index),
        'id.serial': 'SN{0:04d}{1:06d}'.format(tenantindex, index),
        'id.model': '7D76CTO1WW',
        'location.rack': 'r{0}'.format(index // 40),
        'location.u': str(index % 40 + 1),
        'deployment.profile': 'rhel-9.4-x86_64-default',
        'deployment.apiarmed': '',
        'discovery.policy': 'permissive',
        'crypted.rootpassword': {'hashvalue': '$5$rounds=535000$abcdefghijklmnop$' + 'h' * 43},
    }


async def populate(args):
    import confluent.config.configmanager as cm
    cm.init(cfgdir=os.path.join(args.dir, 'cfg'))
    cm.init_masterkey()
    cm.set_global('multitenancy.enabled', True)
    cm._ready = True
    started = time.time()
    define = 0.0
    flush = []
    samples = []
    for t in range(args.tenants):
        tid = await cm.create_tenant('tenant{0:04d}'.format(t))
        cfm = cm.ConfigManager(tid)
        begun = time.time()
        groups = {'compute': {'console.method': 'ipmi'}}
        for rack in range((args.nodes - 1) // 40 + 1):
            groups['rack{0}'.format(rack)] = {'location.row': 'a'}
        await cfm.add_group_attributes(groups)
        for first in range(0, args.nodes, 500):
            await cfm.set_node_attributes(dict(
                ('n{0:05d}'.format(i), _node(t, i))
                for i in range(first, min(first + 500, args.nodes))), autocreate=True)
        await cfm.create_user('admin', role='Administrator')
        define += time.time() - begun
        begun = time.time()
        cm.ConfigManager.wait_for_sync()
        flush.append(time.time() - begun)
        if t % max(1, args.tenants // 10) == 0:
            samples.append({'tenants': t + 1, 'rss_mb': _rss(),
                            'elapsed_s': round(time.time() - started, 1)})
    files, size = _disk(args.dir)
    flush.sort()
    return {
        'phase': 'populate', 'tenants': args.tenants, 'nodes_each': args.nodes,
        'nodes': args.tenants * args.nodes,
        'define_s': round(define, 1),
        'define_nodes_per_s': round(args.tenants * args.nodes / define),
        'flush_per_tenant_s': {'median': round(flush[len(flush) // 2], 3),
                               'max': round(flush[-1], 3), 'sum': round(sum(flush), 1)},
        'total_s': round(time.time() - started, 1),
        'rss_mb': _rss(), 'peak_rss_mb': _peak(),
        'files': files, 'disk_mb': size, 'growth': samples,
    }


def _open(args):
    import confluent.config.configmanager as cm
    begun = time.time()
    cm.init(cfgdir=os.path.join(args.dir, 'cfg'))
    cm.init_masterkey()
    return cm, time.time() - begun


async def load(args):
    cm, took = _open(args)
    tenants = cm.list_tenants()
    cfm = cm.ConfigManager(tenants[len(tenants) // 2])
    begun = time.time()
    nodes = list(cfm.list_nodes())
    attrs = cfm.get_node_attributes(nodes, ('net.*', 'hardwaremanagement.*'))
    read = time.time() - begun
    begun = time.time()
    secret = cfm.get_node_attributes(nodes[:200], 'secret.*', decrypt=True)
    decrypt = time.time() - begun
    return {'phase': 'load', 'tenants': len(tenants), 'load_s': round(took, 1),
            'rss_mb': _rss(), 'peak_rss_mb': _peak(),
            'read_one_tenant_s': round(read, 3), 'nodes_read': len(attrs),
            'decrypt_200_nodes_s': round(decrypt, 3), 'decrypted': len(secret)}


async def churn(args):
    """Changes as a running service makes them: one node of one tenant at a
    time (a deployment moving on), each on disk before the next; then the
    same number at once (a tenant redeploying a rack), written together."""
    cm, took = _open(args)
    cm._ready = True
    rnd = random.Random(1)
    tenants = cm.list_tenants()
    managers = {}

    def pick():
        tid = rnd.choice(tenants)
        if tid not in managers:
            managers[tid] = (cm.ConfigManager(tid), None)
            managers[tid] = (managers[tid][0], list(managers[tid][0].list_nodes()))
        cfm, nodes = managers[tid]
        return cfm, rnd.choice(nodes)

    cm.ConfigManager.wait_for_sync()
    each = []
    for n in range(args.changes):
        cfm, node = pick()
        begun = time.time()
        await cfm.set_node_attributes({node: {
            'deployment.pendingprofile': 'rhel-9.4-x86_64-default',
            'deployment.stagedprofile': '', 'deployment.state': 'run {0}'.format(n)}})
        cm.ConfigManager.wait_for_sync()
        each.append(time.time() - begun)
    each.sort()
    # a burst: one tenant changes many of its nodes
    cfm, _ = pick()
    nodes = list(cfm.list_nodes())[:args.burst]
    begun = time.time()
    await cfm.set_node_attributes(dict(
        (node, {'deployment.pendingprofile': 'ubuntu-24.04-x86_64-default',
                'deployment.state': 'burst'}) for node in nodes))
    inmemory = time.time() - begun
    cm.ConfigManager.wait_for_sync()
    burst = time.time() - begun
    # many tenants change a few nodes each at the same moment
    begun = time.time()
    touched = set()
    for n in range(args.changes):
        cfm, node = pick()
        touched.add(cfm.tenant)
        await cfm.set_node_attributes({node: {'deployment.state': 'spread {0}'.format(n)}})
    cm.ConfigManager.wait_for_sync()
    spread = time.time() - begun
    return {
        'phase': 'churn', 'load_s': round(took, 1),
        'single_change_durable_ms': {
            'median': round(each[len(each) // 2] * 1000, 1),
            'p95': round(each[int(len(each) * 0.95)] * 1000, 1),
            'max': round(each[-1] * 1000, 1)},
        'single_changes_per_s': round(len(each) / sum(each), 1),
        'burst_nodes': len(nodes), 'burst_in_memory_s': round(inmemory, 3),
        'burst_durable_s': round(burst, 3),
        'burst_nodes_per_s': round(len(nodes) / burst),
        'spread_changes': args.changes, 'spread_tenants': len(touched),
        'spread_durable_s': round(spread, 3),
        'spread_changes_per_s': round(args.changes / spread),
        'rss_mb': _rss(),
    }


async def fsync(args):
    """What the disk under --dir takes to make one small write durable."""
    import dbm
    os.makedirs(args.dir, exist_ok=True)
    path = os.path.join(args.dir, 'fsync-probe')
    took = []
    with open(path, 'wb') as probe:
        for _ in range(200):
            begun = time.time()
            probe.write(b'x' * 512)
            probe.flush()
            os.fsync(probe.fileno())
            took.append(time.time() - begun)
    os.remove(path)
    took.sort()
    # and one key through dbm, as the store writes it
    dbpath = os.path.join(args.dir, 'dbm-probe')
    keys = []
    db = dbm.open(dbpath, 'c', 384)
    for n in range(200):
        begun = time.time()
        db['k{0}'.format(n)] = b'v' * 700
        keys.append(time.time() - begun)
    db.close()
    backend = dbm.whichdb(dbpath)
    for name in os.listdir(args.dir):
        if name.startswith('dbm-probe'):
            os.remove(os.path.join(args.dir, name))
    keys.sort()
    return {'phase': 'fsync', 'python': sys.version.split()[0], 'dbm': backend,
            'fsync_ms': {'median': round(took[100] * 1000, 3), 'p95': round(took[190] * 1000, 3)},
            'dbm_key_ms': {'median': round(keys[100] * 1000, 3), 'p95': round(keys[190] * 1000, 3)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('phase', choices=('populate', 'churn', 'load', 'fsync'))
    parser.add_argument('--dir', required=True)
    parser.add_argument('--repo', default=_REPO,
                        help='source tree to measure (default: the one this file is in)')
    parser.add_argument('--tenants', type=int, default=10)
    parser.add_argument('--nodes', type=int, default=100)
    parser.add_argument('--changes', type=int, default=200)
    parser.add_argument('--burst', type=int, default=1000)
    args = parser.parse_args()
    _paths(os.path.abspath(args.repo))
    if args.phase != 'fsync':
        # the name of this host is otherwise read from, and if missing
        # written to, /etc/confluent/cfg/myname whatever --dir says
        import confluent.config.configmanager as cm
        cm.mycachedname[:] = ['scalehost', float('inf')]
    result =asyncio.run(globals()[args.phase](args))
    if args.phase != 'fsync':
        import confluent.config.configmanager as cm
        cm.ConfigManager.wait_for_sync()
    print(json.dumps(result))


if __name__ == '__main__':
    main()
