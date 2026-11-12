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

import dbm
import os
import pickle

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


async def test_tenant_nodes_are_separate_in_memory(confluent_config):
    # Regression: a new tenant's 'everything' group had no 'nodes' set, so
    # adding any node to a tenant raised KeyError.
    main = confluent_config.manager()
    await _make_cluster(main)
    tenant = confluent_config.manager('acme', create_tenant=True)
    await tenant.set_node_attributes({'n1': {'net.ipv4_address': '10.0.0.10'}}, autocreate=True)

    assert configmanager.is_tenant('acme')
    assert sorted(tenant.list_nodes()) == ['n1']
    assert tenant.get_nodegroup_attributes('everything')['nodes'] == set(['n1'])
    assert _value(tenant, 'n1', 'net.ipv4_address') == '10.0.0.10'
    assert _value(main, 'n1', 'net.ipv4_address') is None
    assert 'n1' in main.list_nodes()  # main's own n1 from _make_cluster is untouched


async def test_tenant_store_survives_restart(confluent_config):
    # Regression: tenant stores were written to <cfgdir>/tenants/<tenant>/ but
    # read back from <cfgdir>/<tenant>/ into the wrong key, so a restart lost
    # every tenant.
    tenant = confluent_config.manager('acme', create_tenant=True)
    await tenant.create_user('bob', role='Operator')
    await tenant.add_group_attributes({'compute': {'console.method': 'ipmi'}})
    await tenant.set_node_attributes({'c1': {'groups': ['compute'],
                                             'net.ipv4_address': '10.241.34.2'}},
                                     autocreate=True)

    confluent_config.restart()

    assert configmanager.is_tenant('acme')
    tenant = confluent_config.manager('acme')
    assert tenant.get_user('bob')['role'] == 'Operator'
    assert sorted(tenant.list_nodes()) == ['c1']
    assert _value(tenant, 'c1', 'net.ipv4_address') == '10.241.34.2'
    assert _value(tenant, 'c1', 'console.method') == 'ipmi'
    assert tenant.get_nodegroup_attributes('everything')['nodes'] == set(['c1'])
    assert list(confluent_config.manager().list_nodes()) == []


async def test_tenant_user_can_be_created_first_after_restart(confluent_config):
    # Regression: creating a tenant user before anything had opened the
    # main store raised KeyError: 'main'.
    confluent_config.manager('acme', create_tenant=True)
    confluent_config.restart()
    await confluent_config.manager('acme').create_user('bob')
    assert confluent_config.manager('acme').get_user('bob') is not None


async def test_user_id_map_survives_restart(confluent_config):
    # Regression: the id map was written to <cfgdir>/idmap but never loaded,
    # so after a restart new ids were not checked against existing users.
    main = confluent_config.manager()
    await main.create_user('alice')
    await confluent_config.manager('acme', create_tenant=True).create_user('bob')
    ids = {'alice': main.get_user('alice')['id'],
           'bob': confluent_config.manager('acme').get_user('bob')['id']}

    confluent_config.restart()

    idmap = configmanager._cfgstore['main']['idmap']
    assert idmap[ids['alice']] == {'tenant': None, 'username': 'alice', 'role': 'Administrator'}
    assert idmap[ids['bob']] == {'tenant': 'acme', 'username': 'bob', 'role': 'Administrator'}


async def test_empty_tenant_survives_restart(confluent_config):
    confluent_config.manager('acme', create_tenant=True)
    confluent_config.restart()
    assert configmanager.is_tenant('acme')
    assert list(confluent_config.manager('acme').list_nodes()) == []


async def test_tenants_with_identical_nodes_stay_separate_across_restart(confluent_config):
    for name, serial in (('acme', 'SN-A'), ('globex', 'SN-B')):
        tenant = confluent_config.manager(name, create_tenant=True)
        await tenant.set_node_attributes(
            {'c1': {'net.ipv4_address': '10.241.34.2', 'id.serial': serial}},
            autocreate=True)

    confluent_config.restart()

    for name, serial in (('acme', 'SN-A'), ('globex', 'SN-B')):
        tenant = confluent_config.manager(name)
        assert sorted(tenant.list_nodes()) == ['c1']
        assert _value(tenant, 'c1', 'net.ipv4_address') == '10.241.34.2'
        assert _value(tenant, 'c1', 'id.serial') == serial


async def test_tenant_deleted_node_stays_deleted_after_restart(confluent_config):
    tenant = confluent_config.manager('acme', create_tenant=True)
    await tenant.set_node_attributes({'c1': {}, 'c2': {}}, autocreate=True)
    await tenant.del_nodes(['c2'])

    confluent_config.restart()

    assert sorted(confluent_config.manager('acme').list_nodes()) == ['c1']


async def test_tenant_store_from_older_release_is_repaired(confluent_config):
    # Stores written before the fix have an 'everything' group without a
    # node set; opening the tenant must repair it rather than fail later.
    configmanager._cfgstore.setdefault('tenant', {})['legacy'] = {
        'nodegroups': {'everything': {}}, 'nodes': {}}
    tenant = confluent_config.manager('legacy')
    await tenant.set_node_attributes({'c1': {}}, autocreate=True)
    assert tenant.get_nodegroup_attributes('everything')['nodes'] == set(['c1'])

    confluent_config.restart()

    assert sorted(confluent_config.manager('legacy').list_nodes()) == ['c1']


async def test_stray_file_in_tenants_directory_is_ignored(confluent_config):
    confluent_config.manager('acme', create_tenant=True)
    confluent_config.flush()
    with open(os.path.join(confluent_config.cfgdir, 'tenants', 'README'), 'w') as f:
        f.write('not a tenant')

    confluent_config.restart()

    assert configmanager.is_tenant('acme')
    assert not configmanager.is_tenant('README')


async def test_restart_does_not_touch_other_directories(confluent_config, tmp_path):
    cfm = confluent_config.manager()
    await _make_cluster(cfm)
    confluent_config.flush()
    assert sorted(p.name for p in tmp_path.iterdir()) == ['cfg']


async def test_dump_starts_with_nothing_left_to_write(confluent_config, monkeypatch):
    # The dump is read from disk by a worker, and a file that is being
    # written reads as empty or damaged there. The first manager of an
    # empty store changes it (the 'everything' group): after the caller
    # has waited for the store to be written, as the backup does.
    import asyncio
    import json
    import time
    cm = configmanager.ConfigManager
    write = cm._sync_to_file.__func__
    seen = []

    def slow_write(cls, fullsync=False):
        time.sleep(0.3)  # a slow disk
        return write(cls, fullsync)

    spawn = asyncio.create_subprocess_exec

    async def watched_spawn(*args, **kwargs):
        seen.append((cm._syncrunning, cm._cfgwriter is not None and cm._cfgwriter.is_alive(),
                     sorted(os.listdir(confluent_config.cfgdir))))
        return await spawn(*args, **kwargs)

    monkeypatch.setattr(cm, '_sync_to_file', classmethod(slow_write))
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', watched_spawn)
    assert 'nodegroups' not in configmanager._cfgstore.get('main', {})
    cm.wait_for_sync()
    dumped = json.loads(await cm(None)._dump_to_json())
    assert len(seen) == 1
    running, alive, files = seen[0]
    assert not running and not alive
    assert any(name.split('.')[0] == 'nodegroups' for name in files), files
    assert dumped['nodegroups'] == {'everything': {'nodes': []}}


def test_a_test_that_asks_for_no_store_still_has_its_own(tmp_path):
    # (conftest.store_of_its_own) what makes a ConfigManager here must not
    # read or write the installation's store, or an earlier test's
    cm = configmanager.ConfigManager
    assert cm._cfgdir == os.path.join(str(tmp_path), 'cfg')
    assert configmanager._cfgstore is None and cm._cfgwriter is None
    cm(None)
    cm.wait_for_sync()
    assert 'nodegroups' in set(name.split('.')[0] for name in os.listdir(cm._cfgdir))


def test_and_leaves_nothing_to_the_next_one(tmp_path):
    cm = configmanager.ConfigManager
    assert configmanager._cfgstore is None and cm._cfgwriter is None
    assert not os.path.exists(cm._cfgdir)


async def test_restore_removes_store_files_only_between_writes(confluent_config, monkeypatch):
    # A restore (or a tenant import) starts by removing the files of the
    # store it replaces. The writer thread may be in those files: it holds
    # _synclock for the whole of a write, so that is when they may go.
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    tid = await configmanager.create_tenant('acme')
    removed = []
    unlink = os.unlink

    def watched_unlink(path, *args, **kwargs):
        if str(path).startswith(confluent_config.cfgdir):
            removed.append((os.path.relpath(str(path), confluent_config.cfgdir),
                            configmanager._synclock._is_owned()))
        return unlink(path, *args, **kwargs)

    for tenant in (None, tid):
        cfm = configmanager.ConfigManager(tenant)
        await _make_cluster(cfm)
        confluent_config.flush()
        dump = cfm._real_dump_to_json()
        monkeypatch.setattr(os, 'unlink', watched_unlink)
        await cfm._load_from_json(dump)
        monkeypatch.setattr(os, 'unlink', unlink)
        confluent_config.flush()
    assert any(name == 'nodes' for name, _ in removed)
    assert any(name == os.path.join('tenants', tid, 'nodes') for name, _ in removed)
    assert [name for name, locked in removed if not locked] == []


def _sqlite_store():
    import tempfile
    with tempfile.TemporaryDirectory() as scratch:
        name = os.path.join(scratch, 'probe')
        dbm.open(name, 'c').close()
        return dbm.whichdb(name) == 'dbm.sqlite3'


sqlite_store = pytest.mark.skipif(
    not _sqlite_store(), reason='the dbm of this Python does not write sqlite files')


@sqlite_store
async def test_a_file_of_the_store_is_written_in_one_transaction(confluent_config, monkeypatch):
    # (every key committed by itself waits for the disk once per key)
    cfm = confluent_config.manager()
    await _make_cluster(cfm)
    confluent_config.flush()
    statements = {}
    opened = dbm.open

    def watched_open(path, flag='r', mode=0o666):
        db = opened(path, flag, mode)
        if flag != 'r':
            db._cx.set_trace_callback(
                statements.setdefault(os.path.basename(path), []).append)
        return db

    monkeypatch.setattr(dbm, 'open', watched_open)
    nodes = dict(('extra{0}'.format(n), {'console.method': 'ipmi'}) for n in range(40))
    await cfm.set_node_attributes(nodes, autocreate=True)
    confluent_config.flush()
    monkeypatch.setattr(dbm, 'open', opened)
    seen = [s.split()[0].upper() for s in statements['nodes']]
    written = [n for n, s in enumerate(seen) if s == 'REPLACE']
    assert len(written) >= 40
    assert seen.count('BEGIN') == seen.count('COMMIT') >= 1
    # every key is written inside a transaction, and few of those are needed
    for at in written:
        before = seen[:at]
        assert before.count('BEGIN') == before.count('COMMIT') + 1
    assert seen.count('COMMIT') <= 3
    confluent_config.restart()
    assert set(nodes) <= set(confluent_config.manager().list_nodes())


@sqlite_store
async def test_a_write_that_fails_leaves_the_file_as_it_was(confluent_config, monkeypatch):
    cfm = confluent_config.manager()
    await _make_cluster(cfm)
    confluent_config.flush()

    def stored():
        db = dbm.open(os.path.join(confluent_config.cfgdir, 'nodes'), 'r')
        try:
            return dict((key.decode(), pickle.loads(db[key])) for key in db.keys())
        finally:
            db.close()

    before = stored()
    assert before
    dumps = pickle.dumps
    count = []

    def failing_dumps(value, *args, **kwargs):
        count.append(1)
        if len(count) == 20:
            raise RuntimeError('the disk is gone')
        return dumps(value, *args, **kwargs)

    await cfm.set_node_attributes(
        dict(('late{0}'.format(n), {'console.method': 'ipmi'}) for n in range(40)),
        autocreate=True)
    configmanager.ConfigManager._cfgwriter.join()
    cm = configmanager.ConfigManager
    monkeypatch.setattr(configmanager.cPickle, 'dumps', failing_dumps)
    monkeypatch.setattr('threading.excepthook', lambda args: None)
    await cfm.set_node_attributes(
        dict(('later{0}'.format(n), {'console.method': 'ipmi'}) for n in range(40)),
        autocreate=True)
    cm._cfgwriter.join()
    monkeypatch.setattr(configmanager.cPickle, 'dumps', dumps)
    assert len(count) >= 20, 'the write was interrupted'
    after = stored()
    assert not [name for name in after if name.startswith('later')]
    assert dict((k, v) for k, v in after.items() if not k.startswith('late')) == before
    # and the next write makes up for it (a full one, as after any failure)
    confluent_config.flush()
    assert len([name for name in stored() if name.startswith('later')]) == 40
