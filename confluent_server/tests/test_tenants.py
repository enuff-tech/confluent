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

"""Tenant registry, tenant-scoped globals and keys, backup, collective
join and migration of the configuration store."""

import asyncio
import hashlib
import json
import os

import pytest
from cryptography.exceptions import InvalidTag

import confluent.config.configmanager as configmanager
import confluent.exceptions as exc

SECRET = 'secret.hardwaremanagementpassword'


@pytest.fixture
def tenancy(confluent_config):
    configmanager.set_global('multitenancy.enabled', True)
    configmanager.init_masterkey()
    return confluent_config


def _value(cfm, node, attr, decrypt=False):
    value = cfm.get_node_attributes([node], [attr], decrypt=decrypt).get(
        node, {}).get(attr, {}).get('value')
    if isinstance(value, bytes):  # decrypted secrets come back as bytes
        value = value.decode('utf8')
    return value


def _store(tenantid):
    return configmanager._cfgstore['tenant'][tenantid]


def _tree_digest(path):
    """A digest of every file name and content below path."""
    digest = hashlib.sha256()
    for root, dirs, files in sorted(os.walk(path)):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            digest.update(os.path.relpath(full, path).encode())
            with open(full, 'rb') as f:
                digest.update(f.read())
    return digest.hexdigest()


async def _populate(cfm, serial, password):
    await cfm.add_group_attributes({'compute': {'console.method': 'ipmi',
                                                'secret.hardwaremanagementuser': 'admin'}})
    await cfm.set_node_attributes({
        'c1': {'groups': ['compute'], 'net.ipv4_address': '10.241.34.2',
               'id.serial': serial, SECRET: password},
        'c2': {'groups': ['compute'], 'net.ipv4_address': '10.241.34.3'},
    }, autocreate=True)
    await cfm.create_user('admin', role='Administrator')


# ------------------------------------------------------------- registry

async def test_create_refused_unless_multitenancy_enabled(confluent_config):
    with pytest.raises(exc.InvalidArgumentException):
        await configmanager.create_tenant('acme')
    assert configmanager.list_tenants() == []


async def test_create_and_look_up_tenant(tenancy):
    tid = await configmanager.create_tenant('acme')
    assert configmanager.valid_tenant_id(tid)
    record = configmanager.get_tenant(tid)
    assert record['name'] == 'acme'
    assert record['state'] == 'active'
    assert record['schema'] == configmanager.TENANCY_SCHEMA
    assert record['id'] == tid
    assert configmanager.find_tenant('acme') == tid
    assert configmanager.list_tenants() == [tid]
    assert configmanager.is_tenant(tid)
    assert configmanager.get_tenant('t000000000000') is None


@pytest.mark.parametrize('name', ['', 'Acme', 'a/b', '-acme', 'acme_1', 'a' * 64, '../x'])
async def test_invalid_tenant_names_are_refused(tenancy, name):
    with pytest.raises(exc.InvalidArgumentException):
        await configmanager.create_tenant(name)


async def test_duplicate_tenant_name_is_refused(tenancy):
    await configmanager.create_tenant('acme')
    with pytest.raises(exc.InvalidArgumentException):
        await configmanager.create_tenant('acme')
    assert len(configmanager.list_tenants()) == 1


async def test_concurrent_creation_same_name_yields_one_tenant(tenancy):
    results = await asyncio.gather(
        *[configmanager.create_tenant('acme') for _ in range(5)],
        return_exceptions=True)
    created = [r for r in results if isinstance(r, str)]
    assert len(created) == 1
    assert all(isinstance(r, exc.InvalidArgumentException) for r in results if r not in created)


async def test_concurrent_creation_distinct_names(tenancy):
    ids = await asyncio.gather(*[configmanager.create_tenant('t-%d' % i) for i in range(10)])
    assert len(set(ids)) == 10
    assert sorted(configmanager.get_tenant(t)['name'] for t in ids) == sorted('t-%d' % i for i in range(10))


async def test_registry_and_state_survive_restart(tenancy):
    acme = await configmanager.create_tenant('acme')
    globex = await configmanager.create_tenant('globex')
    await configmanager.set_tenant_state(globex, 'disabled')

    tenancy.restart()

    assert configmanager.list_tenants() == sorted([acme, globex])
    assert configmanager.get_tenant(acme)['state'] == 'active'
    assert configmanager.get_tenant(globex)['state'] == 'disabled'
    assert configmanager.find_tenant('globex') == globex


async def test_invalid_state_and_unknown_tenant(tenancy):
    tid = await configmanager.create_tenant('acme')
    with pytest.raises(exc.InvalidArgumentException):
        await configmanager.set_tenant_state(tid, 'leased')
    with pytest.raises(exc.NotFoundException):
        await configmanager.set_tenant_state('t000000000000', 'disabled')


# -------------------------------------------------- isolation of contents

async def test_identical_names_addresses_and_groups_in_two_tenants(tenancy):
    main = tenancy.manager()
    await main.set_node_attributes({'c1': {'net.ipv4_address': '192.0.2.1'}}, autocreate=True)
    acme = tenancy.manager(await configmanager.create_tenant('acme'))
    globex = tenancy.manager(await configmanager.create_tenant('globex'))
    await _populate(acme, 'SN-A', 'pw-a')
    await _populate(globex, 'SN-B', 'pw-b')

    for cfm, serial in ((acme, 'SN-A'), (globex, 'SN-B')):
        assert sorted(cfm.list_nodes()) == ['c1', 'c2']
        assert _value(cfm, 'c1', 'net.ipv4_address') == '10.241.34.2'
        assert _value(cfm, 'c1', 'id.serial') == serial
        assert cfm.get_nodegroup_attributes('compute')['nodes'] == set(['c1', 'c2'])
    assert _value(main, 'c1', 'net.ipv4_address') == '192.0.2.1'
    assert _value(main, 'c1', 'id.serial') is None
    assert sorted(main.list_nodes()) == ['c1']


async def test_node_indexes_are_counted_per_tenant(tenancy):
    main = tenancy.manager()
    await main.set_node_attributes(dict(('m%d' % i, {}) for i in range(5)), autocreate=True)
    acme = tenancy.manager(await configmanager.create_tenant('acme'))
    globex = tenancy.manager(await configmanager.create_tenant('globex'))
    for cfm in (acme, globex):
        await cfm.set_node_attributes({'c1': {}, 'c2': {}}, autocreate=True)
        assert _value(cfm, 'c1', 'id.index') == 1
        assert _value(cfm, 'c2', 'id.index') == 2
    # deleting the last node frees its index, in that tenant only
    await acme.del_nodes(['c2'])
    await acme.set_node_attributes({'c3': {}}, autocreate=True)
    await globex.set_node_attributes({'c3': {}}, autocreate=True)
    assert _value(acme, 'c3', 'id.index') == 2
    assert _value(globex, 'c3', 'id.index') == 3
    assert configmanager.get_global('max_node_index') == 6  # main unaffected

    tenancy.restart()

    acme = tenancy.manager(configmanager.find_tenant('acme'))
    await acme.set_node_attributes({'c4': {}}, autocreate=True)
    assert _value(acme, 'c4', 'id.index') == 3


async def test_scoped_globals(tenancy):
    acme = tenancy.manager(await configmanager.create_tenant('acme'))
    main = tenancy.manager()
    acme.set_scoped_global('discovery.autosense', False)
    main.set_scoped_global('discovery.autosense', True)
    assert acme.get_scoped_global('discovery.autosense') is False
    assert configmanager.get_global('discovery.autosense') is True

    tenancy.restart()

    assert tenancy.manager(configmanager.find_tenant('acme')).get_scoped_global(
        'discovery.autosense') is False


async def test_opening_an_unchanged_tenant_does_not_write(tenancy, monkeypatch):
    tid = await configmanager.create_tenant('acme')
    tenancy.manager(tid)
    tenancy.flush()
    calls = []
    monkeypatch.setattr(configmanager.ConfigManager, '_bg_sync_to_file',
                        classmethod(lambda cls, fullsync=False: calls.append(1)))
    for _ in range(20):
        tenancy.manager(tid)
    assert calls == []


# -------------------------------------------------------- tenant data keys

async def test_tenant_secrets_use_the_tenant_data_key(tenancy):
    acme_id = await configmanager.create_tenant('acme')
    globex_id = await configmanager.create_tenant('globex')
    acme, globex = tenancy.manager(acme_id), tenancy.manager(globex_id)
    await _populate(acme, 'SN-A', 'same-password')
    await _populate(globex, 'SN-B', 'same-password')

    assert _value(acme, 'c1', SECRET, decrypt=True) == 'same-password'
    assert _value(acme, 'c2', 'secret.hardwaremanagementuser', decrypt=True) == 'admin'  # inherited
    raw = _store(acme_id)['nodes']['c1'][SECRET]['cryptvalue']
    with pytest.raises(InvalidTag):
        configmanager.decrypt_value(raw)  # not the master key
    with pytest.raises(InvalidTag):
        configmanager.decrypt_value(raw, key=globex._cryptkey())
    assert configmanager.decrypt_value(raw, key=acme._cryptkey()) == b'same-password'
    assert acme._cryptkey() != globex._cryptkey()
    assert _value(acme, 'c1', SECRET) is None  # no plaintext without decrypt

    tenancy.restart()

    acme = tenancy.manager(acme_id)
    assert _value(acme, 'c1', SECRET, decrypt=True) == 'same-password'


async def test_default_tenant_still_uses_master_key(tenancy):
    main = tenancy.manager()
    await main.set_node_attributes({'n1': {SECRET: 'pw'}}, autocreate=True)
    raw = configmanager._cfgstore['main']['nodes']['n1'][SECRET]['cryptvalue']
    assert configmanager.decrypt_value(raw) == b'pw'


async def test_store_without_data_key_falls_back_to_master_key(tenancy):
    legacy = tenancy.manager('legacy', create_tenant=True)
    await legacy.set_node_attributes({'c1': {SECRET: 'pw'}}, autocreate=True)
    raw = _store('legacy')['nodes']['c1'][SECRET]['cryptvalue']
    assert configmanager.decrypt_value(raw) == b'pw'
    assert _value(legacy, 'c1', SECRET, decrypt=True) == 'pw'


# ------------------------------------------------------------------ delete

async def test_delete_requires_disabled_tenant(tenancy):
    tid = await configmanager.create_tenant('acme')
    with pytest.raises(exc.InvalidArgumentException):
        await configmanager.delete_tenant(tid)
    with pytest.raises(exc.NotFoundException):
        await configmanager.delete_tenant('t000000000000')
    assert configmanager.is_tenant(tid)


async def test_delete_removes_only_that_tenant(tenancy):
    main = tenancy.manager()
    await main.set_node_attributes({'n1': {}}, autocreate=True)
    acme_id = await configmanager.create_tenant('acme')
    globex_id = await configmanager.create_tenant('globex')
    await _populate(tenancy.manager(acme_id), 'SN-A', 'pw-a')
    await _populate(tenancy.manager(globex_id), 'SN-B', 'pw-b')
    tenancy.flush()
    tenantroot = os.path.join(tenancy.cfgdir, 'tenants')
    globex_before = _tree_digest(os.path.join(tenantroot, globex_id))
    main_nodes_before = _tree_digest(os.path.join(tenancy.cfgdir, 'nodes'))

    await configmanager.set_tenant_state(acme_id, 'disabled')
    # an unwritten change right before deletion must not recreate the tenant
    await tenancy.manager(acme_id).set_node_attributes({'c9': {}}, autocreate=True)
    await configmanager.delete_tenant(acme_id)
    tenancy.flush()

    assert not configmanager.is_tenant(acme_id)
    assert configmanager.find_tenant('acme') is None
    assert not os.path.exists(os.path.join(tenantroot, acme_id))
    assert _tree_digest(os.path.join(tenantroot, globex_id)) == globex_before
    assert _tree_digest(os.path.join(tenancy.cfgdir, 'nodes')) == main_nodes_before
    idmap = configmanager._cfgstore['main']['idmap']
    assert not [u for u in idmap if idmap[u]['tenant'] == acme_id]
    assert [u for u in idmap if idmap[u]['tenant'] == globex_id]

    tenancy.restart()

    assert configmanager.list_tenants() == [globex_id]
    assert sorted(tenancy.manager(globex_id).list_nodes()) == ['c1', 'c2']
    # the name can be used again, and gets a new id
    assert await configmanager.create_tenant('acme') != acme_id


async def test_directory_removal_refuses_anything_but_a_tenant_directory(tenancy, tmp_path):
    outside = tmp_path / 'precious'
    outside.mkdir()
    (outside / 'data').write_text('keep')
    tenantroot = os.path.join(tenancy.cfgdir, 'tenants')
    os.makedirs(tenantroot, exist_ok=True)
    os.symlink(str(outside), os.path.join(tenantroot, 't0123456789ab'))
    configmanager._remove_tenant_directory(tenancy.cfgdir, 't0123456789ab')
    configmanager._remove_tenant_directory(tenancy.cfgdir, '..')
    configmanager._remove_tenant_directory(tenancy.cfgdir, '')
    assert (outside / 'data').read_text() == 'keep'


# ---------------------------------------------------------- backup/restore

async def test_backup_and_restore_round_trip(tenancy, tmp_path):
    main = tenancy.manager()
    await main.set_node_attributes({'n1': {SECRET: 'main-pw'}}, autocreate=True)
    acme_id = await configmanager.create_tenant('acme')
    globex_id = await configmanager.create_tenant('globex')
    await _populate(tenancy.manager(acme_id), 'SN-A', 'pw-a')
    await _populate(tenancy.manager(globex_id), 'SN-B', 'pw-b')
    await configmanager.set_tenant_state(globex_id, 'disabled')
    backup = str(tmp_path / 'backup')
    os.makedirs(backup)

    await configmanager.dump_db_to_directory(backup, 'backup-password')

    with open(os.path.join(backup, 'tenants', acme_id, 'main.json')) as f:
        acme_dump = json.load(f)
    assert sorted(acme_dump['nodes']) == ['c1', 'c2']  # not the main store
    with open(os.path.join(backup, 'tenants', acme_id, 'tenant.json')) as f:
        assert json.load(f)['meta']['name'] == 'acme'

    tenancy.switch('restored')
    await configmanager.restore_db_from_directory(backup, 'backup-password')

    assert configmanager.list_tenants() == sorted([acme_id, globex_id])
    assert configmanager.get_tenant(globex_id)['state'] == 'disabled'
    for tid, serial, pw in ((acme_id, 'SN-A', 'pw-a'), (globex_id, 'SN-B', 'pw-b')):
        cfm = tenancy.manager(tid)
        assert sorted(cfm.list_nodes()) == ['c1', 'c2']
        assert _value(cfm, 'c1', 'id.serial') == serial
        assert _value(cfm, 'c1', SECRET, decrypt=True) == pw
        assert _value(cfm, 'c2', 'console.method') == 'ipmi'
        assert cfm.get_user('admin') is not None
    assert _value(main, 'n1', SECRET, decrypt=True) == 'main-pw'

    tenancy.restart()
    assert _value(tenancy.manager(acme_id), 'c1', SECRET, decrypt=True) == 'pw-a'


async def test_restore_removes_tenants_not_in_the_backup(tenancy, tmp_path):
    keep = await configmanager.create_tenant('keep')
    backup = str(tmp_path / 'backup')
    os.makedirs(backup)
    await configmanager.dump_db_to_directory(backup, None, skipkeys=True)
    with open(os.path.join(backup, 'keys.json'), 'w') as f:
        f.write(configmanager._dump_keys(None))
    extra = await configmanager.create_tenant('extra')
    tenancy.flush()

    await configmanager.restore_db_from_directory(backup, None)
    tenancy.flush()

    assert configmanager.list_tenants() == [keep]
    assert not os.path.exists(os.path.join(tenancy.cfgdir, 'tenants', extra))


async def test_old_format_dump_copy_is_not_restored_as_tenant(tenancy, tmp_path):
    backup = str(tmp_path / 'backup')
    os.makedirs(os.path.join(backup, 'tenants', 'acme'))
    await configmanager.dump_db_to_directory(backup, None, skipkeys=True)
    with open(os.path.join(backup, 'keys.json'), 'w') as f:
        f.write(configmanager._dump_keys(None))
    # what older releases wrote: a copy of the main configuration
    with open(os.path.join(backup, 'main.json')) as src, \
            open(os.path.join(backup, 'tenants', 'acme', 'main.json'), 'w') as dst:
        dst.write(src.read())

    tenancy.switch('restored')
    await configmanager.restore_db_from_directory(backup, None)

    assert configmanager.list_tenants() == []
    assert not configmanager.is_tenant('acme')


async def test_redacted_dump_has_no_tenant_key(tenancy, tmp_path):
    tid = await configmanager.create_tenant('acme')
    await _populate(tenancy.manager(tid), 'SN-A', 'pw-a')
    backup = str(tmp_path / 'backup')
    os.makedirs(backup)
    await configmanager.dump_db_to_directory(backup, None, redact=True)
    with open(os.path.join(backup, 'tenants', tid, 'tenant.json')) as f:
        assert 'data_key' not in json.load(f)['globals']
    with open(os.path.join(backup, 'tenants', tid, 'main.json')) as f:
        assert 'pw-a' not in f.read()


async def test_backup_refuses_unregistered_tenant_stores(tenancy, tmp_path):
    tenancy.manager('legacy', create_tenant=True)
    with pytest.raises(Exception, match='migrate-tenancy'):
        await configmanager.dump_db_to_directory(str(tmp_path), None, skipkeys=True)


# ------------------------------------------------------- collective join

async def test_collective_join_receives_tenants(tenancy):
    main = tenancy.manager()
    await main.set_node_attributes({'n1': {SECRET: 'main-pw'}}, autocreate=True)
    acme_id = await configmanager.create_tenant('acme')
    await _populate(tenancy.manager(acme_id), 'SN-A', 'pw-a')
    keys = configmanager._dump_keys(None, False)
    payload = await configmanager.dump_collective_payload()
    assert acme_id in json.loads(payload)['_tenants']

    # the joining member, which has a stale tenant of its own
    tenancy.switch('follower')
    configmanager.set_global('multitenancy.enabled', True)
    stale = await configmanager.create_tenant('stale')
    tenancy.flush()
    await configmanager.clear_configuration()
    configmanager._restore_keys(keys, None, sync=False)
    await configmanager.ConfigManager(None)._load_from_json(payload, sync=False)
    await configmanager.load_collective_tenants(payload)
    configmanager.commit_clear()

    assert configmanager.list_tenants() == [acme_id]
    acme = tenancy.manager(acme_id)
    assert _value(acme, 'c1', SECRET, decrypt=True) == 'pw-a'
    assert _value(tenancy.manager(), 'n1', SECRET, decrypt=True) == 'main-pw'

    tenancy.restart()

    assert configmanager.list_tenants() == [acme_id]
    assert not os.path.exists(os.path.join(tenancy.cfgdir, 'tenants', stale))
    assert _value(tenancy.manager(acme_id), 'c1', 'id.serial') == 'SN-A'


async def test_collective_payload_loads_on_members_without_tenant_support(tenancy):
    # Older members only load the main store from the payload and must
    # not be confused by the extra '_tenants' key.
    await tenancy.manager().set_node_attributes({'n1': {}}, autocreate=True)
    await configmanager.create_tenant('acme')
    payload = await configmanager.dump_collective_payload()
    tenancy.switch('oldmember')
    await configmanager.ConfigManager(None)._load_from_json(payload)
    assert sorted(tenancy.manager().list_nodes()) == ['n1']
    assert configmanager.list_tenants() == []


async def test_tenant_creation_is_replicated_with_the_same_id_and_key(tenancy, monkeypatch):
    sent = []

    async def fake_followers(fnname, *args):
        sent.append((fnname, args))
    monkeypatch.setattr(configmanager, 'cfgstreams', {'peer': {}})
    monkeypatch.setattr(configmanager, 'exec_on_followers', fake_followers)

    tid = await configmanager.create_tenant('acme')
    await configmanager.set_tenant_state(tid, 'disabled')
    await configmanager.delete_tenant(tid)

    assert [s[0] for s in sent] == ['_rpc_create_tenant', '_rpc_set_tenant_state',
                                    '_rpc_delete_tenant']
    created = sent[0][1]
    assert created[0] == tid and created[1] == 'acme'
    # a follower applying the same call ends up with the same tenant and key
    configmanager._rpc_create_tenant(*created)
    assert configmanager.get_tenant(tid)['name'] == 'acme'
    assert _store(tid)['globals']['data_key'] == created[2]


async def test_replicated_create_rejects_bad_input(tenancy):
    with pytest.raises(exc.InvalidArgumentException):
        configmanager._rpc_create_tenant('../etc', 'acme', 'x', 0)
    tid = await configmanager.create_tenant('acme')
    with pytest.raises(exc.InvalidArgumentException):
        configmanager._rpc_create_tenant(tid, 'other', 'x', 0)


# ---------------------------------------------------------------- migration

async def test_migration_registers_legacy_stores_and_is_repeatable(tenancy):
    main = tenancy.manager()
    await main.set_node_attributes({'n1': {SECRET: 'main-pw'}}, autocreate=True)
    legacy = tenancy.manager('acme', create_tenant=True)
    await legacy.set_node_attributes({'c1': {SECRET: 'legacy-pw'}}, autocreate=True)
    await legacy.create_user('bob')
    tenancy.flush()
    main_before = json.dumps(configmanager._cfgstore['main']['nodes'], sort_keys=True, default=str)

    changes = await configmanager.migrate_tenancy()

    moved = [c for c in changes if 'store' in c]
    assert len(moved) == 1 and moved[0]['store'] == 'acme' and moved[0]['name'] == 'acme'
    tid = moved[0]['id']
    assert configmanager.valid_tenant_id(tid)
    assert configmanager.find_tenant('acme') == tid
    assert not configmanager.is_tenant('acme')
    cfm = tenancy.manager(tid)
    assert _value(cfm, 'c1', SECRET, decrypt=True) == 'legacy-pw'
    raw = _store(tid)['nodes']['c1'][SECRET]['cryptvalue']
    with pytest.raises(InvalidTag):
        configmanager.decrypt_value(raw)  # re-encrypted with the tenant key
    idmap = configmanager._cfgstore['main']['idmap']
    assert [idmap[u]['tenant'] for u in idmap if idmap[u]['username'] == 'bob'] == [tid]
    assert configmanager.get_global('tenancy.schema') == configmanager.TENANCY_SCHEMA
    assert json.dumps(configmanager._cfgstore['main']['nodes'], sort_keys=True,
                      default=str) == main_before

    assert await configmanager.migrate_tenancy() == []

    tenancy.restart()

    assert configmanager.list_tenants() == [tid]
    assert not os.path.exists(os.path.join(tenancy.cfgdir, 'tenants', 'acme'))
    assert _value(tenancy.manager(tid), 'c1', SECRET, decrypt=True) == 'legacy-pw'
    assert _value(tenancy.manager(), 'n1', SECRET, decrypt=True) == 'main-pw'
    assert await configmanager.migrate_tenancy() == []


async def test_migration_of_single_tenant_install_only_records_schema(tenancy):
    await tenancy.manager().set_node_attributes({'n1': {}}, autocreate=True)
    tenancy.flush()
    before = _tree_digest(os.path.join(tenancy.cfgdir, 'nodes'))
    assert await configmanager.migrate_tenancy() == [{'schema': configmanager.TENANCY_SCHEMA}]
    assert _tree_digest(os.path.join(tenancy.cfgdir, 'nodes')) == before
    assert configmanager.list_tenants() == []


async def test_migration_when_main_store_was_never_opened(tenancy):
    # Regression: a full write crashed with KeyError: 'main' when only a
    # tenant store had been opened, as when confluentdbutil migrates.
    legacy = tenancy.manager('acme', create_tenant=True)
    await legacy.set_node_attributes({'c1': {}}, autocreate=True)
    tenancy.restart()
    configmanager._cfgstore.pop('main', None)
    changes = await configmanager.migrate_tenancy()
    tenancy.flush()
    assert [c['name'] for c in changes if 'name' in c] == ['acme']
    tenancy.restart()
    assert sorted(tenancy.manager(configmanager.find_tenant('acme')).list_nodes()) == ['c1']


async def test_migration_of_legacy_stores_refused_in_a_collective(tenancy):
    tenancy.manager('acme', create_tenant=True)
    configmanager._cfgstore['collective'] = {'a': {}, 'b': {}}
    with pytest.raises(exc.InvalidArgumentException):
        await configmanager.migrate_tenancy()
    assert configmanager.is_tenant('acme')
