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

"""A tenant's configuration can be moved between installations.

Exported from a tenant, imported as the whole configuration of an
installation, exported again and imported into another tenant: at every
step the configuration is the same (secrets included, each time under a
different key), nothing of the source's keys travels, and an import
either happens completely into an empty destination or not at all.
"""

import base64
import json
import os

import pytest
import yaml
from cryptography.exceptions import InvalidTag

import confluent.config.configmanager as configmanager
import confluent.discovery.core as disco
import confluent.networking.tenantnetcfg as netcfg
import confluent.tenantexport as tenantexport
import confluent.tenantservices as services

SRC = 't00000000000a'
OTHER = 't00000000000b'
DEST = 't00000000000c'
BACK = 't00000000000d'
PASSPHRASE = 'correct horse battery staple'
BMC_PASSWORD = 'bmc-password-of-the-tenant'
SNMP = 'snmp-community-of-the-tenant'
NETCFG = {'interfaces': {'up0': {'addresses': ['10.250.1.1/24'], 'mtu': 1400}},
          'routes': [{'destination': 'default', 'gateway': '10.250.1.254'}],
          'dns': {'nameservers': ['10.250.1.53'], 'search': ['acme.example']}}


def _create(tid, name):
    configmanager._true_create_tenant(
        tid, name, configmanager._wrap_tenant_key(os.urandom(32)), 0)


@pytest.fixture
async def installation(confluent_config, monkeypatch, tmp_path):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    monkeypatch.setattr(netcfg, 'start', lambda tenant: False)
    monkeypatch.setattr(tenantexport, 'SCRYPT_N', 2 ** 14)  # quick, for tests
    monkeypatch.setattr(tenantexport, 'SUBSCRIPTIONS', str(tmp_path / 'no-subscriptions'))
    for tid, name in ((SRC, 'acme'), (OTHER, 'globex'), (DEST, 'initech'), (BACK, 'hooli')):
        _create(tid, name)
    src = configmanager.ConfigManager(SRC)
    await src.add_group_attributes({'compute': {
        'console.method': 'ipmi', 'secret.snmpcommunity': SNMP}})
    await src.set_node_attributes({
        'n1': {'groups': ['compute'], 'hardwaremanagement.manager': '10.250.1.11',
               'secret.hardwaremanagementpassword': BMC_PASSWORD,
               'net.hwaddr': '02:00:00:00:00:01', 'net.ipv4_address': '10.250.1.21/24',
               'net.ipv4_method': 'static', 'id.uuid': '6a1e4c8e-2b6f-4b8e-9d3c-6f1f0c7a5e11',
               'crypted.rootpassword': {'hashvalue': '$5$salt$hashhashhash'},
               'discovery.policy': 'pxe'},
        'n2': {'groups': ['compute'], 'net.ipv4_method': 'dhcp'},
        'sw1': {'type': 'switch'},
    }, autocreate=True)
    await src.create_user('admin', role='Administrator')
    await src.set_user('admin', {'password': 'the-admins-password'})
    await src.create_user('op', role='Operator')
    await src.create_usergroup('operators', role='Operator')
    src.set_scoped_global('discovery.autosense', False)
    src.set_scoped_global('netcfg', NETCFG)
    other = configmanager.ConfigManager(OTHER)
    await other.set_node_attributes({'n1': {
        'secret.hardwaremanagementpassword': 'secret-of-the-other-tenant'}}, autocreate=True)
    await other.create_user('admin', role='Administrator')
    return str(tmp_path)


def _view(cfm):
    """Everything that should survive a move, with secrets in the clear."""
    nodes = {}
    for node, attrs in cfm.get_node_attributes(list(cfm.list_nodes()), (), decrypt=True).items():
        nodes[node] = dict(
            (name, value.get('value', value.get('hashvalue')))
            for name, value in attrs.items()
            if isinstance(value, dict) and name != 'id.index')
        for name, value in nodes[node].items():
            if isinstance(value, bytes):
                nodes[node][name] = value.decode()
    groups = {}
    for group in cfm.get_groups():
        attrs = cfm.get_nodegroup_attributes(group)
        groups[group] = sorted(attrs.get('nodes', []))
    return {'nodes': nodes, 'groups': groups,
            'autosense': cfm.get_scoped_global('discovery.autosense')}


def _roles(cfm, names):
    return dict((name, cfm.get_user(name)['role']) for name in names)


def _checksum(tid):
    return json.loads(configmanager.ConfigManager(tid)._real_dump_to_json())


async def _move(source, destination, directory, **options):
    tenantexport.write(tenantexport.build(source, PASSPHRASE), directory)
    return await tenantexport.import_package(
        destination, tenantexport.read(directory), PASSPHRASE, **options)


async def test_round_trip_tenant_to_installation_and_back(installation):
    src = configmanager.ConfigManager(SRC)
    original = _view(src)
    assert original['nodes']['n1']['secret.hardwaremanagementpassword'] == BMC_PASSWORD
    assert original['nodes']['n1']['secret.snmpcommunity'] == SNMP  # from its group
    other = _checksum(OTHER)
    # a tenant of a shared installation becomes an installation of its own
    standalone = configmanager.ConfigManager(None)
    report = await _move(src, standalone, os.path.join(installation, 'a'))
    assert report['status'] == 'imported' and report['nodes'] == 3
    assert report['secrets'] >= 2 and sorted(report['users']) == ['admin', 'op']
    assert report['not_imported'] == {'netcfg': NETCFG}
    assert _view(standalone) == original
    assert _roles(standalone, ['admin', 'op']) == {'admin': 'Administrator', 'op': 'Operator'}
    assert standalone.get_user('admin')['cryptpass'] == src.get_user('admin')['cryptpass']
    # and that installation's configuration becomes a tenant of a shared one
    back = configmanager.ConfigManager(BACK)
    await back.create_user('importer', role='Administrator')
    report = await _move(standalone, back, os.path.join(installation, 'b'))
    assert report['status'] == 'imported' and 'importer' not in report['users']
    assert _view(back) == original
    assert _roles(back, ['admin', 'op', 'importer'])['importer'] == 'Administrator'
    # each copy is encrypted under its own key: the ciphertext differs
    stored = [cfg._cfgstore['nodes']['n1']['secret.hardwaremanagementpassword']['cryptvalue']
              for cfg in (src, standalone, back)]
    assert len(set(stored)) == 3
    assert configmanager.decrypt_value(stored[2], key=back._cryptkey()) == BMC_PASSWORD.encode()
    with pytest.raises(InvalidTag):
        configmanager.decrypt_value(stored[2], key=src._cryptkey())
    # the tenant that had nothing to do with it is exactly as it was
    assert _checksum(OTHER) == other
    assert _checksum(SRC)['nodes'].keys() == {'n1', 'n2', 'sw1'}


async def test_import_is_repeatable_and_only_into_an_empty_destination(installation):
    src = configmanager.ConfigManager(SRC)
    dest = configmanager.ConfigManager(DEST)
    directory = os.path.join(installation, 'pkg')
    assert (await _move(src, dest, directory))['status'] == 'imported'
    before = _checksum(DEST)
    # the same package again: nothing to do
    again = await tenantexport.import_package(dest, tenantexport.read(directory), PASSPHRASE)
    assert again['status'] == 'already imported' and _checksum(DEST) == before
    # another package (even of the same tenant): refused, nothing merged
    other = os.path.join(installation, 'pkg2')
    tenantexport.write(tenantexport.build(src, PASSPHRASE), other)
    with pytest.raises(tenantexport.DestinationNotEmpty):
        await tenantexport.import_package(dest, tenantexport.read(other), PASSPHRASE)
    # and never into a tenant that already has nodes
    with pytest.raises(tenantexport.DestinationNotEmpty):
        await tenantexport.import_package(
            configmanager.ConfigManager(OTHER), tenantexport.read(other), PASSPHRASE)
    assert _checksum(DEST) == before


async def test_wrong_passphrase_or_damage_changes_nothing(installation):
    src = configmanager.ConfigManager(SRC)
    dest = configmanager.ConfigManager(DEST)
    directory = os.path.join(installation, 'pkg')
    tenantexport.write(tenantexport.build(src, PASSPHRASE), directory)
    empty = _checksum(DEST)
    for passphrase in ('not the passphrase', '', None):
        with pytest.raises(tenantexport.PackageError):
            await tenantexport.import_package(dest, tenantexport.read(directory), passphrase)
    assert _checksum(DEST) == empty and dest.get_scoped_global(tenantexport.IMPORTED) is None
    # a secret that does not decrypt (the store was swapped under the manifest)
    files = tenantexport.read(directory)
    store = json.loads(files['store/main.json'])
    secret = store['nodes']['n1']['secret.hardwaremanagementpassword']
    parts = secret['cryptvalue'].split('!')
    parts[1] = base64.b64encode(b'x' * 16).decode()
    secret['cryptvalue'] = '!'.join(parts)
    files['store/main.json'] = json.dumps(store).encode()
    with pytest.raises(tenantexport.PackageError):
        await tenantexport.import_package(dest, files, PASSPHRASE)
    assert _checksum(DEST) == empty
    # a file changed after export, a missing file, a name that leaves the package
    with open(os.path.join(directory, 'store/main.json'), 'ab') as f:
        f.write(b' ')
    with pytest.raises(tenantexport.PackageError, match='damaged'):
        tenantexport.read(directory)
    os.unlink(os.path.join(directory, 'netcfg.yaml'))
    with pytest.raises(tenantexport.PackageError):
        tenantexport.read(directory)
    with open(os.path.join(directory, 'manifest.json')) as f:
        manifest = json.load(f)
    manifest['files'] = {'../../etc/hostname': '0' * 64}
    with open(os.path.join(directory, 'manifest.json'), 'w') as f:
        json.dump(manifest, f)
    with pytest.raises(tenantexport.PackageError):
        tenantexport.read(directory)
    with pytest.raises(tenantexport.PackageError):
        tenantexport.read(os.path.join(installation, 'no-such-package'))
    assert _checksum(DEST) == empty


async def test_package_carries_no_plaintext_and_no_source_key(installation):
    src = configmanager.ConfigManager(SRC)
    files = tenantexport.build(src, PASSPHRASE)
    everything = b''.join(files.values())
    keys = [src._cryptkey(), configmanager._masterkey]
    for secret in (BMC_PASSWORD, SNMP, PASSPHRASE, 'the-admins-password'):
        assert secret.encode() not in everything
    for key in keys:
        assert key not in everything and base64.b64encode(key) not in everything
    manifest = json.loads(files['manifest.json'])
    assert manifest['format'] == 'confluent-tenant-export' and manifest['version'] == 1
    assert manifest['source'] == {'kind': 'tenant', 'id': SRC, 'name': 'acme'}
    assert set(manifest['files']) == {'store/main.json', 'store/globals.json',
                                      'netcfg.yaml', 'keys.json'}
    assert yaml.safe_load(files['netcfg.yaml']) == NETCFG
    assert json.loads(files['keys.json'])['kdf'] == 'scrypt'
    # written for the exporting user only
    directory = os.path.join(installation, 'pkg')
    tenantexport.write(files, directory)
    for root, _, names in os.walk(directory):
        assert os.stat(root).st_mode & 0o077 == 0
        for name in names:
            assert os.stat(os.path.join(root, name)).st_mode & 0o077 == 0
    # two exports of the same tenant do not share a key
    again = tenantexport.build(src, PASSPHRASE)
    assert json.loads(again['keys.json'])['packagekey'] != \
        json.loads(files['keys.json'])['packagekey']
    with pytest.raises(tenantexport.PackageError):
        tenantexport.build(src, None)


async def test_redacted_package_has_no_secrets_and_is_not_importable(installation):
    src = configmanager.ConfigManager(SRC)
    files = tenantexport.build(src, None, redact=True)
    assert 'keys.json' not in files and json.loads(files['manifest.json'])['redacted'] is True
    everything = b''.join(files.values())
    for secret in (BMC_PASSWORD, SNMP, 'the-admins-password'):
        assert secret.encode() not in everything
    store = json.loads(files['store/main.json'])
    assert store['nodes']['n1']['secret.hardwaremanagementpassword'] == '*REDACTED*'
    assert store['users']['admin']['cryptpass'] == '*REDACTED*'
    assert store['nodes']['n1']['net.ipv4_address']['value'] == '10.250.1.21/24'
    with pytest.raises(tenantexport.PackageError, match='redacted'):
        await tenantexport.import_package(
            configmanager.ConfigManager(DEST), files, PASSPHRASE)


async def test_users_and_api_keys_on_import(installation):
    src = configmanager.ConfigManager(SRC)
    src._cfgstore['users']['op']['apikeys'] = {'kid1': {'expires': 4102444800}}
    src._cfgstore['users']['op']['secret.apikey'] = {
        'cryptvalue': configmanager.crypt_value(b'api-key-secret', key=src._cryptkey())}
    dest = configmanager.ConfigManager(DEST)
    await dest.create_user('admin', role='Operator')  # the destination's own
    mine = dest.get_user('admin')
    report = await _move(src, dest, os.path.join(installation, 'a'))
    # the destination's user of the same name is kept, not replaced
    assert report['users_kept'] == ['admin'] and report['users'] == ['op']
    assert dest.get_user('admin')['role'] == 'Operator' and dest.get_user('admin') == mine
    # API keys do not travel unless asked for
    assert 'apikeys' not in dest._cfgstore['users']['op']
    assert 'secret.apikey' not in dest._cfgstore['users']['op']
    back = configmanager.ConfigManager(BACK)
    report = await _move(src, back, os.path.join(installation, 'b'), keep_apikeys=True)
    assert back._cfgstore['users']['op']['apikeys'] == {'kid1': {'expires': 4102444800}}
    assert configmanager.decrypt_value(
        back._cfgstore['users']['op']['secret.apikey']['cryptvalue'],
        key=back._cryptkey()) == b'api-key-secret'
    # or without the package's users at all
    standalone = configmanager.ConfigManager(None)
    report = await _move(src, standalone, os.path.join(installation, 'c'), users=False)
    assert report['users'] == [] and report['not_imported']['users'] == ['admin', 'op']
    assert 'op' not in standalone.list_users() and len(list(standalone.list_nodes())) == 3


async def test_standalone_installation_into_a_tenant(installation, monkeypatch):
    # a standalone installation, with discovery subscriptions of its own
    subscriptions = os.path.join(installation, 'discovery_subscriptions.json')
    with open(subscriptions, 'w') as f:
        json.dump({'switch1': {}, 'switch2': {}}, f)
    monkeypatch.setattr(tenantexport, 'SUBSCRIPTIONS', subscriptions)
    standalone = configmanager.ConfigManager(None)
    await standalone.set_node_attributes({'legacy1': {
        'secret.hardwaremanagementpassword': 'legacy-secret',
        'net.ipv4_address': '192.168.1.5/24'}}, autocreate=True)
    files = tenantexport.build(standalone, PASSPHRASE)
    assert json.loads(files['manifest.json'])['source']['kind'] == 'default'
    assert b'legacy-secret' not in b''.join(files.values())
    dest = configmanager.ConfigManager(DEST)
    report = await tenantexport.import_package(dest, files, PASSPHRASE)
    assert report['nodes'] == 1
    # what belongs to an installation, not to a tenant, is reported
    assert report['not_imported'] == {'discovery.subscriptions': ['switch1', 'switch2']}
    attrs = dest.get_node_attributes('legacy1', (), decrypt=True)['legacy1']
    assert attrs['secret.hardwaremanagementpassword']['value'] in ('legacy-secret', b'legacy-secret')
    assert 'legacy1' not in configmanager.ConfigManager(OTHER).list_nodes()


def test_full_strength_key_derivation_and_nmstate():
    # the real cost parameter (tests above lower it)
    assert tenantexport.SCRYPT_N == 2 ** 17
    key = tenantexport._derive(PASSPHRASE, b's' * 16, tenantexport.SCRYPT_N)
    assert len(key) == 32 and key != tenantexport._derive('other', b's' * 16, tenantexport.SCRYPT_N)
    state = yaml.safe_load(tenantexport.nmstate(NETCFG))
    assert state['interfaces'] == [{
        'name': 'up0', 'state': 'up', 'mtu': 1400,
        'ipv4': {'enabled': True, 'dhcp': False,
                 'address': [{'ip': '10.250.1.1', 'prefix-length': 24}]}}]
    assert state['routes']['config'] == [
        {'destination': '0.0.0.0/0', 'next-hop-address': '10.250.1.254'}]
    assert state['dns-resolver']['config'] == {
        'server': ['10.250.1.53'], 'search': ['acme.example']}
