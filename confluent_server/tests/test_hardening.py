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

"""Limits on what can be asked of the service, and cleaning up after an
interrupted deletion: the lifetime of SSH certificates, challenges that
are remembered, packages offered for import, what a deleted tenant leaves.
"""

import asyncio
import base64
import hashlib
import json
import os
import shutil
import subprocess
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import confluent.config.configmanager as configmanager
import confluent.discovery.core as disco
import confluent.log as log
import confluent.networking.tenantnetcfg as netcfg
import confluent.tenantexport as tenantexport
import confluent.tenantpaths as tenantpaths
import confluent.tenantservices as services
import confluent.tenantssh as tenantssh
import confluent.util as util

A = 't00000000000a'
B = 't00000000000b'
GONE = 't0000000000ff'


@pytest.fixture
async def tenants(confluent_config, monkeypatch, tmp_path):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    monkeypatch.setattr(netcfg, 'start', lambda tenant: False)
    monkeypatch.setattr(tenantpaths, 'BASE', str(tmp_path / 'lib'))
    logs = str(tmp_path / 'logs')
    monkeypatch.setattr(log, 'base_directory', lambda: logs)
    for tid, name in ((A, 'acme'), (B, 'globex')):
        configmanager._true_create_tenant(
            tid, name, configmanager._wrap_tenant_key(os.urandom(32)), 0)
    return {'base': str(tmp_path / 'lib'), 'logs': logs}


# ------------------------------------------------- SSH certificate lifetime

def _configured(monkeypatch, value):
    def get_option(section, name):
        return value if (section, name) == ('tenants', 'sshcert_days') else None
    monkeypatch.setattr(tenantssh.conf, 'get_option', get_option)


def _cert(tid=A):
    hostkey = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    text = tenantssh.sign_host_key(tid, hostkey, 'n1')
    return text, serialization.load_ssh_public_identity(text.encode())


@pytest.mark.skipif(not tenantssh.available(), reason='cryptography without SSH certificates')
def test_ssh_certificates_end_when_a_lifetime_is_set(tenants, monkeypatch, tmp_path):
    _configured(monkeypatch, '30')
    assert tenantssh.lifetime() == 30 * 86400
    now = time.time()
    text, cert = _cert()
    cert.verify_cert_signature()
    assert abs(cert.valid_before - (now + 30 * 86400)) < 60
    assert abs(cert.valid_after - (now - tenantssh.BACKDATE)) < 60
    if shutil.which('ssh-keygen'):
        certfile = tmp_path / 'host-cert.pub'
        certfile.write_text(text)
        shown = subprocess.run(['ssh-keygen', '-L', '-f', str(certfile)], check=True,
                               stdout=subprocess.PIPE).stdout.decode()
        assert 'Valid: from ' in shown and 'forever' not in shown
    _configured(monkeypatch, '0.5')
    assert _cert()[1].valid_before - time.time() < 12 * 3600 + 60


@pytest.mark.skipif(not tenantssh.available(), reason='cryptography without SSH certificates')
@pytest.mark.parametrize('value', [None, '', '0', '-3', 'soon', '1e9', 'nan', 'inf'])
def test_ssh_certificates_have_no_end_otherwise(tenants, monkeypatch, value):
    _configured(monkeypatch, value)
    assert tenantssh.lifetime() is None
    cert = _cert()[1]
    assert (cert.valid_after, cert.valid_before) == (0, 2 ** 64 - 1)


# --------------------------------------------------- what is remembered

def test_what_anyone_can_have_remembered_is_bounded_and_forgotten():
    now = [1000.0]
    store = util.ExpiringStore(lifetime=300, limit=3, clock=lambda: now[0])
    store.put(b'c1', 'alice')
    assert b'c1' in store and len(store) == 1
    # taken once
    assert store.take(b'c1') == 'alice'
    assert store.take(b'c1') is None and b'c1' not in store
    # forgotten after a while
    store.put(b'c2', 'bob')
    now[0] += 299
    assert b'c2' in store
    now[0] += 2
    assert b'c2' not in store and store.take(b'c2') is None and len(store) == 0
    # never more than so many: the oldest make room
    for index in range(10):
        now[0] += 1
        store.put(b'flood%d' % index, None)
    assert len(store) == 3
    assert store.take(b'flood0') is None and b'flood9' in store
    # a value that is None is told apart from nothing by 'in'
    assert store.take(b'flood9', 'missing') is None
    assert store.take(b'flood9', 'missing') == 'missing'
    # asked for again: remembered anew, as the newest
    store.put(b'flood8', 'x')
    now[0] += 1
    store.put(b'new1', 1)
    store.put(b'new2', 2)
    assert b'flood8' in store and b'flood7' not in store


def test_challenges_of_passkey_logins_are_kept_that_way():
    webauthn = pytest.importorskip('webauthn')
    assert webauthn
    import confluent.webauthn as cwebauthn
    assert isinstance(cwebauthn.challenges, util.ExpiringStore)
    assert cwebauthn.challenges.limit <= 4096 and cwebauthn.challenges.lifetime <= 600


# ------------------------------------------------- packages offered for import

def _keys(**changes):
    keys = {'kdf': 'scrypt', 'n': tenantexport.SCRYPT_N, 'r': 8, 'p': 1,
            'salt': base64.b64encode(b's' * 16).decode(), 'packagekey': 'AAAA'}
    keys.update(changes)
    return {'keys.json': json.dumps(keys).encode()}


@pytest.mark.parametrize('changes', [
    {'n': 2}, {'n': 2 ** 13}, {'n': 2 ** 19}, {'n': 2 ** 30}, {'n': 2 ** 17 + 1},
    {'n': -(2 ** 17)}, {'n': 'many'}, {'r': 1024}, {'p': 64},
    {'salt': ''}, {'salt': base64.b64encode(b's' * 4096).decode()}, {'salt': '!!'},
])
def test_a_package_does_not_choose_what_unlocking_it_costs(changes, monkeypatch):
    derived = []
    monkeypatch.setattr(tenantexport, '_derive',
                        lambda *args: derived.append(args) or b'k' * 32)
    with pytest.raises(tenantexport.PackageError):
        tenantexport._unlock(_keys(**changes), 'passphrase')
    assert derived == []  # refused before any work is done


def test_the_work_factor_packages_are_written_with_is_accepted(monkeypatch):
    derived = []
    monkeypatch.setattr(tenantexport, '_derive',
                        lambda *args: derived.append(args) or b'k' * 32)
    for n in (tenantexport.SCRYPT_MIN_N, tenantexport.SCRYPT_N, tenantexport.SCRYPT_MAX_N):
        with pytest.raises(tenantexport.PackageError):  # (the key in it is no key)
            tenantexport._unlock(_keys(n=n), 'passphrase')
    assert [args[2] for args in derived] == [2 ** 14, 2 ** 17, 2 ** 18]


def _package(directory, files, manifest=None):
    os.makedirs(directory)
    listed = {}
    for name, data in files.items():
        with open(os.path.join(directory, name), 'wb') as f:
            f.write(data)
        listed[name] = hashlib.sha256(data).hexdigest()
    with open(os.path.join(directory, 'manifest.json'), 'w') as f:
        json.dump(manifest if manifest is not None else {
            'format': tenantexport.FORMAT, 'version': tenantexport.VERSION,
            'files': listed}, f)
    return directory


def test_a_package_is_read_within_limits(tmp_path, monkeypatch):
    good = _package(str(tmp_path / 'good'), {'a.json': b'{}', 'b.json': b'[]'})
    assert sorted(tenantexport.read(good)) == ['a.json', 'b.json', 'manifest.json']
    many = _package(str(tmp_path / 'many'),
                    dict(('f%d.json' % i, b'{}') for i in range(tenantexport.MAX_FILES + 1)))
    with pytest.raises(tenantexport.PackageError, match='too many'):
        tenantexport.read(many)
    monkeypatch.setattr(tenantexport, 'MAX_FILE_SIZE', 4096)
    big = _package(str(tmp_path / 'big'), {'a.json': b'x' * 5000})
    with pytest.raises(tenantexport.PackageError, match='too large'):
        tenantexport.read(big)
    for index, manifest in enumerate(([], 'x', {'format': tenantexport.FORMAT,
                                                 'version': tenantexport.VERSION, 'files': []})):
        odd = _package(str(tmp_path / ('odd%d' % index)), {}, manifest=manifest)
        with pytest.raises(tenantexport.PackageError):
            tenantexport.read(odd)
    huge = str(tmp_path / 'huge')
    os.makedirs(huge)
    with open(os.path.join(huge, 'manifest.json'), 'wb') as f:
        f.write(b'{"files": {' + b' ' * 5000 + b'}}')
    with pytest.raises(tenantexport.PackageError):
        tenantexport.read(huge)


# ------------------------------------------------ what a deleted tenant leaves

def _trees(tenants, tid):
    made = []
    for root in (tenants['base'], tenants['logs']):
        path = os.path.join(root, 'tenants', tid)
        os.makedirs(os.path.join(path, 'sub'), exist_ok=True)
        with open(os.path.join(path, 'sub', 'file'), 'w') as f:
            f.write('content of ' + tid)
        made.append(path)
    return made


def _mark(tenants, tid):
    marker = os.path.join(tenants['base'], 'tenants', tenantpaths.MARKERS, tid)
    os.makedirs(os.path.dirname(marker), exist_ok=True)
    open(marker, 'w').close()
    return marker


async def _until(cond, timeout=10):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError('timed out')


async def test_deleting_a_tenant_leaves_nothing_and_no_note(tenants):
    kept, gone = _trees(tenants, A), _trees(tenants, B)
    await configmanager.set_tenant_state(B, 'disabled')
    await configmanager.delete_tenant(B)
    await _until(lambda: not any(os.path.exists(path) for path in gone))
    marker = os.path.join(tenants['base'], 'tenants', tenantpaths.MARKERS, B)
    await _until(lambda: not os.path.exists(marker))
    assert all(os.path.exists(path) for path in kept)
    assert tenantpaths.finish_deletions() == []


async def test_an_interrupted_deletion_is_finished_at_the_next_start(tenants, monkeypatch):
    # the service stopped after the tenant was gone from the configuration
    # and before its trees were: a note was left
    kept, left = _trees(tenants, A), _trees(tenants, GONE)
    marker = _mark(tenants, GONE)
    # (in a collective, where not every tenant may be known here yet,
    # only what has such a note is removed)
    monkeypatch.setattr(configmanager, 'list_collective', lambda: iter(['other']))
    stray = _trees(tenants, 't0000000000ee')
    assert tenantpaths.finish_deletions() == [GONE]
    assert not any(os.path.exists(path) for path in left)
    assert not os.path.exists(marker)
    assert all(os.path.exists(path) for path in kept + stray)
    assert tenantpaths.finish_deletions() == []


async def test_trees_of_no_tenant_are_removed_on_a_single_server(tenants):
    kept, stray = _trees(tenants, A), _trees(tenants, 't0000000000ee')
    odd = os.path.join(tenants['base'], 'tenants', 'not-a-tenant')
    os.makedirs(odd)
    assert tenantpaths.finish_deletions() == ['t0000000000ee']
    assert not any(os.path.exists(path) for path in stray)
    assert all(os.path.exists(path) for path in kept)
    assert os.path.isdir(odd)  # (only what is named like a tenant)


async def test_a_note_about_a_tenant_that_exists_deletes_nothing(tenants):
    kept = _trees(tenants, A)
    marker = _mark(tenants, A)
    assert tenantpaths.finish_deletions() == []
    assert all(os.path.exists(path) for path in kept)
    assert not os.path.exists(marker)


async def test_nothing_outside_the_tenant_trees_is_followed(tenants, tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'precious').write_text('keep')
    os.makedirs(os.path.join(tenants['base'], 'tenants'))
    os.symlink(str(outside), os.path.join(tenants['base'], 'tenants', GONE))
    _mark(tenants, GONE)
    tenantpaths.finish_deletions()
    assert (outside / 'precious').read_text() == 'keep'
