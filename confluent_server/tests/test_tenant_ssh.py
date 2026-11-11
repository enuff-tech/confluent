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

"""The SSH certificate authority of a tenant.

Each tenant signs the host keys of its own nodes with an authority of its
own, which is part of its site content; what is signed for one tenant is
nothing to the nodes of another.
"""

import os
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

import confluent.config.configmanager as configmanager
import confluent.discovery.core as disco
import confluent.exceptions as exc
import confluent.networking.tenantnetcfg as netcfg
import confluent.tenantpaths as tenantpaths
import confluent.tenantservices as services
import confluent.tenantsite as tenantsite
import confluent.tenantssh as tenantssh

A = 't00000000000a'
B = 't00000000000b'
OPENSSH = (serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

pytestmark = pytest.mark.skipif(
    not tenantssh.available(), reason='cryptography without SSH certificates')


@pytest.fixture
async def tenants(confluent_config, monkeypatch, tmp_path):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    monkeypatch.setattr(netcfg, 'start', lambda tenant: False)
    monkeypatch.setattr(tenantpaths, 'BASE', str(tmp_path / 'lib'))
    for tid, name in ((A, 'acme'), (B, 'globex')):
        configmanager._true_create_tenant(
            tid, name, configmanager._wrap_tenant_key(os.urandom(32)), 0)
    return str(tmp_path)


def _hostkey(kind='ed25519'):
    if kind == 'rsa':
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif kind == 'ecdsa':
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = ed25519.Ed25519PrivateKey.generate()
    return key.public_key().public_bytes(*OPENSSH)


def _authority(tid):
    return serialization.load_ssh_public_key(tenantssh.ca_public(tid))


def test_each_tenant_has_an_authority_of_its_own(tenants):
    lines = {tid: tenantssh.ca_public(tid) for tid in (A, B)}
    for tid in (A, B):
        assert lines[tid].startswith(b'ssh-ed25519 ') and lines[tid].endswith(b' SSH CA\n')
        assert tid.encode() in lines[tid]
        assert tenantssh.ca_public(tid) == lines[tid]  # the same each time
    assert lines[A].split()[1] != lines[B].split()[1]
    with pytest.raises(ValueError):
        tenantssh.ca_public(None)
    with pytest.raises(exc.NotFoundException):
        tenantssh.ca_public('t00000000000c')
    with pytest.raises(exc.NotFoundException):
        tenantssh.sign_host_key('t00000000000c', _hostkey(), 'n1')


@pytest.mark.parametrize('kind', ['ed25519', 'rsa', 'ecdsa'])
def test_a_host_certificate_names_the_node(tenants, kind):
    public = _hostkey(kind)
    text = tenantssh.sign_host_key(A, public + b' root@n1\n', 'n1', ['n1.example.com', '10.1.2.3', ''])
    assert text.endswith(' n1\n') and '\n' not in text[:-1]
    cert = serialization.load_ssh_public_identity(text.encode())
    cert.verify_cert_signature()
    assert cert.type == serialization.SSHCertificateType.HOST
    assert cert.key_id == b'n1'
    assert cert.valid_principals == [b'10.1.2.3', b'n1', b'n1.example.com']
    assert cert.public_key().public_bytes(*OPENSSH) == public
    assert (cert.valid_after, cert.valid_before) == (0, 2 ** 64 - 1)
    assert not cert.critical_options and not cert.extensions
    # signed by this tenant's authority, and not by the other's
    signer = cert.signature_key().public_bytes(*OPENSSH)
    assert signer == _authority(A).public_bytes(*OPENSSH)
    assert signer != _authority(B).public_bytes(*OPENSSH)
    again = serialization.load_ssh_public_identity(
        tenantssh.sign_host_key(A, public, 'n1').encode())
    assert again.serial != cert.serial
    assert again.valid_principals == [b'n1']


@pytest.mark.parametrize('what', [
    b'', b'   \n', b'not a key', b'ssh-ed25519 AAAA', b'ssh-dss AAAAB3NzaC1kc3M=',
    b'-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----\n',
    b'x' * 20000, None, 7])
def test_only_a_public_key_is_signed(tenants, what):
    with pytest.raises(exc.InvalidArgumentException):
        tenantssh.sign_host_key(A, what, 'n1')


def test_one_key_and_a_bounded_number_of_names(tenants):
    with pytest.raises(exc.InvalidArgumentException, match='One SSH public key'):
        tenantssh.sign_host_key(A, _hostkey() + b'\n' + _hostkey() + b'\n', 'n1')
    with pytest.raises(exc.InvalidArgumentException, match='Too many'):
        tenantssh.sign_host_key(A, _hostkey(), 'n1', ['name%d' % i for i in range(300)])


@pytest.mark.skipif(not shutil.which('ssh-keygen'), reason='needs ssh-keygen')
def test_openssh_takes_the_certificate(tenants, tmp_path):
    certfile = tmp_path / 'ssh_host_ed25519_key-cert.pub'
    certfile.write_text(tenantssh.sign_host_key(A, _hostkey(), 'n1', ['n1.example.com']))
    shown = subprocess.run(['ssh-keygen', '-L', '-f', str(certfile)], check=True,
                           stdout=subprocess.PIPE).stdout.decode()
    assert 'host certificate' in shown
    assert 'Key ID: "n1"' in shown
    assert 'n1.example.com' in shown
    assert 'Valid: forever' in shown
    cafile = tmp_path / 'ca.pub'
    cafile.write_bytes(tenantssh.ca_public(A))
    fingerprint = subprocess.run(['ssh-keygen', '-l', '-f', str(cafile)], check=True,
                                 stdout=subprocess.PIPE).stdout.decode().split()[1]
    assert 'Signing CA: ED25519 ' + fingerprint in shown


def test_the_authority_follows_the_tenants_key_not_the_disk(tenants):
    # nothing of it is stored: it is derived from what the tenant's secrets
    # are encrypted with
    before = tenantssh.ca_public(A)
    for current, _, files in os.walk(tenants):
        for name in files:
            with open(os.path.join(current, name), 'rb') as f:
                assert b'OPENSSH PRIVATE KEY' not in f.read()
    assert tenantssh.ca_public(A) == before


async def test_the_authority_is_part_of_the_site_content(tenants):
    for tid in (A, B):
        site = await tenantsite.ensure(tid)
        assert os.listdir(os.path.join(site, 'ssh')) == [tid + '.ca']
        with open(os.path.join(site, 'ssh', tid + '.ca'), 'rb') as f:
            assert f.read() == tenantssh.ca_public(tid)
        # and of what the boot images of the tenant carry
        with open(os.path.join(site, 'initramfs.cpio'), 'rb') as f:
            packed = f.read()
        assert ('ssh/' + tid + '.ca').encode() in packed
        assert tenantssh.ca_public(tid) in packed
        other = B if tid == A else A
        assert tenantssh.ca_public(other).split()[1] not in packed
