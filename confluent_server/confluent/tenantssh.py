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

Each tenant has an authority of its own that signs the host keys of its
nodes (/self/sshcert), so that the nodes of a tenant recognize each other
and nothing signed for one tenant is trusted by the nodes of another. Its
public key is part of the tenant's site content (site/ssh/<tenant>.ca).

A certificate is valid without an end unless a lifetime is set, as the
authority of the installation signs them (a node asks for one when it is
deployed, and does not ask again by itself):

    [tenants]                      (in /etc/confluent/service.cfg)
    sshcert_days = 400             a certificate is valid this long

The authority's key is derived from the key the tenant's secrets are
encrypted with: it is nowhere on disk, is the same on every collective
member, and is gone with the tenant. Certificates are made in the service
itself (no ssh-keygen, no agent: a tenant's task starts no process).
"""

import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import confluent.config.conf as conf
import confluent.config.configmanager as configmanager
import confluent.exceptions as exc

PURPOSE = b'confluent-tenant-ssh-ca'
FOREVER = 2 ** 64 - 1
MAX_KEY = 16384
MAX_PRINCIPALS = 256
BACKDATE = 300  # (clocks of nodes are not exact)


def lifetime():
    """How long a certificate is valid, in seconds, or None: without end."""
    try:
        days = float(conf.get_option('tenants', 'sshcert_days'))
    except Exception:
        return None
    if not 0 < days < 36500:
        return None
    return int(days * 86400)


def available():
    """Whether certificates can be made here (cryptography 40 or later)."""
    return hasattr(serialization, 'SSHCertificateBuilder')


def _key(tenant):
    if tenant is None:
        raise ValueError('the default tenant has the SSH authority of the installation')
    if configmanager.get_tenant(tenant) is None:
        raise exc.NotFoundException('No such tenant')
    seed = configmanager.ConfigManager(tenant).derive_secret(PURPOSE)
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def ca_public(tenant):
    """The authority's public key, as a line of OpenSSH (bytes)."""
    public = _key(tenant).public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return public + b' confluent tenant ' + tenant.encode() + b' SSH CA\n'


def _host_key(pubkey):
    if isinstance(pubkey, str):
        pubkey = pubkey.encode()
    if not isinstance(pubkey, bytes) or not pubkey.strip() or len(pubkey) > MAX_KEY:
        raise exc.InvalidArgumentException('Not an SSH public key')
    lines = [line for line in pubkey.splitlines() if line.strip()]
    if len(lines) != 1:
        raise exc.InvalidArgumentException('One SSH public key is signed at a time')
    try:
        return serialization.load_ssh_public_key(lines[0].strip())
    except Exception:
        raise exc.InvalidArgumentException('Not an SSH public key')


def sign_host_key(tenant, pubkey, nodename, principals=()):
    """A host certificate for a node's public key: the text of the
    certificate, naming the node and whatever else it is known as."""
    if not available():
        raise exc.NotImplementedException(
            'SSH certificates for tenants need a newer cryptography library')
    names = set(str(name) for name in principals if name)
    names.add(nodename)
    if len(names) > MAX_PRINCIPALS:
        raise exc.InvalidArgumentException('Too many names for one certificate')
    valid = lifetime()
    now = int(time.time())
    builder = (
        serialization.SSHCertificateBuilder()
        .public_key(_host_key(pubkey))
        .serial(int.from_bytes(os.urandom(8), 'big') >> 1)
        .type(serialization.SSHCertificateType.HOST)
        .key_id(nodename.encode('utf8'))
        .valid_principals([name.encode('utf8') for name in sorted(names)]))
    if valid:
        builder = builder.valid_after(now - BACKDATE).valid_before(now + valid)
    else:
        # (as the authority of the installation does: without an end)
        builder = builder.valid_after(0).valid_before(FOREVER)
    certificate = builder.sign(_key(tenant))
    return certificate.public_bytes().decode('ascii') + ' ' + nodename + '\n'
