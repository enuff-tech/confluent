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

"""The site content of a tenant's deployment tree.

What `osdeploy initialize` prepares for the default tenant under
/var/lib/confluent/public/site, each tenant has under its own tree: the
identity of the service as its nodes know it, the certificate authorities
its nodes are to trust (the tenant's own, never the service's), and both
packed as the "site" part of the boot images (initramfs.cpio, and
initramfs.tgz for the systems that take a tar file).

It is built by the service itself, without starting a process, whenever
the tenant's nodes begin to be served and before anything is imported.
"""

import io
import os
import shutil
import tarfile

import confluent.config.configmanager as configmanager
import confluent.tenantca as tenantca
import confluent.tenantpaths as tenantpaths
import confluent.tenantssh as tenantssh

IPXE_SOURCE = '/opt/confluent/lib/ipxe'
IPXE_FILES = ('ipxe-shim.efi', 'ipxe.efi', 'ipxe-aarch64-shim.efi', 'ipxe-aarch64.efi')


def _write(path, data, mode=0o644):
    """Write a file other accounts may read (it is served to nodes)."""
    tmp = path + '.new'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _mkdir(path):
    os.makedirs(path, mode=0o755, exist_ok=True)
    os.chmod(path, 0o755)


def _cpio_entry(name, mode, data, inode):
    name = name.encode() + b'\0'
    header = '070701' + ''.join('%08X' % field for field in (
        inode, mode, 0, 0, 2 if mode & 0o040000 else 1, 0, len(data),
        0, 0, 0, 0, len(name), 0))
    entry = header.encode() + name
    entry += b'\0' * (-len(entry) % 4)
    entry += data
    entry += b'\0' * (-len(entry) % 4)
    return entry


def pack_cpio(root, names):
    """A "newc" cpio archive of the named files and directories of root
    (as `cpio -H newc -o` writes it)."""
    archive = b''
    inode = 1
    for name in names:
        path = os.path.join(root, name)
        if os.path.isdir(path):
            archive += _cpio_entry(name.rstrip('/'), 0o040755, b'', inode)
        else:
            with open(path, 'rb') as f:
                archive += _cpio_entry(name, 0o100644, f.read(), inode)
        inode += 1
    archive += _cpio_entry('TRAILER!!!', 0, b'', 0)
    return archive + b'\0' * (-len(archive) % 512)


def _members(sitedir):
    """What goes into the site part of the boot images, in order."""
    names = ['confluent_uuid']
    for sub in ('ssh', 'tls'):
        if os.path.isdir(os.path.join(sitedir, sub)):
            names.append(sub + '/')
            for current, _, files in os.walk(os.path.join(sitedir, sub)):
                for fname in sorted(files):
                    names.append(os.path.relpath(os.path.join(current, fname), sitedir))
    return names


async def ensure(tenant):
    """Create or refresh the site content of a tenant's deployment tree;
    returns its directory."""
    if tenant is None:
        raise ValueError('the site content of the default tenant is made by osdeploy')
    public = tenantpaths.public_root(tenant)
    sitedir = os.path.join(public, 'site')
    for path in (tenantpaths.base(tenant), public, sitedir, os.path.join(sitedir, 'tls'),
                 os.path.join(public, 'os'), tenantpaths.distributions_root(tenant)):
        _mkdir(path)
    for path in (tenantpaths.private_root(tenant), tenantpaths.media_root(tenant)):
        os.makedirs(path, mode=0o700, exist_ok=True)
    cfm = configmanager.ConfigManager(tenant)
    _write(os.path.join(sitedir, 'confluent_uuid'), (cfm.service_uuid() + '\n').encode())
    # the one authority this tenant's nodes trust for their server
    _write(os.path.join(sitedir, 'tls', tenant + '.pem'), await tenantca.ca_pem(tenant))
    if tenantssh.available():
        # and the one that signs the SSH host keys of its nodes
        _mkdir(os.path.join(sitedir, 'ssh'))
        _write(os.path.join(sitedir, 'ssh', tenant + '.ca'), tenantssh.ca_public(tenant))
    names = _members(sitedir)
    _write(os.path.join(sitedir, 'initramfs.cpio'), pack_cpio(sitedir, names))
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode='w:gz') as tar:
        for name in ('confluent_uuid', 'ssh', 'tls'):
            if os.path.exists(os.path.join(sitedir, name)):
                tar.add(os.path.join(sitedir, name), arcname=name)
    _write(os.path.join(sitedir, 'initramfs.tgz'), packed.getvalue())
    # the boot loader offered for HTTP boot, as osdeploy copies it
    for name in IPXE_FILES:
        source = os.path.join(IPXE_SOURCE, name)
        target = os.path.join(public, 'ipxe', name)
        if os.path.exists(source) and not os.path.exists(target):
            _mkdir(os.path.join(public, 'ipxe'))
            shutil.copy(source, target)
            os.chmod(target, 0o644)
    return sitedir
