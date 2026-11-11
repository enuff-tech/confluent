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

"""Where deployment content lives, for each tenant.

The default tenant keeps /var/lib/confluent/public and .../private exactly
as before. Every other tenant has trees of its own:

    /var/lib/confluent/tenants/<tenant id>/public    (served to its nodes)
    /var/lib/confluent/tenants/<tenant id>/private   (to authenticated nodes)

laid out like the default ones (os/<profile>/..., site/...). A tenant's
nodes are only ever served from its own trees. They are deleted, like the
tenant's logs, when the tenant is.
"""

import asyncio
import os

import confluent.config.configmanager as configmanager
import confluent.log as log

BASE = '/var/lib/confluent'


def _root(tenant, kind):
    if tenant is None:
        return os.path.join(BASE, kind)
    if not configmanager.valid_tenant_id(tenant):
        raise ValueError('invalid tenant id')
    return os.path.join(BASE, 'tenants', tenant, kind)


def base(tenant):
    """The directory all of a tenant's deployment trees are under (the
    whole of /var/lib/confluent for the default tenant)."""
    if tenant is None:
        return BASE
    if not configmanager.valid_tenant_id(tenant):
        raise ValueError('invalid tenant id')
    return os.path.join(BASE, 'tenants', tenant)


def public_root(tenant):
    return _root(tenant, 'public')


def distributions_root(tenant):
    """Imported OS media, which profiles link to."""
    return _root(tenant, 'distributions')


def media_root(tenant):
    """Where a tenant's OS media wait to be imported."""
    return _root(tenant, 'media')


# Product content every installation has, the same for all tenants, which
# profiles link to (boot environments, stock profile parts, boot loaders).
SHARED_ROOTS = ('/opt/confluent/genesis', '/opt/confluent/lib/osdeploy',
                '/opt/confluent/lib/ipxe')


def content_roots(tenant):
    """Where a file served as the tenant's public content may really
    be: its public tree, the media it imported, and product content."""
    return (distributions_root(tenant),) + SHARED_ROOTS


def private_root(tenant):
    return _root(tenant, 'private')


def public_path(tenant, *parts):
    """A path below the tenant's public tree (as the default tenant's code
    spells /var/lib/confluent/public/...)."""
    return os.path.join(public_root(tenant), *parts)


def remove_tenant(tenant):
    """Delete a tenant's deployment trees (and nothing else: the path is
    derived from the validated id and removed without following links)."""
    configmanager._remove_tenant_directory(BASE, tenant)


def _tenant_state_changed(tenant, state):
    if state != 'deleted':
        return
    # what was kept for the tenant on disk goes with it: its logs, and
    # its deployment content
    log.remove_tenant(tenant)
    try:
        # images are large: off the event loop
        asyncio.get_running_loop().run_in_executor(None, remove_tenant, tenant)
    except RuntimeError:
        remove_tenant(tenant)


configmanager.watch_tenant_state(_tenant_state_changed)


def contained_file(root, relative, also=()):
    """The real path of a regular file below root, or None.

    Nothing outside root is ever returned: not through '..', and not
    through a symbolic link that leaves the tree (so a tenant's tree
    cannot be made to serve another tenant's files, or the host's). A
    link may lead into one of the trees given as also (see content_roots).
    """
    if '\x00' in relative:
        return None
    realroot = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(realroot, relative.lstrip('/')))
    # the name asked for is always below root; only where it really is
    # may be in one of the other trees
    if not os.path.normpath(os.path.join(realroot, relative.lstrip('/'))).startswith(
            os.path.join(realroot, '')):
        return None
    allowed = [realroot] + [os.path.realpath(other) for other in also]
    if not any(candidate.startswith(os.path.join(tree, '')) for tree in allowed):
        return None
    if not os.path.isfile(candidate):
        return None
    return candidate
