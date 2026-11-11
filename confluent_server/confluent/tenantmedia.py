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

"""OS installation media a tenant uploads to import.

A tenant administrator sends media to /deployment/media/<name>; it is
kept in the tenant's media directory (readable by the service only) until
imported or deleted. What a tenant can store there is bounded: by the size
of one file, by the total it may keep, and by the space that must stay
free on the volume for everything else.

    [tenants]                      (in /etc/confluent/service.cfg)
    media_max_gb = 16              largest single media file
    media_quota_gb = 64            total a tenant may keep waiting
    media_reserve_gb = 20          space the volume must keep free
"""

import asyncio
import os
import re
import shutil

import confluent.config.conf as conf
import confluent.exceptions as exc
import confluent.tenantpaths as tenantpaths

GIB = 2 ** 30
DEFAULTS = {'media_max_gb': 16, 'media_quota_gb': 64, 'media_reserve_gb': 20}
CHUNK = 1 << 20
# one path component, nothing a shell or a listing would trip on
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$')


class TooLarge(exc.InvalidArgumentException):
    """More than the tenant may store."""
    apierrorcode = 413
    _apierrorstr = 'Payload Too Large'


def limit(name):
    """One of the limits above, in bytes."""
    try:
        configured = conf.get_option('tenants', name)
    except Exception:
        configured = None
    try:
        value = float(configured) if configured is not None else DEFAULTS[name]
    except ValueError:
        value = DEFAULTS[name]
    return int(value * GIB)


def media_name(name):
    if not isinstance(name, str) or not NAME_RE.match(name) or name.endswith('.part'):
        raise exc.InvalidArgumentException(
            'A media name is letters, digits and . _ + - (not starting with a dot)')
    return name


def _directory(tenant):
    if tenant is None:
        raise exc.NotFoundException('Media are uploaded within a tenant')
    directory = tenantpaths.media_root(tenant)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    return directory


def listing(tenant):
    """The media a tenant has waiting: {name: size}."""
    directory = _directory(tenant)
    found = {}
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if NAME_RE.match(name) and not name.endswith('.part') and \
                os.path.isfile(path) and not os.path.islink(path):
            found[name] = os.path.getsize(path)
    return found


def used(tenant):
    """Bytes in the tenant's media directory, unfinished uploads included."""
    directory = _directory(tenant)
    total = 0
    for name in os.listdir(directory):
        try:
            total += os.lstat(os.path.join(directory, name)).st_size
        except OSError:
            pass
    return total


def remove(tenant, name):
    path = os.path.join(_directory(tenant), media_name(name))
    if os.path.islink(path) or not os.path.isfile(path):
        raise exc.NotFoundException('No such media')
    os.unlink(path)


async def receive(tenant, name, stream, length):
    """Store an upload of exactly length bytes as the tenant's media name.

    Refused before a byte is read when it could not be kept; nothing is
    left behind when it fails or is cut short.
    """
    directory = _directory(tenant)
    name = media_name(name)
    target = os.path.join(directory, name)
    if length is None or length <= 0:
        raise exc.InvalidArgumentException('The size of the media must be given (Content-Length)')
    if os.path.lexists(target):
        raise exc.InvalidArgumentException('Media {0} already exists'.format(name))
    if length > limit('media_max_gb'):
        raise TooLarge('The media is larger than a tenant may upload')
    if used(tenant) + length > limit('media_quota_gb'):
        raise TooLarge('The tenant has no room for this media: delete or import what is waiting')
    if shutil.disk_usage(directory).free - length < limit('media_reserve_gb'):
        raise TooLarge('There is not enough space for this media')
    partial = target + '.part'
    loop = asyncio.get_running_loop()
    received = 0
    try:
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise exc.InvalidArgumentException('Media {0} is being uploaded'.format(name))
    try:
        # (its announced size counts against the tenant from now on)
        os.ftruncate(fd, length)
        with os.fdopen(fd, 'wb') as out:
            while True:
                chunk = await stream.read(CHUNK)
                if not chunk:
                    break
                received += len(chunk)
                if received > length:
                    raise TooLarge('More was sent than announced')
                await loop.run_in_executor(None, out.write, chunk)
        if received != length:
            raise exc.InvalidArgumentException('The upload was cut short')
        os.replace(partial, target)
    finally:
        if os.path.lexists(partial):
            os.unlink(partial)
    return received
