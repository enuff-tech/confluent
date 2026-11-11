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

"""OS images and deployment profiles of a tenant.

A tenant imports media from its own media directory into its own trees,
gets profiles that link to its own site content, and builds their boot
files; the tools this takes run as the service itself (a tenant's task
starts no process) and act on that tenant's tree only.
"""

import asyncio
import io
import json
import os
import tarfile

import pytest
import yaml

import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.discovery.core as disco
import confluent.exceptions as exc
import confluent.networking.tenantnetcfg as netcfg
import confluent.osimage as osimage
import confluent.tenantca as tenantca
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
import confluent.tenantpaths as tenantpaths
import confluent.tenantservices as services
import confluent.tenantsite as tenantsite
import confluent.util as util

A = 't00000000000a'
B = 't00000000000b'
OSNAME = 'rocky-9.4-x86_64'


def _create(tid, name):
    configmanager._true_create_tenant(
        tid, name, configmanager._wrap_tenant_key(os.urandom(32)), 0)


async def _until(cond, timeout=10):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError('timed out')


def _write(path, data=b''):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)


class FakeWorker(object):
    """The media extraction process, which these tests do not run."""
    returncode = 0

    class stdout(object):
        @staticmethod
        async def read(count):
            return b''

    async def wait(self):
        return 0

    def kill(self):
        pass


class IdentifyWorker(FakeWorker):
    """The process that reads what a tenant's media is."""

    def __init__(self, output):
        self.output = output

    async def communicate(self):
        return self.output, None


@pytest.fixture
async def images(confluent_config, monkeypatch, tmp_path):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    configmanager.set_global('confluent_uuid', 'the-hosts-own-uuid')
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    monkeypatch.setattr(netcfg, 'start', lambda tenant: False)
    base = str(tmp_path / 'lib')
    monkeypatch.setattr(tenantpaths, 'BASE', base)
    monkeypatch.setattr(osimage, 'STOCK_BASE', '/var/lib/confluent')
    # packaged profile content, as confluent_osdeploy installs it
    templates = str(tmp_path / 'osdeploy')
    monkeypatch.setattr(osimage, 'TEMPLATE_ROOT', templates)
    monkeypatch.setattr(tenantpaths, 'SHARED_ROOTS', (templates,))
    _write(os.path.join(templates, 'el9/profiles/default/profile.yaml'),
           b'label: %%DISTRO%% %%VERSION%% %%ARCH%% (Default Profile)\nkernelargs: quiet\n')
    _write(os.path.join(templates, 'el9/profiles/default/initprofile.sh'), b'#!/bin/sh\n')
    _write(os.path.join(templates, 'el9/profiles/default/scripts/post.sh'), b'# stock\n')
    _write(os.path.join(templates, 'el9/initramfs/addons.cpio'), b'addons')
    ran = []

    async def check_call(*cmd, **kwargs):
        if len(cmd) == 1 and isinstance(cmd[0], (list, tuple)):
            cmd = tuple(cmd[0])
        ran.append((tenantguard.current_tenant.get(), tenantnet.current_network(), cmd))

    identified = []

    async def spawn(*args, **kwargs):
        if args[3:4] == ('--identify',):
            identified.append((tenantguard.current_tenant.get(), args[2],
                               kwargs.get('preexec_fn')))
            found = osimage.fingerprint(None)
            return IdentifyWorker(json.dumps(found[0] if found else None).encode())
        ran.append((tenantguard.current_tenant.get(), tenantnet.current_network(),
                    ('worker',) + tuple(args[2:]), kwargs.get('env', {}).get('CONFLUENT_IMAGE_BASE')))
        # what the worker does: unpack the media into the distribution
        _write(os.path.join(args[4], 'distinfo.yaml'), b'name: ' + OSNAME.encode())
        _write(os.path.join(args[4], 'images/pxeboot/vmlinuz'), b'kernel')
        return FakeWorker()
    monkeypatch.setattr(util, 'check_call', check_call)
    monkeypatch.setattr(osimage.asyncio, 'create_subprocess_exec', spawn)
    monkeypatch.setattr(osimage, 'fingerprint', lambda archive: (
        {'name': OSNAME, 'method': osimage.EXTRACT, 'category': 'el9'}, None, 'rocky'))
    for tid, name in ((A, 'acme'), (B, 'globex')):
        _create(tid, name)
    # (the workers are stand-ins here: whatever the host running the tests
    # provides, they count as confined)
    import confluent.sandbox as sandbox
    monkeypatch.setattr(sandbox, '_supported', [('limits', 'namespaces', 'landlock')])
    monkeypatch.setattr(sandbox, 'policy', lambda: 'default')
    yield {'base': base, 'templates': templates, 'ran': ran, 'identified': identified}
    tenantnet.enter(None)


async def _as(tid, path, operation='retrieve', inputdata=None):
    tenantnet.enter(tid)
    try:
        result = core.handle_path(path, operation, configmanager.ConfigManager(tid), inputdata)
        if asyncio.iscoroutine(result):
            result = await result
        if hasattr(result, '__aiter__'):
            result = [r async for r in result]
        return [r.href if hasattr(r, 'href') else getattr(r, 'kvpairs', r) for r in result]
    finally:
        tenantnet.enter(None)


def _cpio_names(data):
    names, pos = {}, 0
    while pos < len(data):
        assert data[pos:pos + 6] == b'070701', pos
        fields = [int(data[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        size, namesize = fields[6], fields[11]
        name = data[pos + 110:pos + 110 + namesize - 1].decode()
        start = (pos + 110 + namesize + 3) & ~3
        if name == 'TRAILER!!!':
            break
        names[name] = data[start:start + size]
        pos = (start + size + 3) & ~3
    return names


async def _import(tid, name='rocky.iso', **more):
    _write(os.path.join(tenantpaths.media_root(tid), name), b'media of ' + tid.encode())
    started = (await _as(tid, '/deployment/importing/', 'create', dict(filename=name, **more)))[0]
    key = started['name']['value'] if isinstance(started['name'], dict) else started['name']
    await _until(lambda: osimage.importing.for_tenant(tid)[key].phase in ('complete', 'error'))
    assert osimage.importing.for_tenant(tid)[key].error == ''
    return key


# ------------------------------------------------------------- site content

async def test_site_content_is_the_tenants_own(images):
    sites = {tid: await tenantsite.ensure(tid) for tid in (A, B)}
    for tid in (A, B):
        site = sites[tid]
        assert site == os.path.join(images['base'], 'tenants', tid, 'public', 'site')
        with open(os.path.join(site, 'confluent_uuid')) as f:
            assert f.read().strip() == configmanager.ConfigManager(tid).service_uuid()
        with open(os.path.join(site, 'tls', tid + '.pem'), 'rb') as f:
            authority = f.read()
        assert authority == await tenantca.ca_pem(tid)
        # packed for the boot images as osdeploy packs the default tenant's
        with open(os.path.join(site, 'initramfs.cpio'), 'rb') as f:
            packed = f.read()
        assert len(packed) % 512 == 0
        names = _cpio_names(packed)
        assert list(names) == [
            'confluent_uuid', 'ssh', 'ssh/' + tid + '.ca', 'tls', 'tls/' + tid + '.pem']
        assert names['tls/' + tid + '.pem'] == authority
        with open(os.path.join(site, 'initramfs.tgz'), 'rb') as f:
            tar = tarfile.open(fileobj=io.BytesIO(f.read()))
        assert tar.extractfile('tls/' + tid + '.pem').read() == authority
        assert tar.extractfile('confluent_uuid').read().decode().strip() != 'the-hosts-own-uuid'
        # what nodes fetch is readable, what they must not see is not
        assert os.stat(site).st_mode & 0o777 == 0o755
        for private in (tenantpaths.private_root(tid), tenantpaths.media_root(tid)):
            assert os.stat(private).st_mode & 0o077 == 0
    with open(os.path.join(sites[A], 'tls', A + '.pem'), 'rb') as a, \
            open(os.path.join(sites[B], 'tls', B + '.pem'), 'rb') as b:
        assert a.read() != b.read()
    with pytest.raises(ValueError):
        await tenantsite.ensure(None)


def test_paths_follow_the_tenant_being_worked_for(images):
    stock = '/var/lib/confluent/public/os/p1'
    assert osimage._p(stock) == os.path.join(images['base'], 'public/os/p1')
    tenantnet.enter(A)
    assert osimage._p(stock) == os.path.join(images['base'], 'tenants', A, 'public/os/p1')
    assert osimage.image_base() == tenantpaths.base(A)
    tenantnet.enter(None)
    for bad in ('', '.', '..', 'a/b', '../x', 'a\x00b', None, 5):
        with pytest.raises(exc.InvalidArgumentException):
            osimage.safe_name(bad)


# ------------------------------------------------------------------ import

async def test_import_goes_into_the_tenants_own_trees(images):
    key = await _import(A)
    assert key == OSNAME
    base = tenantpaths.base(A)
    profile = os.path.join(base, 'public/os', OSNAME + '-default')
    assert sorted(os.listdir(os.path.join(base, 'distributions'))) == [OSNAME]
    assert os.path.exists(os.path.join(profile, 'manifest.yaml'))
    with open(os.path.join(profile, 'profile.yaml')) as f:
        assert yaml.safe_load(f)['label'] == 'rocky 9.4 x86_64 (Default Profile)'
    # the profile links to the tenant's own media and site content
    assert os.readlink(os.path.join(profile, 'distribution')) == \
        os.path.join(base, 'distributions', OSNAME)
    assert os.readlink(os.path.join(profile, 'boot/initramfs/site.cpio')) == \
        os.path.join(base, 'public/site/initramfs.cpio')
    assert os.path.exists(os.path.join(base, 'public/site/initramfs.cpio'))
    # through the API: this tenant's, and nobody else's
    assert await _as(A, '/deployment/distributions/') == [OSNAME + '/']
    assert await _as(A, '/deployment/profiles/') == [OSNAME + '-default/']
    info = (await _as(A, '/deployment/profiles/' + OSNAME + '-default/info'))[0]
    assert info['name'] == OSNAME + '-default'
    for other in (B, None):
        assert await _as(other, '/deployment/profiles/') == []
        assert await _as(other, '/deployment/distributions/') == []
        assert await _as(other, '/deployment/importing/') == []
    assert await _as(A, '/deployment/importing/') == [OSNAME]
    assert not os.path.exists(os.path.join(images['base'], 'public'))
    assert not os.path.exists(os.path.join(images['base'], 'distributions'))
    # every tool ran as the service itself, on tenant a's tree
    assert images['ran'], 'nothing ran'
    for entry in images['ran']:
        assert entry[0] is None and entry[1] is None, entry
    worker = [e for e in images['ran'] if e[2][0] == 'worker'][0]
    assert worker[3] == base
    assert worker[2][1] == os.path.join(base, 'media', 'rocky.iso')
    assert worker[2][3] == os.path.join(base, 'distributions', OSNAME)
    tools = [e[2] for e in images['ran'] if e[2][0] != 'worker']
    assert ('sh', os.path.join(profile, 'initprofile.sh'),
            os.path.join(base, 'distributions', OSNAME), profile) in tools
    assert any(cmd[0].endswith('dir2img') and cmd[1] == profile + '/boot' for cmd in tools)


async def test_two_tenants_import_the_same_media_name(images):
    await _import(A)
    await _import(B)
    for tid in (A, B):
        profile = os.path.join(tenantpaths.base(tid), 'public/os', OSNAME + '-default')
        assert os.path.realpath(os.path.join(profile, 'distribution')).startswith(
            tenantpaths.base(tid) + os.sep)
        assert await _as(tid, '/deployment/profiles/') == [OSNAME + '-default/']
    # the same media again in the same tenant is refused, as it is without tenants
    _write(os.path.join(tenantpaths.media_root(A), 'again.iso'))
    with pytest.raises(Exception, match='already'):
        await _as(A, '/deployment/importing/', 'create', {'filename': 'again.iso'})


async def test_media_is_only_ever_the_tenants_own(images):
    await tenantsite.ensure(A)
    await tenantsite.ensure(B)
    _write(os.path.join(tenantpaths.media_root(B), 'only-b.iso'), b'x')
    hostfile = os.path.join(images['base'], 'host.iso')
    _write(hostfile, b'x')
    os.symlink(hostfile, os.path.join(tenantpaths.media_root(A), 'link.iso'))
    for name in (hostfile, '/etc/hostname', '../../host.iso', 'only-b.iso',
                 '../' + B + '/media/only-b.iso', 'link.iso', 'missing.iso', '', '.'):
        with pytest.raises(exc.InvalidArgumentException):
            await _as(A, '/deployment/importing/', 'create', {'filename': name})
        with pytest.raises(exc.InvalidArgumentException):
            await _as(A, '/deployment/fingerprint/', 'create', {'filename': name})
    assert not [e for e in images['ran'] if e[2][0] == 'worker']
    # nor a name that would leave its trees
    _write(os.path.join(tenantpaths.media_root(A), 'ok.iso'), b'x')
    for custom in ('../escape', 'a/b', '..'):
        with pytest.raises(exc.InvalidArgumentException):
            await _as(A, '/deployment/importing/', 'create',
                      {'filename': 'ok.iso', 'custname': custom})
    assert osimage.tenant_media(B, 'only-b.iso').endswith('/media/only-b.iso')


async def test_a_tenants_media_is_read_by_a_limited_worker(images, monkeypatch):
    await _import(A)
    # found out by a process of the service, limited, not within the tenant
    media = os.path.join(tenantpaths.media_root(A), 'rocky.iso')
    (tenant, named, confined), = images['identified']
    assert (tenant, named) == (None, media)
    # confined to reading that media, and writing nothing
    assert media in confined.read and confined.write == ()
    spawned = []
    real = osimage.asyncio.create_subprocess_exec

    async def spawn(*args, **kwargs):
        spawned.append(kwargs)
        return await real(*args, **kwargs)
    monkeypatch.setattr(osimage.asyncio, 'create_subprocess_exec', spawn)
    await _import(B)
    identify, unpack = spawned
    media = os.path.join(tenantpaths.media_root(B), 'rocky.iso')
    assert media in identify['preexec_fn'].read and identify['preexec_fn'].write == ()
    # the one that unpacks may write that tenant's distributions, only
    assert media in unpack['preexec_fn'].read
    assert unpack['preexec_fn'].write == (tenantpaths.distributions_root(B),)
    # and neither holds the files the service has open
    assert identify['close_fds'] is True and unpack['close_fds'] is True
    for kwargs in spawned:
        assert not [p for p in kwargs['preexec_fn'].read + kwargs['preexec_fn'].write
                    if p.startswith(tenantpaths.base(A))]


@pytest.mark.parametrize('identity', [
    {'name': '../../../escape'}, {'name': 'a/b'}, {'name': '..'}, {'name': ''},
    {'name': '.hidden'}, {'name': 'x' * 65}, {'name': 7}, {},
    {'name': 'rocky-9.4-x86_64', 'subname': '../1'},
    {'name': 'rocky-9.4-x86_64', 'category': '../../../../etc'},
    {'name': 'rocky-9.4-x86_64', 'category': 'el9/../../x'},
    ['rocky-9.4-x86_64'], 'rocky-9.4-x86_64',
])
async def test_what_media_calls_itself_is_held_to_plain_names(images, monkeypatch, identity):
    # the names media gives itself become directories of the tenant
    if isinstance(identity, dict):
        identity = dict(identity, method=osimage.EXTRACT)
    monkeypatch.setattr(osimage, 'fingerprint', lambda archive: (identity, None, 'rocky'))
    await tenantsite.ensure(A)
    _write(os.path.join(tenantpaths.media_root(A), 'odd.iso'), b'x')
    with pytest.raises(exc.InvalidArgumentException, match='Unsupported Media'):
        await _as(A, '/deployment/importing/', 'create', {'filename': 'odd.iso'})
    with pytest.raises(exc.InvalidArgumentException):
        await _as(A, '/deployment/fingerprint/', 'create', {'filename': 'odd.iso'})
    assert not [e for e in images['ran'] if e[2][0] == 'worker']
    assert await _as(A, '/deployment/distributions/') == []


async def test_ready_made_profiles_are_not_imported_within_a_tenant(images, monkeypatch):
    # an archive of a profile brings scripts and a manifest of its own
    monkeypatch.setattr(osimage, 'fingerprint', lambda archive: (
        {'name': 'custom-profile', 'distribution': False, 'method': osimage.UTAR}, None, None))
    await tenantsite.ensure(A)
    _write(os.path.join(tenantpaths.media_root(A), 'profile.tar'), b'x')
    with pytest.raises(exc.InvalidArgumentException, match='installation media'):
        await _as(A, '/deployment/importing/', 'create', {'filename': 'profile.tar'})
    assert await _as(A, '/deployment/profiles/') == []


# ------------------------------------------------------- boot files, rebase

async def test_boot_files_are_built_in_the_tenants_tree(images):
    await _import(A)
    await _import(B)
    del images['ran'][:]
    name = OSNAME + '-default'
    profile = os.path.join(tenantpaths.base(A), 'public/os', name)
    os.unlink(os.path.join(profile, 'boot.ipxe'))
    other = os.path.join(tenantpaths.base(B), 'public/os', name, 'boot.ipxe')
    before = os.stat(other).st_mtime_ns
    assert await _as(A, '/deployment/profiles/' + name, 'update', {'updateboot': 1}) == [
        {'updated': name}]
    with open(os.path.join(profile, 'boot.ipxe')) as f:
        assert 'imgfetch boot/kernel quiet' in f.read()
    assert os.stat(other).st_mtime_ns == before
    assert [e[2][1] for e in images['ran']] == [profile + '/boot']
    assert all(e[0] is None for e in images['ran'])
    for bad in ('..', 'no-such-profile'):
        with pytest.raises((exc.InvalidArgumentException, exc.NotFoundException, OSError)):
            await _as(A, '/deployment/profiles/' + bad, 'update', {'updateboot': 1})


async def test_rebase_only_copies_from_packaged_content(images):
    await _import(A)
    name = OSNAME + '-default'
    profile = os.path.join(tenantpaths.base(A), 'public/os', name)
    # packaged content was updated: rebase brings it in
    _write(os.path.join(images['templates'], 'el9/profiles/default/scripts/post.sh'), b'# newer\n')
    result = await _as(A, '/deployment/profiles/' + name, 'update', {'rebase': 1})
    assert {'updated': 'scripts/post.sh'} in result
    with open(os.path.join(profile, 'scripts/post.sh'), 'rb') as f:
        assert f.read() == b'# newer\n'
    # a manifest naming anything else is not followed
    secret = os.path.join(images['base'], 'host-secrets')
    _write(os.path.join(secret, 'key.pem'), b'a secret of the host')
    with open(os.path.join(profile, 'manifest.yaml')) as f:
        manifest = yaml.safe_load(f)
    for distdir in (secret, '/etc', os.path.join(images['templates'], '..', 'lib', 'host-secrets'),
                    tenantpaths.base(B)):
        manifest['distdir'] = distdir
        with open(os.path.join(profile, 'manifest.yaml'), 'w') as f:
            yaml.safe_dump(manifest, f)
        with pytest.raises(exc.InvalidArgumentException):
            await _as(A, '/deployment/profiles/' + name, 'update', {'rebase': 1})
    assert not os.path.exists(os.path.join(profile, 'key.pem'))


# ------------------------------------------------------------------ serving

async def test_profile_content_is_served_from_the_tenants_trees(images):
    await _import(A)
    await _import(B)
    public = tenantpaths.public_root(A)
    name = OSNAME + '-default'
    also = tenantpaths.content_roots(A)

    def served(relative):
        return tenantpaths.contained_file(public, relative, also=also)
    # through the profile's link into the tenant's own imported media
    assert served('os/' + name + '/distribution/images/pxeboot/vmlinuz') == os.path.join(
        tenantpaths.base(A), 'distributions', OSNAME, 'images/pxeboot/vmlinuz')
    # and into packaged content (stock boot image parts)
    assert served('os/' + name + '/boot/initramfs/addons.cpio') == os.path.realpath(
        os.path.join(images['templates'], 'el9/initramfs/addons.cpio'))
    assert served('site/initramfs.cpio')
    # but not into another tenant's media, the host's, or its own media and private trees
    links = os.path.join(public, 'os', name)
    for target in (os.path.join(tenantpaths.base(B), 'distributions', OSNAME),
                   images['base'], '/etc', tenantpaths.media_root(A),
                   tenantpaths.private_root(A)):
        link = os.path.join(links, 'escape')
        if os.path.lexists(link):
            os.unlink(link)
        os.symlink(target, link)
        for inside in ('images/pxeboot/vmlinuz', 'hostname', 'rocky.iso', 'host.iso'):
            assert served('os/' + name + '/escape/' + inside) is None, (target, inside)
    assert served('../distributions/' + OSNAME + '/distinfo.yaml') is None


async def test_media_is_refused_where_confinement_is_required_and_missing(images, monkeypatch):
    import confluent.sandbox as sandbox
    await tenantsite.ensure(A)
    _write(os.path.join(tenantpaths.media_root(A), 'rocky.iso'), b'x')
    chosen = ['default']
    monkeypatch.setattr(sandbox, 'policy', lambda: chosen[0])

    async def refused():
        for path in ('/deployment/importing/', '/deployment/fingerprint/'):
            with pytest.raises(exc.NotImplementedException, match='cannot confine'):
                await _as(A, path, 'create', {'filename': 'rocky.iso'})
        # the media was not looked at, by anything
        assert images['identified'] == [] and images['ran'] == []
    # a host with the resource limits only: such a worker could read all
    # the service can, so a tenant's media is not handed to one
    monkeypatch.setattr(sandbox, '_supported', [('limits',)])
    await refused()
    # Landlock required, and only the namespaces there
    chosen[0] = 'required'
    monkeypatch.setattr(sandbox, '_supported', [('limits', 'namespaces')])
    await refused()
    # either of the two is enough otherwise
    chosen[0] = 'default'
    await _import(A)
    # required and there: handled
    chosen[0] = 'required'
    monkeypatch.setattr(sandbox, '_supported', [('limits', 'landlock')])
    await _import(B)
    # and with nothing, only on the operator's word
    chosen[0] = 'none'
    monkeypatch.setattr(sandbox, '_supported', [('limits',)])
    key = await _import(A, name='again.iso', custname='second')
    assert key == 'second'
