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

"""Media a tenant uploads, and what the service does with media it does
not trust.

A tenant administrator sends OS installation media through the API; it is
kept in the tenant's media directory within limits. Media is identified by
a worker process, and unpacking it writes nothing outside the directory it
is unpacked into, whatever the media contains.
"""

import asyncio
import base64
import io
import os
import stat
import tarfile

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import confluent.config.configmanager as configmanager
import confluent.core as core
import confluent.discovery.core as disco
import confluent.exceptions as exc
import confluent.httpapi as httpapi
import confluent.networking.tenantnetcfg as netcfg
import confluent.osimage as osimage
import confluent.tenancy as tenancy
import confluent.tenantmedia as tenantmedia
import confluent.tenantnet as tenantnet
import confluent.tenantpaths as tenantpaths
import confluent.tenantservices as services

PASSWORD = 'correct horse battery'
MIB = 2 ** 20


class Stream(object):
    """A request body arriving in pieces."""

    def __init__(self, data, piece=65536):
        self.data = io.BytesIO(data)
        self.piece = piece
        self.reads = 0

    async def read(self, count):
        self.reads += 1
        await asyncio.sleep(0)
        return self.data.read(min(count, self.piece))


@pytest.fixture
async def media(confluent_config, monkeypatch, tmp_path):
    configmanager.init_masterkey()
    configmanager.set_global('tenancy.schema', configmanager.TENANCY_SCHEMA)
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    monkeypatch.setattr(netcfg, 'start', lambda tenant: False)
    monkeypatch.setattr(tenantpaths, 'BASE', str(tmp_path / 'lib'))
    tenants = {}
    for name in ('acme', 'globex'):
        record = await tenancy.create(name)
        await tenancy.redeem_enrollment(name, record['enrollment_token'], 'admin', PASSWORD)
        tenants[name] = record['id']
    yield tenants
    tenantnet.enter(None)


def _limits(monkeypatch, **gib):
    for name, value in gib.items():
        monkeypatch.setitem(tenantmedia.DEFAULTS, name, value)


def _directory(tenant):
    return tenantpaths.media_root(tenant)


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


# ------------------------------------------------------------------ keeping

async def test_an_upload_is_kept_for_the_tenant_only(media):
    acme, globex = media['acme'], media['globex']
    data = os.urandom(300000)
    stream = Stream(data)
    assert await tenantmedia.receive(acme, 'rocky-9.4.iso', stream, len(data)) == len(data)
    assert stream.reads > 2  # taken as it arrives
    path = os.path.join(_directory(acme), 'rocky-9.4.iso')
    with open(path, 'rb') as stored:
        assert stored.read() == data
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(_directory(acme)).st_mode) == 0o700
    assert tenantmedia.listing(acme) == {'rocky-9.4.iso': len(data)}
    assert tenantmedia.listing(globex) == {}
    assert os.listdir(_directory(acme)) == ['rocky-9.4.iso']
    # and it is what an import of that tenant can name
    assert osimage.tenant_media(acme, 'rocky-9.4.iso') == path
    with pytest.raises(exc.InvalidArgumentException):
        osimage.tenant_media(globex, 'rocky-9.4.iso')


async def test_media_is_a_matter_of_tenants(media):
    with pytest.raises(exc.NotFoundException):
        await tenantmedia.receive(None, 'x.iso', Stream(b'x'), 1)
    with pytest.raises(exc.NotFoundException):
        tenantmedia.listing(None)
    assert 'media/' not in await _as(None, '/deployment/')
    assert 'media/' in await _as(media['acme'], '/deployment/')


@pytest.mark.parametrize('name', [
    '', '.', '..', '.hidden', 'a/b', '../x.iso', '/etc/passwd', 'x.iso.part',
    'white space.iso', 'x\n.iso', 'x' * 129, '-rf', 'semi;colon', 'nul\x00.iso'])
async def test_a_media_name_is_one_plain_component(media, name):
    stream = Stream(b'data')
    with pytest.raises(exc.InvalidArgumentException):
        await tenantmedia.receive(media['acme'], name, stream, 4)
    assert stream.reads == 0
    assert os.listdir(_directory(media['acme'])) == []
    with pytest.raises((exc.InvalidArgumentException, exc.NotFoundException)):
        tenantmedia.remove(media['acme'], name)


async def test_an_upload_states_its_size_and_keeps_to_it(media):
    acme = media['acme']
    for length in (None, 0, -1):
        with pytest.raises(exc.InvalidArgumentException, match='size'):
            await tenantmedia.receive(acme, 'a.iso', Stream(b'data'), length)
    with pytest.raises(exc.InvalidArgumentException, match='cut short'):
        await tenantmedia.receive(acme, 'a.iso', Stream(b'data'), 10)
    with pytest.raises(tenantmedia.TooLarge, match='announced'):
        await tenantmedia.receive(acme, 'a.iso', Stream(b'x' * 200000), 100000)
    # nothing of a failed upload stays
    assert os.listdir(_directory(acme)) == []
    assert tenantmedia.used(acme) == 0
    assert await tenantmedia.receive(acme, 'a.iso', Stream(b'data'), 4) == 4
    with pytest.raises(exc.InvalidArgumentException, match='already exists'):
        await tenantmedia.receive(acme, 'a.iso', Stream(b'other'), 5)
    with open(os.path.join(_directory(acme), 'a.iso'), 'rb') as stored:
        assert stored.read() == b'data'


async def test_what_a_tenant_may_keep_is_bounded(media, monkeypatch):
    acme, globex = media['acme'], media['globex']
    _limits(monkeypatch, media_max_gb=2.0 / 1024, media_quota_gb=3.0 / 1024, media_reserve_gb=0)
    refused = Stream(b'x' * (2 * MIB + 1))
    with pytest.raises(tenantmedia.TooLarge, match='larger than'):
        await tenantmedia.receive(acme, 'big.iso', refused, 2 * MIB + 1)
    assert refused.reads == 0  # refused before any of it is read
    await tenantmedia.receive(acme, 'one.iso', Stream(b'1' * 2 * MIB, MIB), 2 * MIB)
    with pytest.raises(tenantmedia.TooLarge, match='no room'):
        await tenantmedia.receive(acme, 'two.iso', Stream(b'2' * 2 * MIB), 2 * MIB)
    # another tenant's room is its own
    await tenantmedia.receive(globex, 'two.iso', Stream(b'2' * 2 * MIB, MIB), 2 * MIB)
    tenantmedia.remove(acme, 'one.iso')
    await tenantmedia.receive(acme, 'two.iso', Stream(b'2' * 2 * MIB, MIB), 2 * MIB)
    assert sorted(tenantmedia.listing(acme)) == ['two.iso']
    with pytest.raises(tenantmedia.TooLarge) as refusal:
        await tenantmedia.receive(acme, 'three.iso', Stream(b'3' * 2 * MIB), 2 * MIB)
    assert refusal.value.apierrorcode == 413


async def test_an_upload_under_way_counts_as_announced(media, monkeypatch):
    acme = media['acme']
    _limits(monkeypatch, media_max_gb=2.0 / 1024, media_quota_gb=3.0 / 1024, media_reserve_gb=0)
    gate = asyncio.Event()

    class Slow(Stream):
        async def read(self, count):
            await gate.wait()
            return await Stream.read(self, count)
    first = asyncio.ensure_future(
        tenantmedia.receive(acme, 'slow.iso', Slow(b'1' * 2 * MIB, MIB), 2 * MIB))
    await asyncio.sleep(0.05)
    assert tenantmedia.used(acme) == 2 * MIB
    assert tenantmedia.listing(acme) == {}  # not there until it is whole
    with pytest.raises(exc.InvalidArgumentException):
        osimage.tenant_media(acme, 'slow.iso')
    with pytest.raises(tenantmedia.TooLarge, match='no room'):
        await tenantmedia.receive(acme, 'other.iso', Stream(b'2' * 2 * MIB), 2 * MIB)
    with pytest.raises(exc.InvalidArgumentException, match='being uploaded'):
        await tenantmedia.receive(acme, 'slow.iso', Stream(b'x'), 1)
    gate.set()
    assert await first == 2 * MIB
    assert tenantmedia.listing(acme) == {'slow.iso': 2 * MIB}


async def test_an_abandoned_upload_leaves_nothing(media):
    acme = media['acme']
    gate = asyncio.Event()

    class Stalled(Stream):
        async def read(self, count):
            await gate.wait()
    upload = asyncio.ensure_future(
        tenantmedia.receive(acme, 'gone.iso', Stalled(b''), 4096))
    await asyncio.sleep(0.05)
    assert os.listdir(_directory(acme)) == ['gone.iso.part']
    upload.cancel()
    with pytest.raises(asyncio.CancelledError):
        await upload
    assert os.listdir(_directory(acme)) == []


async def test_the_volume_keeps_room_for_everything_else(media, monkeypatch):
    acme = media['acme']
    _limits(monkeypatch, media_reserve_gb=1)

    class Usage(object):
        free = 2 ** 30 + 1000
    monkeypatch.setattr(tenantmedia.shutil, 'disk_usage', lambda path: Usage)
    stream = Stream(b'x' * 1001)
    with pytest.raises(tenantmedia.TooLarge, match='not enough space'):
        await tenantmedia.receive(acme, 'a.iso', stream, 1001)
    assert stream.reads == 0
    assert await tenantmedia.receive(acme, 'a.iso', Stream(b'x' * 1000), 1000) == 1000


async def test_limits_come_from_the_service_configuration(monkeypatch):
    configured = {'media_max_gb': '2', 'media_quota_gb': 'plenty'}
    monkeypatch.setattr(tenantmedia.conf, 'get_option',
                        lambda section, name: configured.get(name) if section == 'tenants' else None)
    assert tenantmedia.limit('media_max_gb') == 2 * 2 ** 30
    assert tenantmedia.limit('media_quota_gb') == 64 * 2 ** 30  # not a number: the default
    assert tenantmedia.limit('media_reserve_gb') == 20 * 2 ** 30


# ---------------------------------------------------------------------- API

async def test_media_through_the_api(media):
    acme, globex = media['acme'], media['globex']
    await tenantmedia.receive(acme, 'a.iso', Stream(b'data'), 4)
    await tenantmedia.receive(acme, 'b.iso', Stream(b'more data'), 9)
    assert 'media/' in await _as(acme, '/deployment/')
    assert await _as(acme, '/deployment/media/') == ['a.iso', 'b.iso']
    assert await _as(globex, '/deployment/media/') == []
    assert (await _as(acme, '/deployment/media/b.iso'))[0] == {'name': 'b.iso', 'size': 9}
    with pytest.raises(exc.NotFoundException):
        await _as(globex, '/deployment/media/b.iso')
    with pytest.raises(exc.NotFoundException):
        await _as(globex, '/deployment/media/b.iso', 'delete')
    await _as(acme, '/deployment/media/b.iso', 'delete')
    assert await _as(acme, '/deployment/media/') == ['a.iso']
    with pytest.raises(exc.NotFoundException):
        await _as(acme, '/deployment/media/b.iso', 'delete')
    for name in ('..', '.part', 'x.part'):
        with pytest.raises((exc.InvalidArgumentException, exc.NotFoundException)):
            await _as(acme, '/deployment/media/' + name, 'delete')
    # (the upload itself is a stream, which only the HTTP API takes)
    with pytest.raises(exc.InvalidArgumentException):
        await _as(acme, '/deployment/media/c.iso', 'create', {})
    assert os.listdir(_directory(acme)) == ['a.iso']


class _Log(object):
    def __init__(self):
        self.entries = []

    def log(self, entry=None, **kwargs):
        self.entries.append(entry)


@pytest.fixture
async def http(media, monkeypatch):
    trace = _Log()
    monkeypatch.setattr(httpapi, 'auditlog', _Log())
    monkeypatch.setattr(httpapi, 'tracelog', trace)
    monkeypatch.setattr(httpapi, 'httpsessions', {})
    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', httpapi.resourcehandler)
    client = TestClient(TestServer(app))
    await client.start_server()
    yield client
    await client.close()
    assert trace.entries == []


def _basic(tenant, password=PASSWORD):
    return {'Authorization': 'Basic ' + base64.b64encode(
        '{0}/admin:{1}'.format(tenant, password).encode()).decode(),
        'Accept': 'application/json'}


async def test_upload_over_http(media, http):
    acme, globex = media['acme'], media['globex']
    data = os.urandom(3 * MIB)  # (more than a request body held in memory may be)
    rsp = await http.put('/deployment/media/rocky.iso', data=data, headers=_basic('acme'))
    assert rsp.status == 201, await rsp.text()
    assert await rsp.json() == {'media': 'rocky.iso', 'size': len(data)}
    with open(os.path.join(_directory(acme), 'rocky.iso'), 'rb') as stored:
        assert stored.read() == data
    assert tenantmedia.listing(globex) == {}
    rsp = await http.get('/deployment/media/', headers=_basic('acme'))
    assert rsp.status == 200 and 'rocky.iso' in await rsp.text()
    rsp = await http.get('/deployment/media/', headers=_basic('globex'))
    assert rsp.status == 200 and 'rocky.iso' not in await rsp.text()
    # POST does the same; a name is taken once
    rsp = await http.post('/deployment/media/second.iso', data=b'second', headers=_basic('globex'))
    assert rsp.status == 201
    rsp = await http.post('/deployment/media/second.iso', data=b'again', headers=_basic('globex'))
    assert rsp.status == 400 and 'already exists' in await rsp.text()
    rsp = await http.delete('/deployment/media/rocky.iso', headers=_basic('acme'))
    assert rsp.status == 200
    assert os.listdir(_directory(acme)) == []
    assert os.listdir(_directory(globex)) == ['second.iso']


async def test_upload_over_http_is_refused(media, http, monkeypatch):
    acme = media['acme']
    _limits(monkeypatch, media_max_gb=1.0 / 1024)
    received = []
    real = tenantmedia.receive

    async def receive(*args):
        received.append(args[:2])
        return await real(*args)
    monkeypatch.setattr(tenantmedia, 'receive', receive)
    # by someone who is not of the tenant: before anything is taken
    rsp = await http.put('/deployment/media/a.iso', data=b'data',
                         headers={'SuppressAuthHeader': '1'})
    assert rsp.status == 401
    rsp = await http.put('/deployment/media/a.iso', data=b'data',
                         headers=_basic('acme', 'not the password'))
    assert rsp.status == 401
    assert received == []
    # larger than a tenant may send
    rsp = await http.put('/deployment/media/a.iso', data=b'x' * (MIB + 1), headers=_basic('acme'))
    assert rsp.status == 413, await rsp.text()
    assert 'larger than' in (await rsp.json())['error']
    # names that are not one plain component
    for name in ('.hidden', 'a.part', 'sub/a.iso', 'a%2Fb.iso'):
        rsp = await http.put('/deployment/media/' + name, data=b'data', headers=_basic('acme'))
        assert rsp.status == 400, name
    assert os.listdir(_directory(acme)) == []
    assert not os.path.exists(os.path.join(tenantpaths.base(acme), 'a.iso'))


# --------------------------------------------------- media that is not trusted

def _tar(path, entries):
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
        for name, kind, content in entries:
            info = tarfile.TarInfo(name)
            if kind == 'link':
                info.type = tarfile.SYMTYPE
                info.linkname = content
                archive.addfile(info)
            elif kind == 'dir':
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            else:
                info.size = len(content)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(content))


def _unpack(path, into, monkeypatch):
    os.makedirs(into, exist_ok=True)
    monkeypatch.chdir(into)
    with open(path, 'rb') as archive:
        return osimage.extract_file(archive, imginfo={'all': 1000})


def test_unpacking_keeps_what_is_plain(tmp_path, monkeypatch):
    _tar(str(tmp_path / 'm.tar'), [
        ('images', 'dir', None), ('images/vmlinuz', 'file', b'kernel'),
        ('EFI/BOOT/grub.cfg', 'file', b'cfg'), ('latest', 'link', 'images/vmlinuz')])
    into = str(tmp_path / 'dist')
    _unpack(str(tmp_path / 'm.tar'), into, monkeypatch)
    with open(os.path.join(into, 'images/vmlinuz'), 'rb') as f:
        assert f.read() == b'kernel'
    assert os.readlink(os.path.join(into, 'latest')) == 'images/vmlinuz'
    assert stat.S_IMODE(os.stat(os.path.join(into, 'images')).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(os.path.join(into, 'EFI/BOOT/grub.cfg')).st_mode) == 0o644


@pytest.mark.parametrize('hostile', ['through-link', 'dotdot', 'absolute'])
def test_unpacking_writes_nothing_outside(tmp_path, monkeypatch, hostile):
    outside = tmp_path / 'outside'
    outside.mkdir()
    entries = [('ok', 'file', b'fine')]
    if hostile == 'through-link':
        entries += [('esc', 'link', str(outside)), ('esc/evil', 'file', b'evil')]
    elif hostile == 'dotdot':
        entries += [('../outside/evil', 'file', b'evil'), ('a/../../outside/evil', 'file', b'evil')]
    else:
        entries += [(str(outside / 'evil'), 'file', b'evil')]
    _tar(str(tmp_path / 'm.tar'), entries)
    try:
        _unpack(str(tmp_path / 'm.tar'), str(tmp_path / 'dist'), monkeypatch)
    except Exception:
        pass  # (refusing the whole media is as good)
    assert os.listdir(str(outside)) == []


def test_unpacking_changes_nothing_a_link_points_at(tmp_path, monkeypatch):
    # (what is unpacked is made readable for the web server: not what a
    # link in the media names)
    secret = tmp_path / 'secret.key'
    secret.write_bytes(b'key')
    os.chmod(str(secret), 0o600)
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    _tar(str(tmp_path / 'm.tar'), [
        ('key', 'link', str(secret)), ('dir', 'link', str(private)), ('ok', 'file', b'fine')])
    _unpack(str(tmp_path / 'm.tar'), str(tmp_path / 'dist'), monkeypatch)
    assert stat.S_IMODE(os.stat(str(secret)).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(str(private)).st_mode) == 0o700
    assert os.path.exists(str(tmp_path / 'dist' / 'ok'))


def test_names_media_may_give_itself():
    good = {'name': 'sle-15.6-x86_64', 'subname': '1', 'category': 'suse15', 'method': osimage.EXTRACT}
    assert osimage.checked_identity(good) is good
    assert osimage.checked_identity({'name': 'ubuntu-24.04.1-x86_64'})
    for bad in ({'name': '../x'}, {'name': 'x', 'subname': '..'}, {'name': 'x', 'category': 'a/b'},
                {'name': 'x', 'subname': 1}, {'name': None}, None, 'x'):
        with pytest.raises(exc.InvalidArgumentException):
            osimage.checked_identity(bad)


async def test_the_identifying_worker_for_real(tmp_path, monkeypatch):
    # an actual process (limited) reading actual files that are no media
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join(
        [os.path.dirname(os.path.dirname(osimage.__file__))] +
        [p for p in os.environ.get('PYTHONPATH', '').split(os.pathsep) if p]))
    monkeypatch.setattr(tenantpaths, 'BASE', str(tmp_path / 'lib'))
    garbage = tmp_path / 'garbage.iso'
    garbage.write_bytes(os.urandom(70000))
    assert await osimage.identify_in_worker(str(garbage)) is None
    with pytest.raises(exc.InvalidArgumentException):
        await osimage.identify_in_worker(str(tmp_path / 'missing.iso'))
    # one that does not come back in time is done away with
    monkeypatch.setattr(osimage, 'IDENTIFY_SECONDS', 0.3)
    stuck = tmp_path / 'stuck.py'
    stuck.write_text('import time\ntime.sleep(60)\n')
    monkeypatch.setattr(osimage, '__file__', str(stuck))
    # (a confined worker reads what the interpreter is told to look in)
    monkeypatch.setenv('PYTHONPATH', os.environ['PYTHONPATH'] + os.pathsep + str(tmp_path))
    started = asyncio.get_running_loop().time()
    with pytest.raises(exc.InvalidArgumentException):
        await osimage.identify_in_worker(str(garbage))
    assert asyncio.get_running_loop().time() - started < 10
