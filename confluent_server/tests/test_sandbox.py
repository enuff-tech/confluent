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

"""The confinement of the workers that handle a tenant's media.

What a confined worker can still do is tried by an actual process, for
whatever of the confinement the host running the tests provides; and the
actual media workers are run confined on an actual (small) ISO image.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys

import libarchive
import pytest

import confluent.exceptions as exc
import confluent.osimage as osimage
import confluent.sandbox as sandbox
import confluent.tenantpaths as tenantpaths

PROBE = r'''
import json, os, socket, sys
allowed, secret, writable, elsewhere, port, unixpath, parent = sys.argv[1:8]
out = {}
def attempt(name, fn):
    try:
        fn()
        out[name] = True
    except Exception as e:
        out[name] = False
def write(path):
    with open(path, 'w') as f:
        f.write('x')
def tcp():
    s = socket.create_connection(('127.0.0.1', int(port)), timeout=3)
    s.close()
def unix():
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    s.connect(unixpath)
    s.close()
attempt('read_allowed', lambda: open(allowed).read())
attempt('read_secret', lambda: open(secret).read())
attempt('list_etc', lambda: os.listdir('/etc'))
attempt('read_passwd', lambda: open('/etc/passwd').read())
attempt('write_allowed', lambda: write(os.path.join(writable, 'made')))
attempt('mkdir_allowed', lambda: os.makedirs(os.path.join(writable, 'a', 'b')))
attempt('write_elsewhere', lambda: write(os.path.join(elsewhere, 'made')))
attempt('write_over_allowed_file', lambda: write(allowed))
attempt('tcp', tcp)
attempt('unix', unix)
attempt('signal_parent', lambda: os.kill(int(parent), 0))
attempt('spawn', lambda: os.system('/bin/true') and (_ for _ in ()).throw(OSError()))
import resource
out['cpu'] = resource.getrlimit(resource.RLIMIT_CPU)[0]
out['core'] = resource.getrlimit(resource.RLIMIT_CORE)[0]
out['fds'] = []
for fd in range(256):
    try:
        os.fstat(fd)
        out['fds'].append(fd)
    except OSError:
        pass
sys.stdout.write(json.dumps(out))
'''


@pytest.fixture
def place(tmp_path, monkeypatch):
    for name in ('dist', 'elsewhere', 'run'):
        (tmp_path / name).mkdir()
    (tmp_path / 'media.iso').write_text('media')
    (tmp_path / 'secret').write_text('the key of another tenant')
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(5)
    unixlistener = socket.socket(socket.AF_UNIX)
    unixlistener.bind(str(tmp_path / 'run' / 'broker.sock'))
    unixlistener.listen(5)
    # (where the service's sockets are, for this test)
    monkeypatch.setattr(sandbox, 'HIDDEN', (str(tmp_path / 'run'),))
    yield {'dir': tmp_path, 'port': listener.getsockname()[1]}
    listener.close()
    unixlistener.close()


def _probe(place, confined):
    tmp = place['dir']
    preexec = sandbox.confiner(read=[str(tmp / 'media.iso')], write=[str(tmp / 'dist')]) \
        if confined else None
    done = subprocess.run(
        [sys.executable, '-c', PROBE, str(tmp / 'media.iso'), str(tmp / 'secret'),
         str(tmp / 'dist'), str(tmp / 'elsewhere'), str(place['port']),
         str(tmp / 'run' / 'broker.sock'), str(os.getpid())],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=preexec, close_fds=True,
        timeout=60)
    assert done.returncode == 0, done.stderr.decode()
    return json.loads(done.stdout.decode())


def test_what_the_host_provides_is_found_out():
    found = sandbox.applied()
    assert found[0] == 'limits'
    assert set(found) <= set(['limits', 'namespaces', 'landlock'])
    assert ('landlock' in found) == bool(sandbox.landlock_abi())
    assert sandbox.supported() == tuple(found)
    # (nothing of it reaches the process that asked)
    assert os.path.exists('/etc/passwd') and open('/etc/passwd').read()


def test_an_unconfined_process_can_do_all_of_it(place):
    # (so that what the next test finds refused is refused by the confinement)
    free = _probe(place, confined=False)
    for name in ('read_allowed', 'read_secret', 'list_etc', 'write_allowed', 'write_elsewhere',
                 'tcp', 'unix', 'signal_parent', 'spawn'):
        assert free[name] is True, name


def test_a_confined_worker_keeps_what_it_needs_and_no_more(place):
    use = sandbox.supported()
    confined = _probe(place, confined=True)
    # its work: read the media, write where the media is unpacked
    assert confined['read_allowed'] is True
    assert confined['write_allowed'] is True
    assert confined['mkdir_allowed'] is True
    # always: bounded, and with none of the files the service has open
    assert confined['cpu'] == sandbox.CPU_SECONDS and confined['core'] == 0
    assert [fd for fd in confined['fds'] if fd > 2] == []
    if 'landlock' in use:
        for name in ('read_secret', 'list_etc', 'read_passwd', 'write_elsewhere',
                     'write_over_allowed_file'):
            assert confined[name] is False, name
        assert not (place['dir'] / 'elsewhere' / 'made').exists()
        assert (place['dir'] / 'media.iso').read_text() == 'media'
        if sandbox.landlock_abi() >= 6:
            assert confined['signal_parent'] is False
    if 'namespaces' in use or sandbox.landlock_abi() >= 4:
        assert confined['tcp'] is False
    if 'namespaces' in use:
        # the service's sockets (a tenant's broker, the API) are not there
        assert confined['unix'] is False
    if not ('landlock' in use or 'namespaces' in use):
        pytest.skip('this host provides neither namespaces nor Landlock to the tests')


def test_only_what_was_found_to_work_is_tried(monkeypatch):
    monkeypatch.setattr(sandbox, '_supported', [('limits',)])
    preexec = sandbox.confiner(read=['/nonexistent/media'], write=[])
    assert preexec.use == ('limits',)
    assert '/nonexistent/media' in preexec.read
    for needed in (sys.prefix, os.path.dirname(os.path.dirname(sandbox.__file__))):
        assert os.path.realpath(needed) in [os.path.realpath(p) for p in preexec.read]
    done = subprocess.run([sys.executable, '-c', 'print(open("/etc/passwd").read()[:1])'],
                          stdout=subprocess.PIPE, preexec_fn=preexec, timeout=60)
    assert done.returncode == 0 and done.stdout.strip()


# ------------------------------------------------------- the media workers

def _iso(path, release='rocky-release-9.4-1.6.el9.noarch.rpm', arch=b'x86_64', extra=()):
    entries = [
        ('.discinfo', b'1715000000.123456\nRocky Linux 9.4\n' + arch + b'\n'),
        ('Packages/r/' + release, b'not really a package'),
        ('images/pxeboot/vmlinuz', b'kernel' * 1000),
        ('images/pxeboot/initrd.img', b'initrd' * 1000),
        ('EFI/BOOT/BOOTX64.EFI', b'efi'),
    ] + list(extra)
    with libarchive.file_writer(str(path), 'iso9660') as archive:
        for name, data in entries:
            archive.add_file_from_memory(name, len(data), data)
    return str(path)


@pytest.fixture
def workers(tmp_path, monkeypatch):
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join(
        [os.path.dirname(os.path.dirname(osimage.__file__))] +
        [p for p in os.environ.get('PYTHONPATH', '').split(os.pathsep) if p]))
    base = tmp_path / 'lib' / 'tenants' / 't00000000000a'
    (base / 'distributions').mkdir(parents=True)
    (base / 'media').mkdir()
    monkeypatch.setattr(tenantpaths, 'BASE', str(tmp_path / 'lib'))
    monkeypatch.setenv('CONFLUENT_IMAGE_BASE', str(base))
    return base


async def _unpack(base, media, name):
    target = str(base / 'distributions' / name)
    worker = await asyncio.create_subprocess_exec(
        sys.executable, osimage.__file__, media, '-b', target, target, '',
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, close_fds=True,
        preexec_fn=sandbox.confiner(read=[media], write=[str(base / 'distributions')]),
        env=osimage._worker_env(str(base)))
    out, err = await asyncio.wait_for(worker.communicate(), 120)
    return worker.returncode, out, err


async def test_the_confined_workers_identify_and_unpack_media(workers):
    media = _iso(workers / 'media' / 'Rocky-9.4-x86_64-minimal.iso')
    identity, _, _ = await osimage.identify_in_worker(media)
    assert identity['name'] == 'rocky-9.4-x86_64' and identity['category'] == 'el9'
    code, out, err = await _unpack(workers, media, identity['name'])
    assert code == 0 and b'ERROR' not in out, (out, err)
    unpacked = workers / 'distributions' / 'rocky-9.4-x86_64'
    assert (unpacked / 'images' / 'pxeboot' / 'vmlinuz').read_bytes() == b'kernel' * 1000
    assert (unpacked / '.discinfo').exists()
    assert (unpacked / 'Packages' / 'r' / 'rocky-release-9.4-1.6.el9.noarch.rpm').exists()


async def test_media_naming_itself_out_of_its_place_is_refused(workers):
    # what the media says of itself would be a path outside the tenant's
    # distributions: refused by the service, and again by the worker
    media = _iso(workers / 'media' / 'odd.iso', arch=b'x/../../../../escape')
    with pytest.raises(exc.InvalidArgumentException):
        await osimage.identify_in_worker(media)
    code, out, err = await _unpack(workers, media, 'odd')
    assert code != 0 or b'ERROR' in out
    assert not (workers / 'distributions' / 'odd' / 'images').exists()
    assert sorted(p.name for p in workers.parent.iterdir()) == ['t00000000000a']
