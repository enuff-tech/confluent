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

"""Events, audit records and background work belong to their tenant.

What is logged while working for a tenant goes to that tenant's own log
tree, work started for a tenant stays that tenant's after the request
that started it has ended, and all of it goes when the tenant is deleted,
without touching another tenant's.
"""

import asyncio
import os

import pytest

import confluent.config.configmanager as configmanager
import confluent.discovery.core as disco
import confluent.log as log
import confluent.tasks as tasks
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
import confluent.tenantpaths as tenantpaths
import confluent.tenantservices as services

A = 't00000000000a'
B = 't00000000000b'


def _create(tid, name):
    configmanager._true_create_tenant(
        tid, name, configmanager._wrap_tenant_key(os.urandom(32)), 0)


async def _until(cond, timeout=10):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return
        await asyncio.sleep(0.05)
    raise AssertionError('timed out')


@pytest.fixture
async def tenants(confluent_config, monkeypatch, tmp_path):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(tenantpaths, 'BASE', str(tmp_path / 'lib'))
    # no listeners: what is logged here is what the tests log
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    monkeypatch.setattr(services, 'start', lambda tenant: False)
    _create(A, 'acme')
    _create(B, 'globex')
    yield confluent_config.logdir
    tenantnet.enter(None)


def _flush(name, tenant=None):
    log.tenant_logger(name, tenant).writedata()


def _read(logdir, name, tenant=None):
    path = os.path.join(logdir, name) if tenant is None else \
        os.path.join(logdir, 'tenants', tenant, name)
    if not os.path.exists(path):
        return ''
    with open(path) as f:
        return f.read()


async def test_events_go_to_the_tenant_they_happen_in(tenants):
    for tid, text in ((A, 'event of a'), (B, 'event of b'), (None, 'event of the service')):
        tenantnet.enter(tid)
        log.log({'info': text}, flush=True)
    tenantnet.enter(None)
    assert 'event of a' in _read(tenants, 'events', A)
    assert 'event of b' in _read(tenants, 'events', B)
    assert 'event of b' not in _read(tenants, 'events', A)
    assert 'event of a' not in _read(tenants, 'events', B)
    service = _read(tenants, 'events')
    assert 'event of the service' in service
    assert 'event of a' not in service and 'event of b' not in service
    assert sorted(os.listdir(os.path.join(tenants, 'tenants'))) == [A, B]


async def test_service_events_are_the_operators(tenants):
    tenantnet.enter(A)
    log.service_log({'info': 'tenant network is not available'}, flush=True)
    tenantnet.enter(None)
    assert 'tenant network is not available' in _read(tenants, 'events')
    assert _read(tenants, 'events', A) == ''


async def test_what_is_not_a_tenant_has_no_log_tree(tenants):
    # a context left over from a tenant that no longer exists, or a bad id
    for stale in ('t0000000000ff', '../../etc'):
        tenantguard.current_tenant.set(stale)
        log.log({'info': 'event of nobody'}, flush=True)
    tenantguard.current_tenant.set(None)
    assert not os.path.exists(os.path.join(tenants, 'tenants', 't0000000000ff'))
    assert 'event of nobody' in _read(tenants, 'events')
    with pytest.raises(ValueError):
        log.tenant_directory('../../etc')
    with pytest.raises(ValueError):
        log.Logger('events', tenant='..')


async def test_audit_records_follow_the_principals_tenant(tenants):
    audit = log.AuditLog()
    audit.log({'operation': 'update', 'target': '/nodes/n1/power/state',
               'user': 'admin', 'tenant': A, 'allowed': True})
    audit.log({'operation': 'delete', 'target': '/nodes/n1', 'user': 'admin',
               'tenant': B, 'allowed': True})
    audit.log({'operation': 'create', 'target': '/tenants/', 'user': 'platform',
               'allowed': True})
    audit.log({'operation': 'retrieve', 'target': '/nodes/', 'user': 'x',
               'tenant': 't0000000000ff', 'allowed': False})
    audit.log({'node': 'n1', 'event': 'certautoadd'}, tenant=A)
    for tid in (A, B):
        _flush('audit', tid)
    audit.servicelog.writedata()
    a, b, service = (_read(tenants, 'audit', tid) for tid in (A, B, None))
    assert '/nodes/n1/power/state' in a and 'certautoadd' in a
    assert '"delete"' in b and '/nodes/n1/power/state' not in b
    assert '/tenants/' in service and 't0000000000ff' in service
    assert 'power/state' not in service and 'certautoadd' not in service


async def test_console_logs_are_kept_per_tenant(tenants):
    # the same node name in two tenants is two console logs
    paths = {tid: log.Logger('n1', console=True, tenant=tid).handler.textpath
             for tid in (A, B, None)}
    assert paths[A] == os.path.join(tenants, 'tenants', A, 'consoles', 'n1')
    assert paths[B] == os.path.join(tenants, 'tenants', B, 'consoles', 'n1')
    assert paths[None] == os.path.join(tenants, 'consoles', 'n1')


async def test_background_work_stays_its_tenants(tenants):
    await configmanager.ConfigManager(A).set_node_attributes(
        {'only-in-a': {}}, autocreate=True)
    ran = []

    async def job(label):
        tenant = tenantguard.current_tenant.get()
        nodes = list(configmanager.ConfigManager(tenant).list_nodes())
        log.log({'info': 'job {0} done'.format(label)}, flush=True)
        ran.append((label, tenant, nodes))
        return tenant

    def blocking():
        return tenantguard.current_tenant.get()

    tenantnet.enter(A)
    later = tasks.spawn_task_after(0.05, job, 'later')
    spawned = tasks.spawn(job('spawned'))
    tasks.TaskPool(max_concurrent=2).schedule(job, 'pooled')
    mapped = [r async for r in tasks.task_imap(job, ['m1', 'm2'])]
    with tenantguard.ContextThreadPoolExecutor(max_workers=1) as pool:
        threaded = pool.submit(blocking)
    # the request that started the work is over, and another tenant's begins
    tenantnet.enter(B)
    await asyncio.gather(later, spawned)
    await _until(lambda: len(ran) == 5)
    assert mapped == [A, A] and threaded.result() == A
    assert {label for label, _, _ in ran} == {'later', 'spawned', 'pooled', 'm1', 'm2'}
    assert all(tenant == A and nodes == ['only-in-a'] for _, tenant, nodes in ran)
    tenantnet.enter(None)
    events = _read(tenants, 'events', A)
    for label in ('later', 'spawned', 'pooled', 'm1', 'm2'):
        assert 'job {0} done'.format(label) in events
    assert 'job' not in _read(tenants, 'events', B) and 'job' not in _read(tenants, 'events')


async def test_a_deleted_tenants_files_go_with_it(tenants):
    base = tenantpaths.BASE
    for tid in (A, B):
        tenantnet.enter(tid)
        log.log({'info': 'event of ' + tid}, flush=True)
        log.AuditLog().log({'operation': 'x', 'tenant': tid})
        _flush('audit', tid)
        image = os.path.join(tenantpaths.public_root(tid), 'os/p1/boot.img')
        os.makedirs(os.path.dirname(image))
        with open(image, 'w') as f:
            f.write('image of ' + tid)
    tenantnet.enter(None)
    hostfile = os.path.join(base, 'public/os/p1/boot.img')
    os.makedirs(os.path.dirname(hostfile))
    with open(hostfile, 'w') as f:
        f.write('host image')
    log.log({'info': 'event of the service'}, flush=True)
    # links planted in tenant a's trees, pointing at what is not its own
    os.symlink(os.path.join(tenants, 'tenants', B), os.path.join(tenants, 'tenants', A, 'planted'))
    os.symlink(tenantpaths.public_root(B), os.path.join(tenantpaths.public_root(A), 'planted'))
    os.symlink(hostfile, os.path.join(tenantpaths.public_root(A), 'os/p1/planted'))
    await configmanager.set_tenant_state(A, 'disabled')
    await configmanager.delete_tenant(A)
    await _until(lambda: not os.path.exists(os.path.join(base, 'tenants', A)))
    assert not os.path.exists(os.path.join(tenants, 'tenants', A))
    # tenant b and the service are as they were
    assert 'event of ' + B in _read(tenants, 'events', B)
    assert _read(tenants, 'audit', B) != ''
    with open(os.path.join(tenantpaths.public_root(B), 'os/p1/boot.img')) as f:
        assert f.read() == 'image of ' + B
    with open(hostfile) as f:
        assert f.read() == 'host image'
    assert 'event of the service' in _read(tenants, 'events')
    # and nothing is written for the deleted tenant afterwards
    tenantguard.current_tenant.set(A)
    log.log({'info': 'late event'}, flush=True)
    tenantguard.current_tenant.set(None)
    assert not os.path.exists(os.path.join(tenants, 'tenants', A))


async def test_a_tenant_directory_that_is_a_link_is_left_alone(tenants):
    base = tenantpaths.BASE
    image = os.path.join(tenantpaths.public_root(B), 'os/p1/boot.img')
    os.makedirs(os.path.dirname(image))
    with open(image, 'w') as f:
        f.write('image of b')
    # tenant a's tree replaced by a link to tenant b's
    os.symlink(os.path.join(base, 'tenants', B), os.path.join(base, 'tenants', A))
    await configmanager.set_tenant_state(A, 'disabled')
    await configmanager.delete_tenant(A)
    await asyncio.sleep(0.3)
    with open(image) as f:
        assert f.read() == 'image of b'
