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

"""A tenant's nodes are served in the tenant's own network.

Both tenants have a node n1 at the same address. Each reaches its own
tenant's listener, is answered from its own tenant's configuration under
its own tenant's certificate authority, and cannot use the other tenant's
API key: the tenant is the listener's, never something the node says.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import ssl
import subprocess
import sys

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

import confluent.config.configmanager as configmanager
import confluent.discovery.core as disco
import confluent.pwcrypt as pwcrypt
import confluent.tenantca as tenantca
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
import confluent.tenantservices as services
from tenanttopo import HW_IP, TENANTS, UP_IP, Topology

A, B = sorted(TENANTS)
KEY = {A: 'apikey-of-node-in-a', B: 'apikey-of-node-in-b'}
RACK = {A: 'rack-of-a', B: 'rack-of-b'}


def _create(tid):
    configmanager._true_create_tenant(
        tid, TENANTS[tid][0], configmanager._wrap_tenant_key(os.urandom(32)), 0)


async def _until(cond, timeout=10):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return
        await asyncio.sleep(0.05)
    raise AssertionError('timed out')


@pytest.fixture
async def tenancy(confluent_config, monkeypatch):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(configmanager, '_hasquorum', True)
    monkeypatch.setattr(services, 'RETRY', 0.2)
    # discovery listeners are not what is being tested here
    monkeypatch.setattr(disco, 'start_tenant_detection', lambda tenant: False)
    yield
    for tid in list(services._services):
        services.stop(tid)
    tenantnet.enter(None)


async def _nodes(tid, armed=None):
    """The same node n1 in a tenant, with that tenant's own API key."""
    attrs = {
        'crypted.selfapikey': {'hashvalue': pwcrypt.crypt(KEY[tid], '$5$saltsalt$')},
        'location.rack': RACK[tid],
        'net.hwaddr': '02:00:00:aa:34:02',
        'net.ipv4_address': HW_IP + '/24',
        'secret.hardwaremanagementpassword': 'not-for-nodes',
    }
    if armed:
        attrs['deployment.apiarmed'] = armed
    await configmanager.ConfigManager(tid).set_node_attributes({'n1': attrs}, autocreate=True)


def _headers(tid, **more):
    headers = {'CONFLUENT_NODENAME': 'n1', 'CONFLUENT_APIKEY': KEY[tid],
               'Accept': 'application/json'}
    headers.update(more)
    return headers


# ----------------------------------------------- without tenant networks

async def test_each_tenant_has_its_own_authority(tenancy):
    _create(A)
    _create(B)
    cert_a, key_a = await tenantca.get_ca(A)
    cert_b, _ = await tenantca.get_ca(B)
    again, _ = await tenantca.get_ca(A)
    assert again == cert_a and cert_a != cert_b
    assert A in cert_a.subject.rfc4514_string()
    # stored with its key encrypted (by a key derived from the tenant's)
    stored = configmanager.get_tenant_ca(A)
    assert 'ENCRYPTED PRIVATE KEY' in stored[1]
    assert configmanager.ConfigManager(A).derive_secret(b'x') != \
        configmanager.ConfigManager(B).derive_secret(b'x')
    # whichever authority was recorded first stays
    other, otherkey = tenantca._generate_ca(A)
    kept = await configmanager.init_tenant_ca(A, 'other-cert', 'other-key')
    assert kept == stored
    # a server certificate verifies under its own tenant's authority only
    certpem, _ = tenantca.issue_server_certificate(cert_a, key_a, [UP_IP, 'confluent.a'])
    server = x509.load_pem_x509_certificate(certpem)
    cert_a.public_key().verify(server.signature, server.tbs_certificate_bytes,
                               ec.ECDSA(hashes.SHA384()))
    with pytest.raises(InvalidSignature):
        cert_b.public_key().verify(server.signature, server.tbs_certificate_bytes,
                                   ec.ECDSA(hashes.SHA384()))
    names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(ip) for ip in names.get_values_for_type(x509.IPAddress)] == [UP_IP]
    assert names.get_values_for_type(x509.DNSName) == ['confluent.a']
    with pytest.raises(ValueError):
        await tenantca.get_ca(None)


async def test_server_certificate_is_renewed_while_serving(tenancy, monkeypatch):
    _create(A)

    class Net(object):
        addresses = ['192.0.2.1/24']

        async def alist_interfaces(self):
            if self.addresses is None:
                raise tenantnet.TenantNetworkError('gone')
            return [{'ipv4': self.addresses, 'ipv6': ['::1/128']}]

    async def shown():
        pem = await asyncio.get_running_loop().run_in_executor(
            None, ssl.get_server_certificate, ('127.0.0.1', port))
        cert = x509.load_pem_x509_certificate(pem.encode())
        alt = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return cert.serial_number, [str(ip) for ip in alt.get_values_for_type(x509.IPAddress)]

    async def answer(reader, writer):
        writer.close()

    net = Net()
    context = await tenantca.server_context(A, {'192.0.2.1'})
    server = await asyncio.start_server(answer, '127.0.0.1', 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    first = await shown()
    assert first[1] == ['192.0.2.1'] and await shown() == first
    monkeypatch.setattr(services, 'RENEW', 0.05)
    net.addresses = ['192.0.2.1/24', '192.0.2.9/24']
    renewal = asyncio.ensure_future(
        services._renew_certificate(A, net, context, {'192.0.2.1'}))
    try:
        for _ in range(100):
            second = await shown()
            if second[1] == ['192.0.2.1', '192.0.2.9']:
                break
            await asyncio.sleep(0.05)
        assert second[0] != first[0] and second[1] == ['192.0.2.1', '192.0.2.9']
        # its network not answering: renewed for the addresses it had
        net.addresses = None
        await asyncio.sleep(0.3)
        third = await shown()
        assert third[0] != second[0] and third[1] == second[1]
    finally:
        renewal.cancel()
        server.close()
        await server.wait_closed()


async def test_only_active_tenants_are_served(tenancy):
    assert services.start(None) is False
    assert services.start('t0000000000ff') is False
    _create(A)  # announced as active: its services start
    assert services.status(A) is False  # no network yet
    await asyncio.sleep(0.5)  # retries: still nothing to listen on
    assert services.status(A) is False and services._services[A]['sockets'] == []
    await configmanager.set_tenant_state(A, 'disabled')
    assert services.status(A) is None and services.start(A) is False
    await configmanager.set_tenant_state(A, 'active')
    assert services.status(A) is False
    await configmanager.set_tenant_state(A, 'disabled')
    await configmanager.delete_tenant(A)
    assert services.status(A) is None


@pytest.fixture
async def listeners(tenancy):
    """Each tenant's node API as its listener serves it (here on loopback
    sockets: what is under test is that the tenant is the listener's)."""
    clients = {}
    for tid in (A, B):
        _create(tid)
        await _nodes(tid)
        app = web.Application()
        app.router.add_route('*', '/{path_info:.*}', services._handler(tid, tls_only=False))
        clients[tid] = TestClient(TestServer(app))
        await clients[tid].start_server()
    yield clients
    for client in clients.values():
        await client.close()
    tenantnet.enter(None)


async def test_node_is_answered_from_its_listeners_tenant(listeners):
    for tid in (A, B):
        rsp = await listeners[tid].get('/confluent-api/self/myattribs', headers=_headers(tid))
        assert rsp.status == 200
        attrs = json.loads(await rsp.text())
        assert attrs['location.rack'] == RACK[tid]
        assert not [k for k in attrs if k.startswith(('secret', 'crypted'))]
        # also without the web server's path prefix
        rsp = await listeners[tid].get('/self/myattribs', headers=_headers(tid))
        assert rsp.status == 200


async def test_another_tenants_key_is_rejected(listeners):
    # the same node name, with the other tenant's (valid) key
    rsp = await listeners[A].get('/confluent-api/self/myattribs', headers=_headers(B))
    assert rsp.status == 401
    rsp = await listeners[B].get('/confluent-api/self/myattribs', headers=_headers(A))
    assert rsp.status == 401
    # and nothing in a request selects a tenant
    for header in ('CONFLUENT_TENANT', 'X-Confluent-Tenant', 'X-Forwarded-Host'):
        rsp = await listeners[A].get('/confluent-api/self/myattribs',
                                     headers=_headers(B, **{header: B}))
        assert rsp.status == 401
    rsp = await listeners[A].get('/confluent-api/self/myattribs',
                                 headers={'CONFLUENT_NODENAME': 'n1'})
    assert rsp.status == 401


async def test_only_node_paths_are_served(listeners):
    for path in ('/', '/nodes/', '/confluent-api/nodes/n1/attributes/all',
                 '/sessions/current/info', '/tenants/', '/selfish'):
        rsp = await listeners[A].get(path, headers=_headers(A))
        assert rsp.status == 404, path
    # remote configuration is not served yet
    for path in ('/self/remoteconfig/post', '/self/remotesyncfiles',
                 '/self/remoteconfigbmc', '/self/register_discovered'):
        rsp = await listeners[A].post('/confluent-api' + path, headers=_headers(A), data=b'x')
        assert rsp.status == 501, path
        # (and say nothing to a node that is not authenticated)
        rsp = await listeners[A].post('/confluent-api' + path, data=b'x',
                                      headers={'CONFLUENT_NODENAME': 'n1'})
        assert rsp.status == 401, path


async def test_ssh_host_keys_are_signed_by_the_tenants_authority(listeners, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    import confluent.tenantssh as tenantssh
    if not tenantssh.available():
        pytest.skip('cryptography without SSH certificates')
    openssh = (serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    hostkey = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(*openssh)
    import confluent.selfservice as selfservice

    async def names(nodename, cfg, myip=None, **kwargs):
        # (what else the node is known as: found on the tenant's network,
        # which these loopback listeners do not have)
        return set([nodename + '.' + cfg.tenant + '.example'])
    monkeypatch.setattr(selfservice, 'get_extra_names', names)
    signers = {}
    for tid in (A, B):
        rsp = await listeners[tid].post('/confluent-api/self/sshcertready', headers=_headers(tid))
        assert rsp.status == 200
        rsp = await listeners[tid].post('/confluent-api/self/sshcert', headers=_headers(tid),
                                        data=hostkey + b' root@n1\n')
        assert rsp.status == 200, await rsp.text()
        cert = serialization.load_ssh_public_identity((await rsp.text()).encode())
        cert.verify_cert_signature()
        assert cert.type == serialization.SSHCertificateType.HOST
        assert cert.key_id == b'n1'
        assert cert.valid_principals == [b'n1', ('n1.' + tid + '.example').encode()]
        assert cert.public_key().public_bytes(*openssh) == hostkey
        signers[tid] = cert.signature_key().public_bytes(*openssh)
        assert tenantssh.ca_public(tid).startswith(signers[tid] + b' ')
    assert signers[A] != signers[B]
    # not for another tenant's node, not for what is no key
    rsp = await listeners[A].post('/confluent-api/self/sshcert', headers=_headers(B), data=hostkey)
    assert rsp.status == 401
    rsp = await listeners[A].post('/confluent-api/self/sshcert', headers=_headers(A),
                                  data=b'not a key')
    assert rsp.status == 400
    # (the authority of the installation and its agent are not involved)
    assert selfservice.inflight_sshcerts == {}


async def test_addresses_are_the_connections_not_the_headers(listeners):
    rsp = await listeners[A].post(
        '/confluent-api/self/updatestatus',
        headers=_headers(A, **{'X-Forwarded-For': '203.0.113.9'}),
        data=b'state: installing\nstate_detail: partitioning\n')
    assert rsp.status == 200
    attrs = configmanager.ConfigManager(A).get_node_attributes('n1', 'deployment.*')['n1']
    assert attrs['deployment.client_ip']['value'] == '127.0.0.1'
    assert attrs['deployment.state']['value'] == 'installing'
    other = configmanager.ConfigManager(B).get_node_attributes('n1', 'deployment.*')['n1']
    assert 'deployment.state' not in other


async def test_node_list_is_the_tenants_own(listeners):
    await configmanager.ConfigManager(B).set_node_attributes({'only-in-b': {}}, autocreate=True)
    await configmanager.ConfigManager(None).set_node_attributes({'host-node': {}}, autocreate=True)
    listed = {}
    for tid in (A, B):
        rsp = await listeners[tid].get('/confluent-api/self/nodelist', headers=_headers(tid))
        assert rsp.status == 200
        listed[tid] = json.loads(await rsp.text())
    assert 'n1' in listed[A] and 'only-in-b' not in listed[A]
    assert 'only-in-b' in listed[B]
    for names in listed.values():
        # neither the host's nodes nor the names of the hosts it runs on
        assert 'host-node' not in names and 'testhost' not in names


async def test_api_key_registration_is_per_tenant(listeners):
    token = 'arm-token-of-a'
    await configmanager.ConfigManager(A).set_node_attributes(
        {'n1': {'secret.selfapiarmtoken': token}})
    newkey = pwcrypt.crypt('a-new-key', '$5$newsalt0$').encode()
    proof = base64.b64encode(hmac.new(token.encode(), newkey, hashlib.sha256).digest()).decode()
    headers = {'CONFLUENT_NODENAME': 'n1', 'CONFLUENT_CRYPTHMAC': proof}
    # tenant b's n1 was not armed: the same request there is refused
    rsp = await listeners[B].post('/confluent-api/self/registerapikey', headers=headers, data=newkey)
    assert rsp.status == 401
    rsp = await listeners[A].post('/confluent-api/self/registerapikey', headers=headers, data=newkey)
    assert rsp.status == 200
    stored = {}
    for tid in (A, B):
        attrs = configmanager.ConfigManager(tid).get_node_attributes('n1', 'crypted.selfapikey')
        stored[tid] = attrs['n1']['crypted.selfapikey']['hashvalue']
    assert stored[A] == newkey.decode() and stored[B] != stored[A]
    rsp = await listeners[A].get('/confluent-api/self/myattribs', headers={
        'CONFLUENT_NODENAME': 'n1', 'CONFLUENT_APIKEY': 'a-new-key',
        'Accept': 'application/json'})
    assert rsp.status == 200


# ------------------------------------------- within the tenant networks

NODE = r'''
# A node asking its deployment server about itself over HTTPS, trusting
# the given authority only.
import json, ssl, sys, urllib.error, urllib.request
url, cafile, name, key, out = sys.argv[1:6]
result = {}
try:
    context = ssl.create_default_context(cafile=cafile)
    request = urllib.request.Request(url, headers={
        'CONFLUENT_NODENAME': name, 'CONFLUENT_APIKEY': key,
        'Accept': 'application/json'})
    with urllib.request.urlopen(request, context=context, timeout=5) as rsp:
        result = {'status': rsp.status, 'body': rsp.read().decode()}
except urllib.error.HTTPError as e:
    result = {'status': e.code}
except Exception as e:
    result = {'error': type(getattr(e, 'reason', e)).__name__}
with open(out + '.tmp', 'w') as f:
    json.dump(result, f)
import os
os.rename(out + '.tmp', out)
'''

GRANT = r'''
# A node presenting the API key it wants to use (confluent's credential
# protocol), from a privileged source port.
import json, os, socket, sys
server, name, crypted, out = sys.argv[1:5]
result = {'granted': False}
try:
    s = socket.socket()
    s.settimeout(5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 302))
    s.connect((server, 13001))
    def need(n):
        data = b''
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk:
                raise EOFError()
            data += chunk
        return data
    need(8)
    s.sendall(bytes([1, len(name)]) + name.encode() + bytes(2))
    need(2)
    token = need(32)
    need(2)
    s.sendall(bytes([3, 32]) + token + bytes([4, len(crypted)]) + crypted.encode() + bytes(2))
    result['granted'] = need(2) == bytes([5, 0])
except Exception as e:
    result['error'] = type(e).__name__
with open(out + '.tmp', 'w') as f:
    json.dump(result, f)
os.rename(out + '.tmp', out)
'''


def _tcp_listeners(ns=None):
    cmd = ['ss', '-Hltnp']
    if ns is not None:
        cmd = ['ip', 'netns', 'exec', ns] + cmd
    return subprocess.run(cmd, capture_output=True, check=True).stdout.decode()


def _own_host_tcp():
    mine = 'pid={0},'.format(os.getpid())
    return sorted(line.split()[3] for line in _tcp_listeners().splitlines() if mine in line)


@pytest.fixture
async def topo(netns, tenancy):
    topology = Topology(netns)
    topology.host_tcp = _own_host_tcp()
    topology.cafile = {}
    tenantguard.recent_violations.clear()
    for tid in TENANTS:
        topology.network(tid)
        _create(tid)
        await _nodes(tid, armed='once')
    for tid in TENANTS:
        await _until(lambda tid=tid: services.status(tid))
        topology.cafile[tid] = os.path.join(topology.dir, 'ca-%s.pem' % tid)
        with open(topology.cafile[tid], 'wb') as f:
            f.write(await tenantca.ca_pem(tid))
    topology.runs = 0
    yield topology
    for tid in TENANTS:
        services.stop(tid)
    tenantnet.enter(None)
    assert list(tenantguard.recent_violations) == []
    assert _own_host_tcp() == topology.host_tcp
    topology.cleanup()


async def _run(topo, tid, script, *args):
    topo.runs += 1
    out = os.path.join(topo.dir, 'run-%d.json' % topo.runs)
    topo.netns.spawn(topo.lan[tid], sys.executable, '-c', script, *(args + (out,)))
    await _until(lambda: os.path.exists(out), timeout=20)
    with open(out) as f:
        return json.load(f)


async def _ask(topo, tid, key, cafile=None, path='/confluent-api/self/myattribs'):
    return await _run(topo, tid, NODE, 'https://%s%s' % (UP_IP, path),
                      cafile or topo.cafile[tid], 'n1', key)


@pytest.mark.netns
async def test_nodes_reach_their_own_tenants_services(topo):
    hits = topo.decoy_hits()
    for tid in TENANTS:
        bound = _tcp_listeners(topo.ns[tid])
        assert ':443 ' in bound and ':13001 ' in bound
        answer = await _ask(topo, tid, KEY[tid])
        assert answer['status'] == 200
        assert json.loads(answer['body'])['location.rack'] == RACK[tid]
    # the same node name and address with the other tenant's key
    assert (await _ask(topo, A, KEY[B]))['status'] == 401
    assert (await _ask(topo, B, KEY[A]))['status'] == 401
    # only the tenant's own authority vouches for its server
    assert (await _ask(topo, A, KEY[A], cafile=topo.cafile[B])).get('error') == \
        'SSLCertVerificationError'
    # the service's API for users is not offered in the tenant's network
    assert (await _ask(topo, A, KEY[A], path='/confluent-api/nodes/'))['status'] == 404
    assert topo.decoy_hits() == hits


@pytest.mark.netns
async def test_node_api_keys_are_granted_per_tenant(topo):
    crypted = pwcrypt.crypt('key-granted-in-a', '$5$grantsal$')
    before = {tid: configmanager.ConfigManager(tid).get_node_attributes(
        'n1', 'crypted.selfapikey')['n1']['crypted.selfapikey']['hashvalue'] for tid in TENANTS}
    assert await _run(topo, A, GRANT, UP_IP, 'n1', crypted) == {'granted': True}
    after = {tid: configmanager.ConfigManager(tid).get_node_attributes(
        'n1', ('crypted.selfapikey', 'deployment.apiarmed'))['n1'] for tid in TENANTS}
    assert after[A]['crypted.selfapikey']['hashvalue'] == crypted
    assert after[B]['crypted.selfapikey']['hashvalue'] == before[B]
    # armed once: used up in tenant a, untouched in tenant b
    assert not after[A].get('deployment.apiarmed', {}).get('value')
    assert after[B]['deployment.apiarmed']['value'] == 'once'
    assert (await _ask(topo, A, 'key-granted-in-a'))['status'] == 200
    assert (await _ask(topo, B, 'key-granted-in-a'))['status'] == 401
    # no longer armed: a second request is not granted
    again = pwcrypt.crypt('another-key', '$5$grantsal$')
    assert (await _run(topo, A, GRANT, UP_IP, 'n1', again))['granted'] is False


@pytest.mark.netns
async def test_services_follow_the_tenants_state(topo):
    def bound(tid):
        listing = _tcp_listeners(topo.ns[tid])
        return [port for port in (':443 ', ':13001 ') if port in listing]

    await configmanager.set_tenant_state(A, 'disabled')
    assert services.status(A) is None
    await _until(lambda: bound(A) == [])
    assert bound(B) == [':443 ', ':13001 ']
    assert 'error' in await _ask(topo, A, KEY[A])
    answer = await _ask(topo, B, KEY[B])
    assert answer.get('status') == 200, answer
    # enabled again: served once its network is back, by the same authority
    await configmanager.set_tenant_state(A, 'active')
    await asyncio.sleep(0.6)
    assert services.status(A) is False
    topo.network(A)
    await _until(lambda: services.status(A))
    answer = await _ask(topo, A, KEY[A])
    assert answer.get('status') == 200, (answer, _tcp_listeners(topo.ns[A]))
    await configmanager.set_tenant_state(B, 'disabled')
    await configmanager.delete_tenant(B)
    await _until(lambda: bound(B) == [])
