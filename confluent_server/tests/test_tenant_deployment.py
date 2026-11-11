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

"""Network boot and deployment content for each tenant.

Both tenants deploy a profile of the same name to a node of the same
name, address and identity. Each node is offered boot from, and served
the content of, its own tenant's tree, with the addressing its own tenant
chose for it.
"""

import asyncio
import json
import os
import sys

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

import confluent.config.configmanager as configmanager
import confluent.discovery.core as disco
import confluent.discovery.protocols.pxe as pxe
import confluent.pwcrypt as pwcrypt
import confluent.tenantca as tenantca
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet
import confluent.tenantpaths as tenantpaths
import confluent.tenantservices as services
import confluent.tenantssh as tenantssh
from tenanttopo import HW_IP, TENANTS, UP_IP, Topology

A, B = sorted(TENANTS)
KEY = 'the-node-api-key'
MAC = '02:00:00:5e:00:07'
RAW_UUID = bytes(range(0x30, 0x40))
UUID = pxe.decode_uuid(RAW_UUID)
IMAGE = {A: b'boot image of tenant a\n', B: b'boot image of tenant b\n'}
ADDRESS = {A: '10.241.34.50', B: '10.241.34.60'}


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


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)


def _trees(base):
    """A profile p1 in each tenant's trees (and one in the host's)."""
    for tid in (A, B):
        public = tenantpaths.public_root(tid)
        _write(os.path.join(public, 'os/p1/boot.img'), IMAGE[tid])
        _write(os.path.join(public, 'os/p1/boot.ipxe'), b'#!ipxe ' + IMAGE[tid])
        _write(os.path.join(public, 'os/p1/scripts/post.d/10-' + tid), b'')
        _write(os.path.join(tenantpaths.private_root(tid), 'os/p1/pending/secret'),
               b'secret of ' + tid.encode())
    _write(os.path.join(base, 'public/os/p1/boot.img'), b'the host image\n')
    _write(os.path.join(base, 'public/os/hostonly/boot.img'), b'host only\n')
    for path in (base, os.path.join(base, 'tenants')):
        os.chmod(path, 0o755)


async def _nodes(tid, **more):
    attrs = {
        'crypted.selfapikey': {'hashvalue': pwcrypt.crypt(KEY, '$5$saltsalt$')},
        'net.hwaddr': MAC, 'id.uuid': UUID,
        'net.ipv4_address': ADDRESS[tid] + '/24',
        'deployment.pendingprofile': 'p1',
    }
    attrs.update(more)
    await configmanager.ConfigManager(tid).set_node_attributes({'n1': attrs}, autocreate=True)


@pytest.fixture
async def tenancy(confluent_config, monkeypatch, tmp_path):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    configmanager.set_global('confluent_uuid', 'the-hosts-own-uuid')
    monkeypatch.setattr(configmanager, '_ready', True)
    monkeypatch.setattr(configmanager, '_hasquorum', True)
    monkeypatch.setattr(services, 'RETRY', 0.2)
    monkeypatch.setattr(disco, 'TENANT_LISTENER_RETRY', 0.2)
    monkeypatch.setattr(tenantpaths, 'BASE', str(tmp_path))
    yield str(tmp_path)
    for tid in list(services._services):
        services.stop(tid)
    for tid in list(disco._tenant_listeners):
        disco.stop_tenant_detection(tid)
    tenantnet.enter(None)


HEADERS = {'CONFLUENT_NODENAME': 'n1', 'CONFLUENT_APIKEY': KEY,
           'Accept': 'application/json'}


# ----------------------------------------------- without tenant networks

@pytest.fixture
async def listeners(tenancy):
    clients = {}
    for tid in (A, B):
        _create(tid)
        await _nodes(tid)
    _trees(tenancy)
    for tid in (A, B):
        for name, handler in ((tid, services._handler(tid, tls_only=False)),
                              (tid + '/plain', services._handler(tid))):
            app = web.Application()
            app.router.add_route('*', '/{path_info:.*}', handler)
            clients[name] = TestClient(TestServer(app))
            await clients[name].start_server()
    yield clients
    for client in clients.values():
        await client.close()
    tenantnet.enter(None)


async def test_content_is_served_from_the_tenants_own_tree(listeners, tenancy):
    for tid in (A, B):
        rsp = await listeners[tid].get('/confluent-public/os/p1/boot.img')
        assert rsp.status == 200 and await rsp.read() == IMAGE[tid]
        # what only the host (or the other tenant) has does not exist here
        rsp = await listeners[tid].get('/confluent-public/os/hostonly/boot.img')
        assert rsp.status == 404
        rsp = await listeners[tid].head('/confluent-public/os/p1/boot.img')
        assert rsp.status == 200 and rsp.headers['Content-Length'] == str(len(IMAGE[tid]))
        rsp = await listeners[tid].get('/confluent-public/os/p1/boot.img',
                                       headers={'Range': 'bytes=0-3'})
        assert rsp.status == 206 and await rsp.read() == IMAGE[tid][:4]
    for bad in ('/confluent-public/os/p1/', '/confluent-public/os/p1',
                '/confluent-public/os/p1/missing', '/confluent-public/'):
        assert (await listeners[A].get(bad)).status == 404, bad
    assert (await listeners[A].post('/confluent-public/os/p1/boot.img', data=b'x')).status == 405


async def test_content_cannot_leave_the_tenants_tree(listeners, tenancy):
    public = tenantpaths.public_root(A)
    outside = os.path.join(tenancy, 'public/os/hostonly/boot.img')
    os.symlink(outside, os.path.join(public, 'os/p1/link-to-host'))
    os.symlink(os.path.join(tenantpaths.public_root(B), 'os'), os.path.join(public, 'other'))
    os.symlink('boot.img', os.path.join(public, 'os/p1/link-inside'))
    assert (await listeners[A].get('/confluent-public/os/p1/link-to-host')).status == 404
    assert (await listeners[A].get('/confluent-public/other/p1/boot.img')).status == 404
    rsp = await listeners[A].get('/confluent-public/os/p1/link-inside')
    assert rsp.status == 200 and await rsp.read() == IMAGE[A]
    for relative in ('../public/os/hostonly/boot.img', '../../public/os/p1/boot.img',
                     'os/../../../public/os/p1/boot.img',
                     '../' + B + '/public/os/p1/boot.img', '/etc/hostname'):
        assert tenantpaths.contained_file(public, relative) is None, relative
    assert tenantpaths.contained_file(public, 'os/p1/boot.img') == \
        os.path.realpath(os.path.join(public, 'os/p1/boot.img'))
    with pytest.raises(ValueError):
        tenantpaths.public_root('../etc')


async def test_each_tenant_is_given_its_own_authority_and_identity(listeners):
    seen = {}
    for tid in (A, B):
        rsp = await listeners[tid + '/plain'].get('/confluent-public/site/tls/ca.pem')
        assert rsp.status == 200
        assert await rsp.read() == await tenantca.ca_pem(tid)
        rsp = await listeners[tid].get('/confluent-public/site/confluent_uuid')
        seen[tid] = (await rsp.text()).strip()
        assert seen[tid] == configmanager.ConfigManager(tid).service_uuid()
    assert len({seen[A], seen[B], 'the-hosts-own-uuid'}) == 3
    assert configmanager.ConfigManager(None).service_uuid() == 'the-hosts-own-uuid'


async def test_node_api_needs_tls_but_content_does_not(listeners):
    plain = listeners[A + '/plain']
    rsp = await plain.get('/confluent-public/os/p1/boot.img')
    assert rsp.status == 200 and await rsp.read() == IMAGE[A]
    assert (await plain.get('/confluent-api/self/myattribs', headers=HEADERS)).status == 404
    assert (await listeners[A].get('/confluent-api/self/myattribs', headers=HEADERS)).status == 200


async def test_scripts_and_private_content_are_the_tenants_own(listeners):
    for tid in (A, B):
        rsp = await listeners[tid].get('/confluent-api/self/scriptlist/post', headers=HEADERS)
        assert rsp.status == 200 and '10-' + tid in await rsp.text()
        other = B if tid == A else A
        assert '10-' + other not in await rsp.text()
        rsp = await listeners[tid].get(
            '/confluent-api/self/profileprivate/pending/secret', headers=HEADERS)
        assert rsp.status == 200 and await rsp.read() == b'secret of ' + tid.encode()
    private = tenantpaths.private_root(A)
    os.symlink(os.path.join(tenantpaths.private_root(B), 'os/p1/pending/secret'),
               os.path.join(private, 'os/p1/pending/stolen'))
    rsp = await listeners[A].get(
        '/confluent-api/self/profileprivate/pending/stolen', headers=HEADERS)
    assert rsp.status == 404
    # private content is for authenticated nodes only
    rsp = await listeners[A].get('/confluent-api/self/profileprivate/pending/secret',
                                 headers={'CONFLUENT_NODENAME': 'n1'})
    assert rsp.status == 401
    assert (await listeners[A].get('/confluent-public/../private/os/p1/pending/secret')
            ).status == 404


async def test_long_boot_urls_are_shortened_per_tenant(listeners):
    tenantnet.enter(A)
    short = pxe.register_shorturl(
        'https://10.241.34.1/confluent-public/os/p1/boot.img', False,
        '/confluent-public/os/p1/boot.img', pxe._public('os', 'p1', 'boot.img'))
    redirect = pxe.register_shorturl('http://10.241.34.1/confluent-public/os/p1/boot.ipxe')
    tenantnet.enter(None)
    path = short[len('https://10.241.34.1'):]
    rsp = await listeners[A].get(path)
    assert rsp.status == 200 and await rsp.read() == IMAGE[A]
    rsp = await listeners[A].get(redirect[len('http://10.241.34.1'):], allow_redirects=False)
    assert rsp.status == 302
    assert rsp.headers['Location'] == 'http://10.241.34.1/confluent-public/os/p1/boot.ipxe'
    # the other tenant has no such name
    assert (await listeners[B].get(path)).status == 404
    assert dict(pxe.shorturls.for_tenant(None)) == {}


async def test_boot_paths_follow_the_tasks_tenant(tenancy):
    _create(A)
    assert pxe._public('os', 'p1') == os.path.join(tenancy, 'public/os/p1')
    tenantnet.enter(A)
    assert pxe._public('os', 'p1') == os.path.join(tenancy, 'tenants', A, 'public/os/p1')


async def test_host_facts_are_looked_up_outside_the_tenant(tenancy):
    _create(A)

    async def who():
        return tenantguard.current_tenant.get(), tenantnet.current_network()
    tenantnet.enter(A)
    assert await tenantnet.outside_tenant(who()) == (None, None)
    assert tenantguard.current_tenant.get() == A  # and the caller is as it was


def _csr(common_name, names):
    key = ec.generate_private_key(ec.SECP256R1())
    request = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
               .add_extension(x509.SubjectAlternativeName(
                   [x509.DNSName(n) for n in names]), critical=False)
               .sign(key, hashes.SHA256()))
    return request.public_bytes(serialization.Encoding.PEM), key


async def test_node_certificates_come_from_the_tenants_authority(tenancy):
    _create(A)
    _create(B)
    # whatever the request asks for, the node gets its own name and names
    csr, key = _csr(u'some-other-node', [u'confluent', u'*.example.com'])
    pem = await tenantca.sign_node_certificate(A, csr, 'n1', ['n1', '10.241.34.50'], 47)
    cert = x509.load_pem_x509_certificate(pem)
    assert cert.subject.rfc4514_string() == 'CN=n1'
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == ['n1']
    assert [str(ip) for ip in names.get_values_for_type(x509.IPAddress)] == ['10.241.34.50']
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert 46 <= lifetime.days <= 47
    authority, _ = await tenantca.get_ca(A)
    other, _ = await tenantca.get_ca(B)
    authority.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                  ec.ECDSA(hashes.SHA384()))
    assert cert.issuer == authority.subject and cert.issuer != other.subject
    with pytest.raises(ValueError):
        await tenantca.sign_node_certificate(A, b'not a request', 'n1', ['n1'], 47)


# ------------------------------------------- within the tenant networks

NODE = r'''
# A node fetching from its deployment server: optional authority to trust,
# optional API key, optional body to POST. Writes what it got.
import base64, json, os, ssl, sys, urllib.error, urllib.request
url, cafile, key, bodyfile, out = sys.argv[1:6]
result = {}
try:
    context = ssl.create_default_context(cafile=cafile) if cafile != '-' else None
    headers = {'Accept': 'application/json'}
    if key != '-':
        headers.update({'CONFLUENT_NODENAME': 'n1', 'CONFLUENT_APIKEY': key})
    data = None
    if bodyfile != '-':
        with open(bodyfile, 'rb') as f:
            data = f.read()
    request = urllib.request.Request(url, headers=headers, data=data)
    with urllib.request.urlopen(request, context=context, timeout=5) as rsp:
        result = {'status': rsp.status, 'body': base64.b64encode(rsp.read()).decode()}
except urllib.error.HTTPError as e:
    result = {'status': e.code}
except Exception as e:
    result = {'error': type(getattr(e, 'reason', e)).__name__}
with open(out + '.tmp', 'w') as f:
    json.dump(result, f)
os.rename(out + '.tmp', out)
'''

SEARCH = r'''
# A node looking for its deployment server by SSDP, as the deployment
# environment does, naming itself by UUID.
import json, os, socket, sys
uuid, out = sys.argv[1:3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'hw0')
s.settimeout(4)
s.sendto(('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
          'ST: urn:xcat.org:service:confluent:/uuid=' + uuid + '\r\n\r\n').encode(),
         ('239.255.255.250', 1900))
result = {'reply': None}
try:
    data, peer = s.recvfrom(4096)
    result = {'reply': data.decode(), 'from': peer[0]}
except socket.timeout:
    pass
with open(out + '.tmp', 'w') as f:
    json.dump(result, f)
os.rename(out + '.tmp', out)
'''


@pytest.fixture
async def topo(netns, tenancy):
    topology = Topology(netns)
    os.chmod(tenancy, 0o755)
    topology.cafile = {}
    topology.runs = 0
    tenantguard.recent_violations.clear()
    for tid in TENANTS:
        topology.network(tid)
        _create(tid)
    _trees(tenancy)
    for tid in TENANTS:
        await _until(lambda tid=tid: services.status(tid) and disco.tenant_detection_status(tid))
        topology.cafile[tid] = os.path.join(topology.dir, 'ca-%s.pem' % tid)
        with open(topology.cafile[tid], 'wb') as f:
            f.write(await tenantca.ca_pem(tid))
    yield topology
    for tid in TENANTS:
        services.stop(tid)
        disco.stop_tenant_detection(tid)
    tenantnet.enter(None)
    assert list(tenantguard.recent_violations) == []
    topology.cleanup()


async def _result(topo, path, timeout=20):
    await _until(lambda: os.path.exists(path), timeout=timeout)
    with open(path) as f:
        return json.load(f)


async def _fetch(topo, tid, url, key='-', cafile=None, body=None):
    import base64
    topo.runs += 1
    out = os.path.join(topo.dir, 'fetch-%d.json' % topo.runs)
    bodyfile = '-'
    if body is not None:
        bodyfile = out + '.body'
        with open(bodyfile, 'wb') as f:
            f.write(body)
    if cafile is None:
        cafile = topo.cafile[tid] if url.startswith('https') else '-'
    topo.netns.spawn(topo.lan[tid], sys.executable, '-c', NODE, url, cafile, key, bodyfile, out)
    result = await _result(topo, out)
    if 'body' in result:
        result['body'] = base64.b64decode(result['body'])
    return result


async def _dhcp(topo, tid, mode, patience=3):
    out = topo.dhcp_client(tid, MAC, mode, RAW_UUID.hex(), patience)
    return await _result(topo, out, timeout=4 * patience + 10)


@pytest.mark.netns
async def test_http_boot_is_offered_from_the_tenants_own_content(topo):
    hits = topo.decoy_hits()
    # tenant a gives the node a static address, tenant b leaves it to DHCP
    await _nodes(A)
    await _nodes(B, **{'net.ipv4_method': 'dhcp'})
    await _until(lambda: MAC in pxe.macmap.for_tenant(A) and MAC in pxe.macmap.for_tenant(B))
    url = 'https://%s/confluent-public/os/p1/boot.img' % UP_IP
    offers = dict(zip((A, B), await asyncio.gather(
        _dhcp(topo, A, 'httpboot'), _dhcp(topo, B, 'httpboot'))))
    for tid in (A, B):
        offer = offers[tid]['offer']
        assert offer and offer['bootfile'] == url and offer['vendor'] == 'HTTPClient'
        assert offer['server'] == UP_IP
    # the addressing each tenant chose applies at boot time too
    assert offers[A]['offer']['yiaddr'] == ADDRESS[A]
    assert offers[A]['offer']['netmask'] == '255.255.255.0'
    assert offers[B]['offer']['yiaddr'] == '0.0.0.0'
    # and what is offered is the tenant's own image, under its authority
    for tid in (A, B):
        fetched = await _fetch(topo, tid, url)
        assert fetched.get('status') == 200 and fetched['body'] == IMAGE[tid], fetched
    other = await _fetch(topo, A, url, cafile=topo.cafile[B])
    assert other.get('error') == 'SSLCertVerificationError'
    assert (await _fetch(topo, A, 'https://%s/confluent-public/os/hostonly/boot.img' % UP_IP)
            )['status'] == 404
    assert topo.decoy_hits() == hits


@pytest.mark.netns
async def test_ipxe_is_offered_and_firmware_pxe_is_not(topo):
    await _nodes(A, **{'deployment.useinsecureprotocols': 'always'})
    await _nodes(B, **{'deployment.useinsecureprotocols': 'always'})
    await _until(lambda: MAC in pxe.macmap.for_tenant(A) and MAC in pxe.macmap.for_tenant(B))
    # firmware PXE would fetch its boot file by TFTP: no offer
    assert (await _dhcp(topo, B, 'pxe', patience=2))['offer'] is None
    booted = await _dhcp(topo, A, 'ipxe')
    assert booted['offer'] and booted['offer']['yiaddr'] == ADDRESS[A]
    assert booted['offer']['vendor'] == 'PXEClient'
    url = 'http://%s/confluent-public/os/p1/boot.ipxe' % UP_IP
    assert booted['proxy'] and booted['proxy']['bootfile'] == url
    fetched = await _fetch(topo, A, url)
    assert fetched.get('status') == 200 and fetched['body'] == b'#!ipxe ' + IMAGE[A]
    # boot content is served without TLS, the node API never
    assert (await _fetch(topo, A, 'http://%s/confluent-api/self/myattribs' % UP_IP, key=KEY)
            )['status'] == 404


@pytest.mark.netns
async def test_deployment_api_answers_from_the_tenants_configuration(topo):
    await _nodes(A)
    await _nodes(B, **{'net.ipv4_method': 'dhcp', 'deployment.pendingprofile': 'p1',
                       'dns.domain': 'b.example'})
    seen = {}
    for tid in (A, B):
        answer = await _fetch(topo, tid, 'https://%s/confluent-api/self/deploycfg' % UP_IP, key=KEY)
        assert answer.get('status') == 200, answer
        seen[tid] = json.loads(answer['body'])
        assert seen[tid]['profile'] == 'p1'
        assert seen[tid]['confluent_uuid'] == configmanager.ConfigManager(tid).service_uuid()
        assert seen[tid]['deploy_server'] == UP_IP
    assert seen[A]['ipv4_method'] == 'static' and seen[A]['ipv4_address'] == ADDRESS[A]
    assert seen[B]['ipv4_method'] == 'dhcp' and not seen[B]['ipv4_address']
    assert seen[B]['dnsdomain'] == 'b.example' and not seen[A]['dnsdomain']
    assert seen[A]['confluent_uuid'] != seen[B]['confluent_uuid']
    # a certificate for the node, from its tenant's authority
    csr, _ = _csr(u'n1', [u'n1'])
    answer = await _fetch(topo, A, 'https://%s/confluent-api/self/tlscert' % UP_IP,
                          key=KEY, body=csr)
    assert answer.get('status') == 200, answer
    cert = x509.load_pem_x509_certificate(answer['body'])
    authority, _ = await tenantca.get_ca(A)
    assert cert.issuer == authority.subject
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ADDRESS[A] in [str(ip) for ip in names.get_values_for_type(x509.IPAddress)]
    # and one for its SSH host key, from its tenant's SSH authority
    if tenantssh.available():
        hostkey = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        answer = await _fetch(topo, A, 'https://%s/confluent-api/self/sshcert' % UP_IP,
                              key=KEY, body=hostkey)
        assert answer.get('status') == 200, answer
        sshcert = serialization.load_ssh_public_identity(answer['body'])
        sshcert.verify_cert_signature()
        assert b'n1' in sshcert.valid_principals
        assert ADDRESS[A].encode() in sshcert.valid_principals
        signer = sshcert.signature_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        assert tenantssh.ca_public(A).startswith(signer + b' ')
        assert not tenantssh.ca_public(B).startswith(signer + b' ')
    # status reports land in the reporting node's tenant
    answer = await _fetch(topo, A, 'https://%s/confluent-api/self/updatestatus' % UP_IP,
                          key=KEY, body=b'status: complete\n')
    assert answer.get('status') == 200, answer
    profile = {tid: configmanager.ConfigManager(tid).get_node_attributes(
        'n1', 'deployment.*')['n1'] for tid in (A, B)}
    assert profile[A]['deployment.profile']['value'] == 'p1'
    assert not profile[A].get('deployment.pendingprofile', {}).get('value')
    assert profile[A]['deployment.client_ip']['value'] == HW_IP
    assert profile[B]['deployment.pendingprofile']['value'] == 'p1'
    assert 'deployment.profile' not in profile[B]


@pytest.mark.netns
async def test_search_for_the_deployment_server_is_answered_per_tenant(topo):
    await _nodes(A)
    await _nodes(B, **{'deployment.pendingprofile': ''})
    for tid in (A, B):
        await _until(lambda tid=tid: UUID in disco.nodes_by_uuid.for_tenant(tid))
    outs = {}
    for tid in (A, B):
        outs[tid] = os.path.join(topo.dir, 'search-' + tid)
        topo.netns.spawn(topo.lan[tid], sys.executable, '-c', SEARCH, UUID, outs[tid])
    found = {tid: await _result(topo, outs[tid]) for tid in (A, B)}
    assert found[A]['reply'] and 'NODENAME: n1' in found[A]['reply']
    assert found[A]['from'] == UP_IP
    # the same node in tenant b has nothing pending: no answer there
    assert found[B] == {'reply': None}
