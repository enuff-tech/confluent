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

"""Two tenants with identical networks, for namespace tests.

Each tenant has a namespace (as on a real service) with up0 at
10.241.34.1/24, cabled to a "LAN" namespace whose hardware sits at
10.241.34.2 with the same MAC in both tenants. The hardware identifies
itself (t1-hw / t2-hw) over TCP 7000 and UDP 7001, and can also run a fake
IPMI BMC and a fake HTTPS (Redfish-like) endpoint. The host namespace gets
the same CIDR, routed to a decoy that counts every contact, so any fallback
to the host network is visible. Brokers run as nobody with only CAP_NET_RAW
and CAP_NET_BIND_SERVICE, from a copy of nsbroker.py so they need no
access to the source tree.
"""

import datetime
import os
import shutil
import sys
import tempfile
import time

import confluent.nsbroker as nsbroker
import confluent.tenantnet as tenantnet

HW_IP = '10.241.34.2'
UP_IP = '10.241.34.1'
UP_MAC = '02:00:00:aa:34:01'
HW_MAC = '02:00:00:aa:34:02'
TENANTS = {'t00000000000a': ('t1-hw', 61), 't00000000000b': ('t2-hw', 62)}
BROKER_UID = 65534   # nobody
CLIENT_UID = 65533   # an unprivileged service account
BMC_USER = 'admin'
BMC_PASSWORD = 'same-in-every-tenant'
SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SERVICE = r'''
import json, socket, sys, threading, time
label, countfile, ready = sys.argv[1:4]
def bump():
    if countfile != '-':
        with open(countfile, 'a') as f:
            f.write('x')
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 7000)); s.listen(16)
    open(ready, 'w').close()
    while True:
        c, a = s.accept(); bump()
        c.sendall(json.dumps({'label': label, 'peer': a[0]}).encode() + b'\n'); c.close()
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', 7001))
    while True:
        d, a = s.recvfrom(2048); bump(); s.sendto(json.dumps({'label': label}).encode(), a)
threading.Thread(target=udp, daemon=True).start()
tcp()
'''

BMC = r'''
import asyncio, sys
sys.path.insert(0, sys.argv[1])
import aiohmi.ipmi.bmc as bmc
user, password, state = sys.argv[2:5]
class FakeBmc(bmc.Bmc):
    def get_power_state(self):
        return state
asyncio.run(FakeBmc({user: password}).listen())
'''

HTTPS = r'''
import asyncio, ssl, sys
from aiohttp import web
label, cert, key, ready = sys.argv[1:5]
async def identity(request):
    return web.json_response({'label': label, 'path': request.path})
async def main():
    app = web.Application()
    app.router.add_get('/{tail:.*}', identity)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, '0.0.0.0', 443, ssl_context=ctx).start()
    open(ready, 'w').close()
    await asyncio.Event().wait()
asyncio.run(main())
'''

CLIENT = r'''
import array, json, socket, struct, sys
path = sys.argv[1]
c = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); c.connect(path)
def call(msgid, op, args):
    c.send(json.dumps({'v': 1, 'id': msgid, 'op': op, 'args': args}).encode())
    fds = array.array('i')
    data, anc, _, _ = c.recvmsg(65536, socket.CMSG_SPACE(4))
    for lvl, typ, cd in anc:
        fds.frombytes(cd[:len(cd) - len(cd) % 4])
    return json.loads(data), fds
call(1, 'hello', {})
rsp, fds = call(2, 'connect_tcp', {'family': 'inet', 'host': sys.argv[2], 'port': 7000})
s = socket.socket(fileno=fds[0]); s.setblocking(True)
caps = [l for l in open('/proc/self/status') if l.startswith('CapEff')][0].split()[1]
print(json.dumps({'caps': caps, 'uid': __import__('os').getuid(),
                  'reply': json.loads(s.makefile().readline())}))
'''


def _self_signed(certfile, keyfile):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'fake-bmc')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(HW_IP))]), critical=False)
            .sign(key, hashes.SHA256()))
    with open(certfile, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))


class Topology(object):
    def __init__(self, netns):
        self.netns = netns
        self.dir = tempfile.mkdtemp(prefix='cftnet')
        os.chmod(self.dir, 0o755)
        self.broker_py = os.path.join(self.dir, 'broker.py')
        shutil.copy(nsbroker.__file__, self.broker_py)
        os.chmod(self.broker_py, 0o644)
        self.ns = {}
        self.lan = {}
        self.brokers = {}
        self.etc = []
        for tid, (label, ttl) in TENANTS.items():
            ns, lan = netns.create(), netns.create()
            netns.veth(ns, 'up0', UP_IP + '/24', lan, 'hw0', HW_IP + '/24',
                       mac_a=UP_MAC, mac_b=HW_MAC)
            netns.run(lan, 'sysctl', '-qw', 'net.ipv4.ip_default_ttl=%d' % ttl)
            self.ns[tid], self.lan[tid] = ns, lan
            self._service(lan, label, '-')
            etc = os.path.join('/etc/netns', ns)
            os.makedirs(etc)
            self.etc.append(etc)
            with open(os.path.join(etc, 'hosts'), 'w') as f:
                f.write('127.0.0.1 localhost\n%s bmc-a\n' % (
                    '10.241.34.2' if label == 't1-hw' else '10.241.34.99'))
            os.makedirs(os.path.join(self.dir, tid))
            os.chmod(os.path.join(self.dir, tid), 0o777)
        self.decoy = netns.create()
        netns.veth(None, None, UP_IP + '/24', self.decoy, 'hw0', HW_IP + '/24')
        netns.run(self.decoy, 'sysctl', '-qw', 'net.ipv4.ip_default_ttl=63')
        self.decoy_count = os.path.join(self.dir, 'decoy.count')
        open(self.decoy_count, 'w').close()
        self._service(self.decoy, 'HOST', self.decoy_count)
        for tid in TENANTS:
            self.start_broker(tid)

    def _service(self, ns, label, countfile):
        ready = os.path.join(self.dir, 'ready-' + ns)
        self.netns.spawn(ns, sys.executable, '-c', SERVICE, label, countfile, ready)
        wait(lambda: os.path.exists(ready))

    def start_bmc(self, tid, state):
        """A fake IPMI BMC at HW_IP:623 in the tenant's LAN."""
        self.netns.spawn(self.lan[tid], sys.executable, '-c', BMC, SERVER_DIR,
                         BMC_USER, BMC_PASSWORD, state)

    def start_https(self, tid):
        """A fake HTTPS endpoint at HW_IP:443 that names its tenant."""
        cert = os.path.join(self.dir, 'cert.pem')
        key = os.path.join(self.dir, 'key.pem')
        if not os.path.exists(cert):
            _self_signed(cert, key)
        ready = os.path.join(self.dir, 'https-ready-' + tid)
        self.netns.spawn(self.lan[tid], sys.executable, '-c', HTTPS,
                         TENANTS[tid][0], cert, key, ready)
        wait(lambda: os.path.exists(ready))

    def socket_path(self, tid):
        return os.path.join(self.dir, tid, 'broker.sock')

    def start_broker(self, tid, ns=None, uid=BROKER_UID):
        path = self.socket_path(tid)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        caps = '-all,+net_raw,+net_bind_service'
        proc = self.netns.spawn(
            ns or self.ns[tid], 'setpriv', '--reuid=%d' % uid, '--regid=%d' % uid,
            '--clear-groups', '--inh-caps=' + caps, '--ambient-caps=' + caps,
            '--bounding-set=' + caps, '--no-new-privs', sys.executable, '-I',
            self.broker_py, '--tenant', tid, '--socket', path,
            '--allow-uid', '0', '--allow-uid', str(CLIENT_UID))
        wait(lambda: os.path.exists(path))
        self.brokers[tid] = proc
        return proc

    def stop_broker(self, tid):
        proc = self.brokers.pop(tid)
        proc.kill()
        proc.wait()

    def network(self, tid, uid=BROKER_UID):
        return tenantnet.register_network(tid, self.socket_path(tid), uid,
                                          os.path.join('/run/netns', self.ns[tid]))

    def decoy_hits(self):
        with open(self.decoy_count) as f:
            return len(f.read())

    def cleanup(self):
        for tid in TENANTS:
            tenantnet.close_tenant(tid)
        for etc in self.etc:
            shutil.rmtree(etc, ignore_errors=True)
        shutil.rmtree(self.dir, ignore_errors=True)


def wait(cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    raise AssertionError('timed out')
