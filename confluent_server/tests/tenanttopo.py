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
import json
import os
import shutil
import sys
import tempfile
import time

import confluent.nsbroker as nsbroker
import confluent.nsnetcfg as nsnetcfg
import confluent.tenantnet as tenantnet

HW_IP = '10.241.34.2'
UP_IP = '10.241.34.1'
UP_MAC = '02:00:00:aa:34:01'
HW_MAC = '02:00:00:aa:34:02'
TENANTS = {'t00000000000a': ('t1-hw', 61), 't00000000000b': ('t2-hw', 62)}
BROKER_UID = 65534   # nobody
CLIENT_UID = 65533   # an unprivileged service account
NETCFG_UID = 65532   # the network configuration helper's account
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

SSH = r'''
import asyncio, sys
import asyncssh
label, user, password, ready = sys.argv[1:5]
class Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True
    def password_auth_supported(self):
        return True
    def validate_password(self, username, pw):
        return username == user and pw == password
async def handle(process):
    process.stdout.write(label + '\n')
    process.exit(0)
async def main():
    key = asyncssh.generate_private_key('ssh-ed25519')
    await asyncssh.create_server(Server, '0.0.0.0', 22, server_host_keys=[key],
                                 process_factory=handle)
    open(ready, 'w').close()
    await asyncio.Event().wait()
asyncio.run(main())
'''

HTTP = r'''
import http.server, sys
label, ready = sys.argv[1:3]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = label.encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
server = http.server.HTTPServer(('0.0.0.0', 80), Handler)
open(ready, 'w').close()
server.serve_forever()
'''

DHCP_CLIENT = r'''
# A DHCP client on hw0: DISCOVER (optionally as a PXE client), and for a
# plain client that is offered an address, REQUEST. Writes what it saw.
# As a client without an address does, it sends from 0.0.0.0 (so by
# packet socket) and takes the broadcast answers on port 68.
import json, os, socket, struct, sys, time
mac, mode, uuidhex, out, patience = sys.argv[1:6]
chaddr = bytes.fromhex(mac.replace(':', ''))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'hw0')
s.bind(('', 68))
raw = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
xid = os.urandom(4)
def csum(data):
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff
def send(options):
    pkt = struct.pack('!BBBB4sHH', 1, 1, 6, 0, xid, 0, 0x8000) + bytes(16)
    pkt += chaddr + bytes(10) + bytes(192) + bytes([99, 130, 83, 99])
    pkt += options + bytes([255])
    pkt += bytes(max(0, 300 - len(pkt)))
    udp = struct.pack('!HHHH', 68, 67, 8 + len(pkt), 0) + pkt
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes(4), bytes([255] * 4))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    raw.sendto(ip + udp, ('hw0', 0x0800, 0, 1, bytes([255] * 6)))
def opt(code, value):
    return bytes([code, len(value)]) + value
def answer(kind, deadline):
    while time.time() < deadline:
        s.settimeout(max(0.05, deadline - time.time()))
        try:
            data = s.recv(4096)
        except socket.timeout:
            break
        if len(data) < 240 or data[0] != 2 or data[4:8] != xid:
            continue
        options, idx = {}, 240
        while idx < len(data) and data[idx] != 255:
            options[data[idx]] = data[idx + 2:idx + 2 + data[idx + 1]]
            idx += 2 + data[idx + 1]
        if options.get(53) != bytes([kind]):
            continue
        return {'yiaddr': socket.inet_ntoa(data[16:20]),
                'server': socket.inet_ntoa(options.get(54, bytes(4))),
                'lease': struct.unpack('!I', options.get(51, bytes(4)))[0],
                'netmask': socket.inet_ntoa(options.get(1, bytes(4))),
                'gateway': socket.inet_ntoa(options.get(3, bytes(4))),
                'vendor': options.get(60, b'').decode(),
                'bootfile': data[108:236].rstrip(bytes(1)).decode()}
    return None
discover = opt(53, bytes([1]))
identity = b''
if mode in ('pxe', 'ipxe'):
    identity = opt(60, b'PXEClient:Arch:00007:UNDI:003016') + opt(93, bytes([0, 7]))
elif mode == 'httpboot':
    identity = opt(60, b'HTTPClient:Arch:00016:UNDI:003001') + opt(93, bytes([0, 16]))
if identity:
    identity += opt(97, bytes(1) + bytes.fromhex(uuidhex))
if mode == 'ipxe':
    identity += opt(77, b'iPXE')
send(discover + identity)
result = {'offer': answer(2, time.time() + float(patience)), 'ack': None}
if result['offer'] and mode == 'ipxe':
    # as a PXE client does next: ask the boot server (proxyDHCP) for the
    # boot file, from the address of this interface
    pkt = struct.pack('!BBBB4sHH', 1, 1, 6, 0, xid, 0, 0) + bytes(16)
    pkt += chaddr + bytes(10) + bytes(192) + bytes([99, 130, 83, 99])
    pkt += opt(53, bytes([3])) + identity + bytes([255])
    s.sendto(pkt, (result['offer']['server'], 4011))
    result['proxy'] = answer(5, time.time() + float(patience))
if result['offer'] and mode == 'plain':
    request = opt(53, bytes([3])) + opt(50, socket.inet_aton(result['offer']['yiaddr']))
    request += opt(54, socket.inet_aton(result['offer']['server']))
    send(request)
    result['ack'] = answer(5, time.time() + float(patience))
with open(out + '.tmp', 'w') as f:
    json.dump(result, f)
os.rename(out + '.tmp', out)
'''

SSDP_NOTIFY = r'''
# One SSDP NOTIFY (a Redfish service coming up) from hw0, by multicast.
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'hw0')
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(sys.argv[1]))
s.sendto(b'\r\n'.join([
    b'NOTIFY * HTTP/1.1', b'HOST: 239.255.255.250:1900',
    b'NT: urn:dmtf-org:service:redfish-rest:1', b'NTS: ssdp:alive',
    b'AL: https://' + sys.argv[1].encode() + b'/redfish/v1/',
    b'LOCATION: https://' + sys.argv[1].encode() + b'/redfish/v1/', b'', b'']),
    ('239.255.255.250', 1900))
'''

SNMP_AGENT = r'''
# A switch's SNMP agent (v2c: get, getnext, getbulk) on port 161. It
# answers only its own community string, from the table it is given, and
# records the community strings it was asked with.
import json, socket, sys
community, datafile, seen, ready = sys.argv[1:5]
def enc_len(n):
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw
def tlv(tag, body):
    return bytes([tag]) + enc_len(len(body)) + body
def enc_int(n):
    return tlv(2, n.to_bytes(n.bit_length() // 8 + 1, 'big', signed=True))
def enc_oid(oid):
    body = bytearray([oid[0] * 40 + oid[1]])
    for arc in oid[2:]:
        chunk = [arc & 0x7f]
        arc >>= 7
        while arc:
            chunk.insert(0, 0x80 | (arc & 0x7f))
            arc >>= 7
        body += bytes(chunk)
    return tlv(6, bytes(body))
def dec(data, pos):
    tag, n = data[pos], data[pos + 1]
    pos += 2
    if n & 0x80:
        size = n & 0x7f
        n = int.from_bytes(data[pos:pos + size], 'big')
        pos += size
    return tag, data[pos:pos + n], pos + n
def dec_oid(body):
    oid, arc = [body[0] // 40, body[0] % 40], 0
    for b in body[1:]:
        arc = (arc << 7) | (b & 0x7f)
        if not b & 0x80:
            oid.append(arc)
            arc = 0
    return tuple(oid)
def enc_value(value):
    kind, value = value
    if kind == 'i':
        return enc_int(value)
    if kind == 'o':
        return enc_oid(tuple(int(x) for x in value.split('.')))
    if kind == 'x':
        return tlv(4, bytes.fromhex(value))
    return tlv(4, value.encode())
with open(datafile) as f:
    table = sorted((tuple(int(x) for x in k.split('.')), v) for k, v in json.load(f).items())
def after(oid):
    for candidate, value in table:
        if candidate > oid:
            return candidate, enc_value(value)
    return oid, bytes([0x82, 0])  # endOfMibView
def exact(oid):
    for candidate, value in table:
        if candidate == oid:
            return oid, enc_value(value)
    return oid, bytes([0x81, 0])  # noSuchInstance
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 161))
open(ready, 'w').close()
while True:
    data, peer = s.recvfrom(65535)
    try:
        _, msg, _ = dec(data, 0)
        _, version, pos = dec(msg, 0)
        _, asked, pos = dec(msg, pos)
        kind, pdu, _ = dec(msg, pos)
        with open(seen, 'a') as f:
            f.write(asked.decode() + '\n')
        if asked.decode() != community:
            continue
        _, reqid, pos = dec(pdu, 0)
        _, first, pos = dec(pdu, pos)
        _, second, pos = dec(pdu, pos)
        _, binds, _ = dec(pdu, pos)
        oids, pos = [], 0
        while pos < len(binds):
            _, bind, pos = dec(binds, pos)
            oids.append(dec_oid(dec(bind, 0)[1]))
        answers = []
        if kind == 0xa0:
            answers = [exact(oid) for oid in oids]
        elif kind == 0xa1:
            answers = [after(oid) for oid in oids]
        elif kind == 0xa5:
            skip = int.from_bytes(first, 'big')
            answers = [after(oid) for oid in oids[:skip]]
            current = oids[skip:]
            for _ in range(int.from_bytes(second, 'big')):
                current = [after(oid) for oid in current]
                answers += current
                current = [oid for oid, _ in current]
        body = b''.join(tlv(0x30, enc_oid(oid) + value) for oid, value in answers)
        rsp = tlv(2, reqid) + enc_int(0) + enc_int(0) + tlv(0x30, body)
        s.sendto(tlv(0x30, tlv(2, version) + tlv(4, asked) + tlv(0xa2, rsp)), peer)
    except Exception:
        continue
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
        # the configuration helper is run from next to the broker
        self.netcfg_py = os.path.join(self.dir, 'nsnetcfg.py')
        shutil.copy(nsnetcfg.__file__, self.netcfg_py)
        os.chmod(self.netcfg_py, 0o644)
        shutil.copy(nsbroker.__file__, os.path.join(self.dir, 'nsbroker.py'))
        os.chmod(os.path.join(self.dir, 'nsbroker.py'), 0o644)
        self.helpers = {}
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
                f.write('%s sw1\n' % HW_IP)  # every tenant has a switch sw1
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

    def start_ssh(self, tid):
        """A fake SSH server at HW_IP:22 that prints its tenant's label."""
        ready = os.path.join(self.dir, 'ssh-ready-' + tid)
        self.netns.spawn(self.lan[tid], sys.executable, '-c', SSH, TENANTS[tid][0],
                         BMC_USER, BMC_PASSWORD, ready)
        wait(lambda: os.path.exists(ready))

    def start_http(self, tid):
        """A plain HTTP server at HW_IP:80 that answers with the label."""
        ready = os.path.join(self.dir, 'http-ready-' + tid)
        self.netns.spawn(self.lan[tid], sys.executable, '-c', HTTP, TENANTS[tid][0], ready)
        wait(lambda: os.path.exists(ready))

    def dhcp_client(self, tid, mac, mode='plain', uuidhex='', patience=3):
        """Start a DHCP client in the tenant's LAN; returns the file its
        result (JSON) appears in when it is done."""
        self._dhcp_runs = getattr(self, '_dhcp_runs', 0) + 1
        out = os.path.join(self.dir, 'dhcp-%s-%d.json' % (tid, self._dhcp_runs))
        self.netns.spawn(self.lan[tid], sys.executable, '-c', DHCP_CLIENT, mac,
                         mode, uuidhex, out, str(patience))
        return out

    def ssdp_notify(self, tid):
        self.netns.run(self.lan[tid], sys.executable, '-c', SSDP_NOTIFY, HW_IP)

    def start_snmp(self, tid, community, table):
        """A switch's SNMP agent at HW_IP:161 in the tenant's LAN, with
        the given table ({oid: [kind, value]}); returns the file listing
        the community strings it is asked with."""
        data = os.path.join(self.dir, 'snmp-%s.json' % tid)
        seen = os.path.join(self.dir, 'snmp-%s.seen' % tid)
        ready = os.path.join(self.dir, 'snmp-ready-' + tid)
        with open(data, 'w') as f:
            json.dump(table, f)
        open(seen, 'w').close()
        self.netns.spawn(self.lan[tid], sys.executable, '-c', SNMP_AGENT,
                         community, data, seen, ready)
        wait(lambda: os.path.exists(ready))
        return seen

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

    def netcfg_socket(self, tid):
        return os.path.join(self.dir, tid, 'netcfg.sock')

    def resolv_conf(self, tid):
        return os.path.join('/etc/netns', self.ns[tid], 'resolv.conf')

    def start_netcfg(self, tid, ns=None, uid=NETCFG_UID, caps='-all,+net_admin'):
        """The tenant's network configuration helper, as its unit runs it:
        in the tenant's namespace, unprivileged, with CAP_NET_ADMIN only."""
        path = self.netcfg_socket(tid)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        resolv = self.resolv_conf(tid)
        with open(resolv, 'w'):
            pass
        os.chown(resolv, uid, uid)
        proc = self.netns.spawn(
            ns or self.ns[tid], 'setpriv', '--reuid=%d' % uid, '--regid=%d' % uid,
            '--clear-groups', '--inh-caps=' + caps, '--ambient-caps=' + caps,
            '--bounding-set=' + caps, '--no-new-privs', sys.executable, '-I',
            self.netcfg_py, '--tenant', tid, '--socket', path, '--resolv', resolv,
            '--allow-uid', '0', '--allow-uid', str(CLIENT_UID))
        wait(lambda: os.path.exists(path))
        self.helpers[tid] = proc
        return proc

    def stop_netcfg(self, tid):
        proc = self.helpers.pop(tid)
        proc.kill()
        proc.wait()

    def netcfg(self, tid, uid=NETCFG_UID):
        return tenantnet.register_netcfg(tid, self.netcfg_socket(tid), uid,
                                         os.path.join('/run/netns', self.ns[tid]))

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
