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

"""Tenant networks through brokers, in real network namespaces.

Two tenants get identical networks: the same CIDR, addresses, interface
name and MACs, each with "hardware" at 10.241.34.2 that identifies
itself. The host namespace gets the same CIDR too, routed to a decoy that
counts every contact, so any fallback to the host network is visible.
"""

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

import pytest

import confluent.config.configmanager as configmanager
import confluent.nsbroker as nsbroker
import confluent.tenantguard as tenantguard
import confluent.tenantnet as tenantnet

pytestmark = pytest.mark.netns

HW_IP = '10.241.34.2'
UP_IP = '10.241.34.1'
UP_MAC = '02:00:00:aa:34:01'
HW_MAC = '02:00:00:aa:34:02'
TENANTS = {'t00000000000a': ('t1-hw', 61), 't00000000000b': ('t2-hw', 62)}
BROKER_UID = 65534   # nobody
CLIENT_UID = 65533   # an unprivileged service account

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
                f.write('127.0.0.1 localhost\n%s bmc-a\n' % ('10.241.34.2' if label == 't1-hw' else '10.241.34.99'))
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
        self._wait(lambda: os.path.exists(ready))

    @staticmethod
    def _wait(cond, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.05)
        raise AssertionError('timed out')

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
        self._wait(lambda: os.path.exists(path))
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


@pytest.fixture
def topo(netns):
    topology = Topology(netns)
    yield topology
    topology.cleanup()


def _label(sock):
    sock.setblocking(True)
    sock.settimeout(5)
    try:
        return json.loads(sock.makefile().readline())['label']
    finally:
        sock.close()


def _host_label():
    sock = socket.create_connection((HW_IP, 7000), timeout=5)
    return _label(sock)


def test_broker_is_attested_and_holds_two_capabilities(topo):
    inodes = set()
    for tid in TENANTS:
        net = topo.network(tid)
        net.list_interfaces()
        att = net.broker.attestation
        assert att['peer_uid'] == BROKER_UID and att['tenant'] == tid
        assert att['netns_ino'] == os.stat('/run/netns/' + topo.ns[tid]).st_ino
        assert int(att['proc']['CapEff'], 16) == (1 << 13) | (1 << 10)
        inodes.add(att['netns_ino'])
    assert len(inodes) == 2


def test_identical_networks_stay_separate(topo):
    views = {}
    for tid, (label, _) in TENANTS.items():
        net = topo.network(tid)
        assert _label(net.connect_tcp(HW_IP, 7000)) == label
        sock = net.udp_socket()
        sock.setblocking(True)
        sock.settimeout(5)
        sock.sendto(b'ping', (HW_IP, 7001))
        assert json.loads(sock.recv(2048))['label'] == label
        sock.close()
        up0 = [i for i in net.list_interfaces() if i['name'] == 'up0'][0]
        views[tid] = (up0['mac'], up0['ipv4'])
    assert views['t00000000000a'] == views['t00000000000b'] == (UP_MAC, [UP_IP + '/24'])
    hits = topo.decoy_hits()
    assert _host_label() == 'HOST'  # the default tenant uses the host network
    assert topo.decoy_hits() == hits + 1


def test_listeners_raw_and_packet_sockets(topo):
    for tid, (label, ttl) in TENANTS.items():
        net = topo.network(tid)
        listener = net.listen_tcp(80)
        listener.setblocking(True)
        listener.settimeout(5)
        topo.netns.run(topo.lan[tid], sys.executable, '-c',
                       'import socket; socket.create_connection(("%s", 80), 5).sendall(b"%s")'
                       % (UP_IP, label))
        conn, _ = listener.accept()
        assert conn.recv(64) == label.encode()
        conn.close()
        listener.close()

        raw = net.raw_icmp()
        raw.setblocking(True)
        raw.settimeout(5)
        ident = 0x3400 + ttl
        packet = struct.pack('!BBHHH', 8, 0, 0, ident, 1) + b'confluent!'
        csum = sum(struct.unpack('!%dH' % (len(packet) // 2), packet))
        csum = ~((csum & 0xffff) + (csum >> 16)) & 0xffff
        raw.sendto(packet[:2] + struct.pack('!H', csum) + packet[4:], (HW_IP, 0))
        while True:
            data = raw.recv(2048)
            ihl = (data[0] & 0xf) * 4
            if data[ihl] == 0 and struct.unpack('!H', data[ihl + 4:ihl + 6])[0] == ident:
                assert data[8] == ttl  # the reply came from this tenant's hardware
                break
        raw.close()

        frames, ifindex = net.packet_socket('up0', 0x0806)
        frames.setblocking(True)
        frames.settimeout(5)
        topo.netns.run(topo.lan[tid], sys.executable, '-c',
                       'import socket; s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); '
                       's.bind(("hw0", 0)); s.send(b"\\xff" * 6 + s.getsockname()[4] + '
                       'b"\\x08\\x06" + b"%s")' % label)
        while True:
            frame = frames.recv(2048)
            if frame[14:].startswith(label.encode()):
                break
        frames.close()


def test_names_resolve_inside_each_tenant(topo):
    assert topo.network('t00000000000a').resolve('bmc-a') == ['10.241.34.2']
    assert topo.network('t00000000000b').resolve('bmc-a') == ['10.241.34.99']


def test_broker_failure_fails_closed(topo):
    net = topo.network('t00000000000a')
    listener = net.listen_tcp(80)
    listener.setblocking(True)
    listener.settimeout(5)
    hits = topo.decoy_hits()
    topo.stop_broker('t00000000000a')
    with pytest.raises(tenantnet.TenantNetworkUnavailable):
        net.connect_tcp(HW_IP, 7000)
    with pytest.raises(tenantnet.TenantNetworkUnavailable):
        net.udp_socket()
    assert _label(topo.network('t00000000000b').connect_tcp(HW_IP, 7000)) == 't2-hw'
    # sockets already handed over keep working, still in the tenant's network
    topo.netns.run(topo.lan['t00000000000a'], sys.executable, '-c',
                   'import socket; socket.create_connection(("%s", 80), 5).sendall(b"after")' % UP_IP)
    conn, _ = listener.accept()
    assert conn.recv(16) == b'after'
    conn.close()
    assert topo.decoy_hits() == hits
    # a restarted broker is checked again and used
    topo.start_broker('t00000000000a')
    assert _label(net.connect_tcp(HW_IP, 7000)) == 't1-hw'


def test_broker_in_the_wrong_namespace_is_rejected(topo):
    topo.stop_broker('t00000000000a')
    topo.start_broker('t00000000000a', ns=topo.ns['t00000000000b'])
    with pytest.raises(tenantnet.BrokerRejected):
        topo.network('t00000000000a').connect_tcp(HW_IP, 7000)


def test_broker_with_the_wrong_uid_is_rejected(topo):
    with pytest.raises(tenantnet.BrokerRejected):
        topo.network('t00000000000a', uid=BROKER_UID - 2).connect_tcp(HW_IP, 7000)


def test_close_tenant_closes_its_sockets(topo):
    net = topo.network('t00000000000a')
    sock = net.udp_socket()
    other = topo.network('t00000000000b').udp_socket()
    tenantnet.close_tenant('t00000000000a')
    assert sock.fileno() == -1
    assert other.fileno() != -1
    with pytest.raises(tenantnet.TenantNetworkUnavailable):
        net.udp_socket()
    other.close()


async def test_disabling_a_tenant_closes_its_sockets(topo, confluent_config):
    configmanager.init_masterkey()
    configmanager.set_global('multitenancy.enabled', True)
    configmanager._true_create_tenant('t00000000000a', 'acme',
                                      configmanager._wrap_tenant_key(os.urandom(32)), 0)
    sock = topo.network('t00000000000a').udp_socket()
    await configmanager.set_tenant_state('t00000000000a', 'disabled')
    assert sock.fileno() == -1


def test_service_needs_no_capabilities_to_use_a_broker(topo):
    script = os.path.join(topo.dir, 'client.py')
    with open(script, 'w') as f:
        f.write(CLIENT)
    os.chmod(script, 0o644)
    out = subprocess.run(
        ['setpriv', '--reuid=%d' % CLIENT_UID, '--regid=%d' % BROKER_UID, '--clear-groups',
         '--inh-caps=-all', '--ambient-caps=-all', '--bounding-set=-all', '--no-new-privs',
         sys.executable, '-I', script, topo.socket_path('t00000000000a'), HW_IP],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout)
    assert result['uid'] == CLIENT_UID and int(result['caps'], 16) == 0
    assert result['reply']['label'] == 't1-hw'


def test_guard_admits_the_tenants_brokered_sockets_only(topo):
    tenantguard.install()
    net = topo.network('t00000000000a')
    hits = topo.decoy_hits()
    with tenantguard.tenant_context('t00000000000a'):
        assert _label(net.connect_tcp(HW_IP, 7000)) == 't1-hw'
        udp = net.udp_socket()
        udp.sendto(b'ping', (HW_IP, 7001))  # brokered: allowed
        udp.close()
        with pytest.raises(tenantguard.TenantNetworkViolation):
            socket.create_connection((HW_IP, 7000), timeout=2)
    assert topo.decoy_hits() == hits
