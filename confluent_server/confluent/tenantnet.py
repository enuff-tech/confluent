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

"""Network access for tenants, through each tenant's broker.

This is the only way the confluent service obtains a network socket for a
tenant. There is no code path that creates a socket in the host's
namespace for a tenant: an unknown or unusable tenant, an unreachable
broker or a failed check of the broker always raises, and nothing is
created. Only the default tenant (None) uses the host's network, exactly
as before.

Each tenant's broker runs in network namespace cf-<id> as user cfnsb-<id>
and listens on /run/confluent/ns/<id>/broker.sock (see confluent.nsbroker
and confluent-netns). Before a broker is used, its peer uid must be that
tenant's broker user, and it must prove it runs in the namespace
registered for that tenant (inode of /run/netns/cf-<id>).
"""

import array
import asyncio
import collections
import ipaddress
import json
import os
import pwd
import socket
import struct
import threading
import weakref

import aiohmi.util.netcontext as netcontext
import aiohttp
import aiohttp.abc

import confluent.config.configmanager as configmanager
import confluent.tenantguard as tenantguard

PROTO_VERSION = 1
MAX_MSG = 65536
MAX_SOCKETS_PER_TENANT = 4096
MAX_IDLE_CONNECTIONS = 8
RUN_DIR = '/run/confluent/ns'
NETNS_DIR = '/run/netns'


def broker_user(tenantid):
    return 'cfnsb-' + tenantid


def netns_name(tenantid):
    return 'cf-' + tenantid


def broker_socket(tenantid):
    return os.path.join(RUN_DIR, tenantid, 'broker.sock')


class TenantNetworkError(Exception):
    """The operation was refused and nothing was created."""


class TenantNetworkUnavailable(TenantNetworkError):
    """The tenant's network cannot be reached right now."""


class BrokerRejected(TenantNetworkError):
    """The peer is not the tenant's broker, or misbehaved."""


class BrokerError(TenantNetworkError):
    def __init__(self, code, msg):
        super(BrokerError, self).__init__('{0}: {1}'.format(code, msg))
        self.code = code


_EXPECTED = {
    # op -> (domain or None for the requested family, type, protocol)
    'connect_tcp': (None, socket.SOCK_STREAM, socket.IPPROTO_TCP),
    'tcp_socket': (None, socket.SOCK_STREAM, socket.IPPROTO_TCP),
    'listen_tcp': (None, socket.SOCK_STREAM, socket.IPPROTO_TCP),
    'udp_socket': (None, socket.SOCK_DGRAM, socket.IPPROTO_UDP),
    'raw_icmp': (None, socket.SOCK_RAW, None),
    'packet_socket': (socket.AF_PACKET, None, None),
}
_FAMILIES = {'inet': socket.AF_INET, 'inet6': socket.AF_INET6}


class Broker(object):
    """Connections to one tenant's broker, each checked before use."""

    def __init__(self, tenantid, sockpath, broker_uid, netns_path):
        self.tenant = tenantid
        self.sockpath = sockpath
        self.broker_uid = broker_uid
        self.netns_path = netns_path
        self._idle = collections.deque()
        self._lock = threading.Lock()
        self._nextid = 0
        self.sockets = weakref.WeakSet()
        self.attestation = None
        self.closed = False

    def _expected_inode(self):
        try:
            return os.stat(self.netns_path).st_ino
        except OSError:
            raise TenantNetworkUnavailable(
                'tenant {0} has no network namespace'.format(self.tenant))

    def _open(self):
        conn = tenantguard.register_control(
            socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET))
        conn.settimeout(35)  # the broker's own operations time out at 30
        try:
            conn.connect(self.sockpath)
        except OSError as e:
            conn.close()
            raise TenantNetworkUnavailable(
                'tenant {0} broker unreachable: {1}'.format(self.tenant, e))
        pid, uid, _ = struct.unpack('3i', conn.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
        if uid != self.broker_uid:
            conn.close()
            raise BrokerRejected('tenant {0} broker runs as uid {1}, expected {2}'.format(
                self.tenant, uid, self.broker_uid))
        try:
            hello, fd = self._exchange(conn, 'hello', {})
        except TenantNetworkError:
            conn.close()
            raise
        expected = self._expected_inode()
        if hello.get('tenant') != self.tenant or hello.get('netns_ino') != expected:
            conn.close()
            raise BrokerRejected(
                'tenant {0} broker is not in the tenant namespace '
                '(tenant={1!r} netns={2!r}, expected {3!r})'.format(
                    self.tenant, hello.get('tenant'), hello.get('netns_ino'), expected))
        self.attestation = dict(hello, peer_pid=pid, peer_uid=uid)
        return conn

    def _exchange(self, conn, op, args):
        with self._lock:
            self._nextid += 1
            msgid = self._nextid
        request = json.dumps({'v': PROTO_VERSION, 'id': msgid, 'op': op,
                              'args': args}).encode()
        fds = array.array('i')
        try:
            conn.send(request)
            data, ancdata, flags, _ = conn.recvmsg(
                MAX_MSG, socket.CMSG_SPACE(fds.itemsize * 4))
        except OSError as e:
            raise TenantNetworkUnavailable(
                'tenant {0} broker connection lost: {1}'.format(self.tenant, e))
        for level, kind, cdata in ancdata:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(cdata[:len(cdata) - (len(cdata) % fds.itemsize)])
        if not data or flags & socket.MSG_CTRUNC or len(fds) > 1:
            for fd in fds:
                os.close(fd)
            if not data:
                raise TenantNetworkUnavailable(
                    'tenant {0} broker closed the connection'.format(self.tenant))
            raise BrokerRejected('tenant {0} broker sent unexpected descriptors'.format(
                self.tenant))
        try:
            response = json.loads(data.decode('utf8'))
        except ValueError:
            response = None
        if not isinstance(response, dict) or response.get('id') != msgid:
            for fd in fds:
                os.close(fd)
            raise BrokerRejected('tenant {0} broker sent a bad response'.format(self.tenant))
        sock = socket.socket(fileno=fds[0]) if fds else None
        if not response.get('ok'):
            if sock is not None:
                sock.close()
            error = response.get('error') or {}
            raise BrokerError(error.get('code'), error.get('msg'))
        return response.get('result') or {}, sock

    def call(self, op, args, want_socket=False):
        if self.closed:
            raise TenantNetworkUnavailable(
                'tenant {0} network is closed'.format(self.tenant))
        if want_socket and len(self.sockets) >= MAX_SOCKETS_PER_TENANT:
            raise TenantNetworkError('tenant {0} has too many open sockets'.format(
                self.tenant))
        try:
            conn = self._idle.popleft()
        except IndexError:
            conn = self._open()
        try:
            result, sock = self._exchange(conn, op, args)
        except BrokerError:
            self._release(conn)
            raise
        except TenantNetworkError:
            conn.close()
            raise
        self._release(conn)
        if not want_socket:
            if sock is not None:
                sock.close()
                raise BrokerRejected('tenant {0} broker sent an unrequested socket'.format(
                    self.tenant))
            return result, None
        if sock is None:
            raise BrokerRejected('tenant {0} broker sent no socket for {1}'.format(
                self.tenant, op))
        self._check_socket(op, args, sock)
        tenantguard.register(self.tenant, sock)
        self.sockets.add(sock)
        return result, sock

    def _release(self, conn):
        if self.closed or len(self._idle) >= MAX_IDLE_CONNECTIONS:
            conn.close()
        else:
            self._idle.append(conn)

    def _check_socket(self, op, args, sock):
        domain, kind, proto = _EXPECTED[op]
        if domain is None:
            domain = _FAMILIES[args['family']]
        ok = (sock.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == domain and
              (kind is None or sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == kind) and
              (proto is None or sock.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL) == proto))
        if not ok:
            sock.close()
            raise BrokerRejected('tenant {0} broker sent the wrong kind of socket for {1}'.format(
                self.tenant, op))

    def close(self):
        """Close every socket this tenant was given and stop using the
        broker (tenant disabled or deleted)."""
        self.closed = True
        while self._idle:
            self._idle.popleft().close()
        for sock in list(self.sockets):
            try:
                sock.close()
            except OSError:
                pass


class TenantNetwork(object):
    """The network API of one tenant. Blocking calls are for threads;
    the a-prefixed coroutines run them off the event loop."""

    def __init__(self, broker):
        self.broker = broker
        self.tenant = broker.tenant

    def connect_tcp(self, host, port, family='inet', timeout=10):
        return self.broker.call('connect_tcp', {'family': family, 'host': host,
                                                'port': port, 'timeout': timeout}, True)[1]

    def udp_socket(self, family='inet', port=0, broadcast=False, pktinfo=False,
                   reuseaddr=False):
        return self.broker.call('udp_socket', {
            'family': family, 'port': port, 'broadcast': broadcast,
            'pktinfo': pktinfo, 'reuseaddr': reuseaddr}, True)[1]

    def listen_tcp(self, port, family='inet', backlog=128):
        return self.broker.call('listen_tcp', {'family': family, 'port': port,
                                               'backlog': backlog}, True)[1]

    def raw_icmp(self, family='inet'):
        return self.broker.call('raw_icmp', {'family': family}, True)[1]

    def packet_socket(self, ifname, ethertype, kind='raw'):
        result, sock = self.broker.call('packet_socket', {
            'ifname': ifname, 'ethertype': ethertype, 'kind': kind}, True)
        return sock, result['ifindex']

    def list_interfaces(self):
        return self.broker.call('list_interfaces', {})[0]['interfaces']

    def resolve(self, name, family='inet'):
        return self.broker.call('resolve', {'name': name, 'family': family})[0]['addresses']

    def tcp_socket(self, family='inet'):
        """An unconnected TCP socket of the tenant's network: connecting it
        routes within the tenant's namespace."""
        return self.broker.call('tcp_socket', {'family': family}, True)[1]

    async def _offload(self, fn, *args):
        return await asyncio.get_running_loop().run_in_executor(None, fn, *args)

    async def aconnect_tcp(self, host, port, family='inet', timeout=10):
        return await self._offload(self.connect_tcp, host, port, family, timeout)

    async def aresolve(self, name, family='inet'):
        return await self._offload(self.resolve, name, family)

    async def alist_interfaces(self):
        return await self._offload(self.list_interfaces)


_FAMILY_NAMES = {socket.AF_INET: 'inet', socket.AF_INET6: 'inet6'}


def _family_name(family):
    if family in _FAMILY_NAMES:
        return _FAMILY_NAMES[family]
    if family in ('inet', 'inet6'):
        return family
    raise TenantNetworkError('unsupported address family {0!r}'.format(family))


def _literal_family(host):
    try:
        addr = ipaddress.ip_address(host.split('%', 1)[0])
    except ValueError:
        return None
    return socket.AF_INET if addr.version == 4 else socket.AF_INET6


class TenantNetworkRef(object):
    """A tenant's network for aiohmi (see aiohmi.util.netcontext).

    The broker is only reached when something actually needs the network,
    so configuration-only work never depends on it.
    """

    def __init__(self, tenantid):
        self.key = ('tenant', tenantid)
        self.tenant = tenantid

    def _net(self):
        return network_for(self.tenant)

    def udp_socket(self, family):
        return self._net().udp_socket(family=_family_name(family))

    def socket_factory(self, addrinfo):
        return self._net().tcp_socket(family=_family_name(addrinfo[0]))

    async def getaddrinfo(self, host, port):
        family = _literal_family(host)
        if family is not None:
            if family == socket.AF_INET6:
                return [(family, (host, port, 0, 0))]
            return [(family, (host, port))]
        net = self._net()
        found = []
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                addresses = await net.aresolve(host, _family_name(family))
            except BrokerError:
                continue
            for addr in addresses:
                found.append((family, (addr, port) if family == socket.AF_INET
                              else (addr, port, 0, 0)))
        if not found:
            raise socket.gaierror(socket.EAI_NONAME, 'cannot resolve ' + host)
        return found

    def resolver(self):
        return TenantResolver(self)

    async def alist_interfaces(self):
        """The interfaces of the tenant's namespace, as the broker reports
        them (name, index, up, mac, ipv4 and ipv6 address/prefix lists)."""
        return await self._net().alist_interfaces()


class TenantResolver(aiohttp.abc.AbstractResolver):
    """aiohttp name resolution within a tenant's network."""

    def __init__(self, ref):
        self.ref = ref

    async def resolve(self, host, port=0, family=socket.AF_INET):
        results = []
        for found, sockaddr in await self.ref.getaddrinfo(host, port):
            if family not in (socket.AF_UNSPEC, found):
                continue
            results.append({'hostname': host, 'host': sockaddr[0], 'port': port,
                            'family': found, 'proto': 0,
                            'flags': socket.AI_NUMERICHOST})
        if not results:
            raise OSError('cannot resolve ' + host)
        return results

    async def close(self):
        pass


def current_network():
    """The current task's tenant network (a TenantNetworkRef), or None for
    the default tenant."""
    return netcontext.current_network.get()


def _addresses_blocking(net, host, port):
    family = _literal_family(host)
    if family is not None:
        return [(family, (host, port) if family == socket.AF_INET else (host, port, 0, 0))]
    found = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            for addr in net._net().resolve(host, _family_name(family)):
                found.append((family, (addr, port) if family == socket.AF_INET
                              else (addr, port, 0, 0)))
        except BrokerError:
            continue
    if not found:
        raise socket.gaierror(socket.EAI_NONAME, 'cannot resolve ' + host)
    return found


def connect_blocking(host, port, timeout=None, setup=None):
    """For code that makes its own blocking TCP connections: a socket
    connected to host:port through the current tenant's network, or None
    for the default tenant (keep using the host network as before).
    setup(sock) may adjust the socket before it connects."""
    net = current_network()
    if net is None:
        return None
    last = None
    for family, sockaddr in _addresses_blocking(net, host, port):
        sock = net.socket_factory((family, socket.SOCK_STREAM, 0, '', sockaddr))
        sock.setblocking(True)
        sock.settimeout(timeout)
        if setup is not None:
            setup(sock)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as e:
            sock.close()
            last = e
    raise last or OSError('cannot connect to {0}'.format(host))


async def aconnect(host, port, timeout=10):
    """The asyncio form of connect_blocking: a connected, non-blocking
    socket through the current tenant's network, or None for the default
    tenant."""
    net = current_network()
    if net is None:
        return None
    loop = asyncio.get_running_loop()
    last = None
    for family, sockaddr in await net.getaddrinfo(host, port):
        sock = net.socket_factory((family, socket.SOCK_STREAM, 0, '', sockaddr))
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, sockaddr), timeout)
            return sock
        except (OSError, asyncio.TimeoutError) as e:
            sock.close()
            last = e
    raise last or OSError('cannot connect to {0}'.format(host))


def aiohttp_connector():
    """For code that builds its own aiohttp.ClientSession: a connector using
    the current tenant's network, or None for the default tenant (aiohttp's
    default connector)."""
    net = current_network()
    if net is None:
        return None
    try:
        return aiohttp.TCPConnector(socket_factory=net.socket_factory,
                                    resolver=net.resolver())
    except TypeError:
        raise TenantNetworkUnsupported(
            'reaching a tenant network over HTTPS needs aiohttp 3.12 or later')


class TenantNetworkUnsupported(TenantNetworkError):
    """This operation cannot yet be done within a tenant's network."""


def refuse_for_tenant(what):
    """Raise TenantNetworkUnsupported if the current task works for a
    tenant: for code that cannot reach a tenant's network yet."""
    net = current_network()
    if net is not None:
        raise TenantNetworkUnsupported(
            '{0} is not yet available within a tenant'.format(what))


def enter(tenantid):
    """Make the rest of the current task (and the tasks it starts) work for
    a tenant: held to its network by tenantguard, and reaching hardware
    through its broker (aiohmi). None is the default tenant."""
    tenantguard.enter(tenantid)
    netcontext.current_network.set(
        None if tenantid is None else TenantNetworkRef(tenantid))


_networks = {}
_networks_lock = threading.Lock()


def network_for(tenantid):
    """The network of a tenant; None (the default tenant) has none here,
    and callers keep using the host's network for it."""
    if tenantid is None:
        raise ValueError('the default tenant uses the host network')
    record = configmanager.get_tenant(tenantid)
    if record is None or record['state'] != 'active' or not configmanager.multitenancy_enabled():
        raise TenantNetworkUnavailable(
            'tenant {0} cannot use its network'.format(tenantid))
    with _networks_lock:
        net = _networks.get(tenantid)
        if net is None or net.broker.closed:
            try:
                uid = pwd.getpwnam(broker_user(tenantid)).pw_uid
            except KeyError:
                raise TenantNetworkUnavailable(
                    'tenant {0} has no broker account'.format(tenantid))
            net = TenantNetwork(Broker(tenantid, broker_socket(tenantid), uid,
                                       os.path.join(NETNS_DIR, netns_name(tenantid))))
            _networks[tenantid] = net
        return net


def register_network(tenantid, sockpath, broker_uid, netns_path):
    """Use an explicitly given broker for a tenant (tests, non-standard
    layouts)."""
    with _networks_lock:
        net = TenantNetwork(Broker(tenantid, sockpath, broker_uid, netns_path))
        _networks[tenantid] = net
        return net


def close_tenant(tenantid):
    with _networks_lock:
        net = _networks.pop(tenantid, None)
    if net is not None:
        net.broker.close()


def _tenant_state_changed(tenantid, state):
    if state != 'active':
        close_tenant(tenantid)


configmanager.watch_tenant_state(_tenant_state_changed)
