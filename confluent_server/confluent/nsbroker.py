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

"""Per-tenant network broker (confluent-nsbroker@<tenant>.service).

The broker runs inside one tenant's network namespace as that tenant's own
unprivileged user, holding only CAP_NET_RAW and CAP_NET_BIND_SERVICE. It
creates sockets for the confluent service and hands them over with
SCM_RIGHTS, so the service can use the tenant's networks without ever
being able to enter a namespace itself.

It is deliberately not a general-purpose privileged service:

* The operation set is closed: no exec, no file access, no setsockopt
  proxy, no netlink writes (neighbor lookups read with the broker's own
  netlink socket, which is never handed out). Arguments are checked against strict schemas,
  and bind ports and ethertypes against fixed allowlists.
* Only peers with an allowed uid (SO_PEERCRED) are served.
* It keeps no tenant sockets: each one is closed as soon as it is sent.
* It cannot enter another namespace (no CAP_SYS_ADMIN), so every socket
  it creates belongs to its tenant's namespace.

Wire format (AF_UNIX SOCK_SEQPACKET, one message per datagram):
  request:  {"v":1, "id":<int>, "op":<str>, "args":{...}}       <= 4096 bytes
  response: {"v":1, "id":<int>, "ok":true,  "result":{...}}     [+ 1 fd]
            {"v":1, "id":<int>, "ok":false, "error":{"code":..,"msg":..}}
"""

import argparse
import array
import fcntl
import ipaddress
import json
import logging
import os
import pwd
import re
import signal
import socket
import struct
import sys
import threading
import time

PROTO_VERSION = 1
MAX_MSG = 4096
MAX_CLIENTS = 16
RATE_PER_SECOND = 200
RATE_BURST = 400
ALLOWED_BIND_PORTS = frozenset(
    [0, 67, 68, 80, 427, 443, 547, 1900, 4011, 5353, 13001] +
    list(range(3900, 4000)))
ALLOWED_ETHERTYPES = frozenset([0x0800, 0x0806, 0x86dd])
FAMILIES = {'inet': socket.AF_INET, 'inet6': socket.AF_INET6}
IP_PKTINFO = 8
SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891b
SIOCGIFHWADDR = 0x8927
HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$')
IFNAME_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')

log = logging.getLogger('nsbroker')


class RpcError(Exception):
    def __init__(self, code, msg):
        super(RpcError, self).__init__(msg)
        self.code = code
        self.msg = msg


class RateLimiter(object):
    """Token bucket shared by all clients of the broker."""

    def __init__(self, rate=RATE_PER_SECOND, burst=RATE_BURST):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.stamp = time.monotonic()
        self.lock = threading.Lock()

    def allow(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.stamp) * self.rate)
            self.stamp = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True


def _args(args, required=(), optional=()):
    if not isinstance(args, dict):
        raise RpcError('EINVAL', 'args must be an object')
    extra = set(args) - set(required) - set(optional)
    if extra:
        raise RpcError('EINVAL', 'unexpected arguments: %s' % sorted(extra))
    missing = set(required) - set(args)
    if missing:
        raise RpcError('EINVAL', 'missing arguments: %s' % sorted(missing))
    return args


def _family(value):
    if value not in FAMILIES:
        raise RpcError('EINVAL', 'family must be inet or inet6')
    return FAMILIES[value]


def _bool(value, name):
    if not isinstance(value, bool):
        raise RpcError('EINVAL', '%s must be boolean' % name)
    return value


def _int(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise RpcError('EINVAL', '%s must be an integer in [%d, %d]' % (name, low, high))
    return value


def _bind_port(value):
    value = _int(value, 'port', 0, 65535)
    if value not in ALLOWED_BIND_PORTS:
        raise RpcError('EACCES', 'bind port %d not permitted' % value)
    return value


def _ip_literal(value, family):
    if not isinstance(value, str):
        raise RpcError('EINVAL', 'address must be a string')
    try:
        addr = ipaddress.ip_address(value.split('%', 1)[0])
    except ValueError:
        raise RpcError('EINVAL', 'address must be an IP literal (use resolve)')
    if (addr.version == 4) != (family == socket.AF_INET):
        raise RpcError('EINVAL', 'address family mismatch')
    return value


def _ifname(value):
    if not isinstance(value, str) or not IFNAME_RE.match(value):
        raise RpcError('EINVAL', 'invalid interface name')
    try:
        socket.if_nametoindex(value)
    except OSError:
        raise RpcError('ENODEV', 'no such interface in this namespace')
    return value


def _ifreq(sock, request, ifname):
    return fcntl.ioctl(sock.fileno(), request,
                       struct.pack('256s', ifname.encode()[:15]))


# ---------------------------------------------------------- operations

def op_hello(ctx, args):
    _args(args)
    status = {}
    with open('/proc/self/status') as f:
        for line in f:
            if line.startswith(('CapEff', 'CapPrm', 'CapBnd', 'NoNewPrivs')):
                key, value = line.split(':', 1)
                status[key] = value.strip()
    return {'tenant': ctx['tenant'], 'version': PROTO_VERSION,
            'netns_ino': os.stat('/proc/self/ns/net').st_ino,
            'pid': os.getpid(), 'uid': os.getuid(), 'proc': status}, None


def op_connect_tcp(ctx, args):
    _args(args, ('family', 'host', 'port'), ('timeout',))
    family = _family(args['family'])
    host = _ip_literal(args['host'], family)
    port = _int(args['port'], 'port', 1, 65535)
    timeout = _int(args.get('timeout', 10), 'timeout', 1, 30)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)[0][4])
        sock.setblocking(False)
    except OSError as e:
        sock.close()
        raise RpcError('ECONNECT', str(e))
    return {}, sock


def op_tcp_socket(ctx, args):
    """An unconnected TCP socket of this namespace; the service connects it
    itself (within this namespace, as the socket belongs to it)."""
    _args(args, ('family',))
    sock = socket.socket(_family(args['family']), socket.SOCK_STREAM)
    sock.setblocking(False)
    return {}, sock


def op_udp_socket(ctx, args):
    _args(args, ('family',), ('port', 'broadcast', 'pktinfo', 'reuseaddr'))
    family = _family(args['family'])
    port = _bind_port(args.get('port', 0))
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if _bool(args.get('reuseaddr', False), 'reuseaddr'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if _bool(args.get('broadcast', False), 'broadcast'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if _bool(args.get('pktinfo', False), 'pktinfo'):
            if family == socket.AF_INET:
                sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
            else:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(('::', port))
        else:
            sock.bind(('0.0.0.0', port))
        sock.setblocking(False)
    except OSError as e:
        sock.close()
        raise RpcError('EBIND', str(e))
    return {'port': sock.getsockname()[1]}, sock


def op_listen_tcp(ctx, args):
    _args(args, ('family', 'port'), ('backlog',))
    family = _family(args['family'])
    port = _bind_port(args['port'])
    if port == 0:
        raise RpcError('EACCES', 'a listener needs an explicit allowed port')
    backlog = _int(args.get('backlog', 128), 'backlog', 1, 512)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(('::', port))
        else:
            sock.bind(('0.0.0.0', port))
        sock.listen(backlog)
        sock.setblocking(False)
    except OSError as e:
        sock.close()
        raise RpcError('EBIND', str(e))
    return {}, sock


def op_raw_icmp(ctx, args):
    _args(args, ('family',))
    family = _family(args['family'])
    proto = socket.IPPROTO_ICMP if family == socket.AF_INET else socket.IPPROTO_ICMPV6
    sock = socket.socket(family, socket.SOCK_RAW, proto)
    sock.setblocking(False)
    return {}, sock


def op_packet_socket(ctx, args):
    _args(args, ('ifname', 'ethertype'), ('kind',))
    ifname = _ifname(args['ifname'])
    ethertype = _int(args['ethertype'], 'ethertype', 0, 0xffff)
    if ethertype not in ALLOWED_ETHERTYPES:
        raise RpcError('EACCES', 'ethertype 0x%04x not permitted' % ethertype)
    kind = args.get('kind', 'raw')
    if kind not in ('raw', 'dgram'):
        raise RpcError('EINVAL', 'kind must be raw or dgram')
    stype = socket.SOCK_RAW if kind == 'raw' else socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_PACKET, stype, socket.htons(ethertype))
    try:
        sock.bind((ifname, ethertype))
        sock.setblocking(False)
    except OSError as e:
        sock.close()
        raise RpcError('EBIND', str(e))
    return {'ifindex': socket.if_nametoindex(ifname)}, sock


def _interface_ipv4(probe, name):
    try:
        addr = socket.inet_ntoa(_ifreq(probe, SIOCGIFADDR, name)[20:24])
        mask = socket.inet_ntoa(_ifreq(probe, SIOCGIFNETMASK, name)[20:24])
    except OSError:
        return []
    return ['%s/%d' % (addr, ipaddress.IPv4Network('0.0.0.0/' + mask).prefixlen)]


def op_list_interfaces(ctx, args):
    """Links of this namespace. /proc/self/net and the interface ioctls are
    namespace-aware; /sys is not used, as it may show the host."""
    _args(args)
    ipv6 = {}
    try:
        with open('/proc/self/net/if_inet6') as f:
            for line in f:
                hexaddr, _, plen, _, _, name = line.split()
                addr = str(ipaddress.IPv6Address(bytes.fromhex(hexaddr)))
                ipv6.setdefault(name, []).append('%s/%d' % (addr, int(plen, 16)))
    except OSError:
        pass
    found = []
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for index, name in socket.if_nameindex():
            flags = struct.unpack('H', _ifreq(probe, SIOCGIFFLAGS, name)[16:18])[0]
            try:
                hwaddr = _ifreq(probe, SIOCGIFHWADDR, name)[18:24]
                mac = ':'.join('%02x' % b for b in bytearray(hwaddr))
            except OSError:
                mac = None
            found.append({'name': name, 'index': index, 'up': bool(flags & 1),
                          'mac': mac, 'ipv4': _interface_ipv4(probe, name),
                          'ipv6': ipv6.get(name, [])})
    finally:
        probe.close()
    return {'interfaces': found}, None


def _neighbor_dump():
    """(address bytes, mac bytes) of this namespace's neighbor table, read
    with an RTM_GETNEIGH dump. The netlink socket is the broker's own and
    is never handed out."""
    nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    try:
        nl.bind((0, 0))
        nl.settimeout(2)
        # nlmsghdr (len, RTM_GETNEIGH, NLM_F_REQUEST|NLM_F_DUMP, seq, pid)
        # and an all-zero ndmsg
        nl.send(struct.pack('IHHII', 28, 30, 0x301, 1, 0) + b'\x00' * 12)
        while True:
            data = nl.recv(65536)
            while data:
                length, kind = struct.unpack('IH', data[:6])
                if length < 16 or kind in (2, 3):  # NLMSG_ERROR, NLMSG_DONE
                    return
                if kind == 28:  # RTM_NEWNEIGH
                    ndtype = struct.unpack('B', data[27:28])[0]
                    rta, addr, mac = data[28:length], None, None
                    while len(rta) >= 4:
                        rtalen, rtatype = struct.unpack('HH', rta[:4])
                        if rtalen < 4:
                            break
                        if rtatype == 1:
                            addr = rta[4:rtalen]
                        elif rtatype == 2:
                            mac = rta[4:rtalen]
                        rta = rta[(rtalen + 3) & ~3:]
                    if ndtype == 1 and addr and mac and len(mac) == 6:
                        yield addr, mac
                data = data[(length + 3) & ~3:]
    finally:
        nl.close()


def op_neighbor(ctx, args):
    """The hardware address this namespace has learned for one address."""
    _args(args, ('address',))
    address = args['address']
    try:
        if not isinstance(address, str):
            raise ValueError(address)
        packed = ipaddress.ip_address(address).packed
    except ValueError:
        raise RpcError('EINVAL', 'invalid address')
    try:
        for addr, mac in _neighbor_dump():
            if addr == packed:
                return {'mac': ':'.join('%02x' % b for b in bytearray(mac))}, None
    except OSError as e:
        raise RpcError('EIO', str(e))
    return {'mac': None}, None


def op_resolve(ctx, args):
    _args(args, ('name',), ('family',))
    name = args['name']
    if not isinstance(name, str) or not HOSTNAME_RE.match(name):
        raise RpcError('EINVAL', 'invalid hostname')
    family = _family(args.get('family', 'inet'))
    try:
        infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise RpcError('ENOENT', str(e))
    return {'addresses': sorted(set(i[4][0] for i in infos))}, None


OPS = {
    'hello': op_hello,
    'connect_tcp': op_connect_tcp,
    'tcp_socket': op_tcp_socket,
    'udp_socket': op_udp_socket,
    'listen_tcp': op_listen_tcp,
    'raw_icmp': op_raw_icmp,
    'packet_socket': op_packet_socket,
    'list_interfaces': op_list_interfaces,
    'neighbor': op_neighbor,
    'resolve': op_resolve,
}


# -------------------------------------------------------------- server

def peercred(conn):
    return struct.unpack('3i', conn.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))


def _reply(conn, msgid, result=None, sock=None, error=None):
    body = {'v': PROTO_VERSION, 'id': msgid}
    if error is not None:
        body.update(ok=False, error={'code': error.code, 'msg': error.msg})
    else:
        body.update(ok=True, result=result or {})
    data = json.dumps(body).encode()
    try:
        if sock is not None:
            conn.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                   array.array('i', [sock.fileno()]))])
        else:
            conn.send(data)
    finally:
        if sock is not None:
            sock.close()  # ownership has passed to the peer


def handle_request(ctx, data):
    """Parse and run one request; returns (msgid, result, sock, error)."""
    msgid = None
    try:
        if len(data) > MAX_MSG:
            raise RpcError('EMSGSIZE', 'request too large')
        try:
            req = json.loads(data.decode('utf8'))
        except (ValueError, UnicodeDecodeError):
            raise RpcError('EINVAL', 'malformed JSON')
        if not isinstance(req, dict) or set(req) - {'v', 'id', 'op', 'args'}:
            raise RpcError('EINVAL', 'malformed request')
        msgid = req.get('id')
        if req.get('v') != PROTO_VERSION:
            raise RpcError('EPROTO', 'unsupported protocol version')
        if not isinstance(msgid, int) or isinstance(msgid, bool):
            raise RpcError('EINVAL', 'id must be an integer')
        op = OPS.get(req.get('op'))
        if op is None:
            raise RpcError('EOPNOTSUPP', 'unknown operation')
        if not ctx['limiter'].allow():
            raise RpcError('EAGAIN', 'rate limit exceeded')
        result, sock = op(ctx, req.get('args', {}))
        return msgid, req['op'], result, sock, None
    except RpcError as e:
        return msgid, None, None, None, e


def serve_client(ctx, conn, peer):
    pid, uid, _ = peer
    try:
        while True:
            data = conn.recv(MAX_MSG + 1)
            if not data:
                return
            msgid, opname, result, sock, error = handle_request(ctx, data)
            if error is None:
                log.info('audit tenant=%s peer_pid=%d peer_uid=%d op=%s ok',
                         ctx['tenant'], pid, uid, opname)
            else:
                log.warning('audit tenant=%s peer_pid=%d peer_uid=%d denied code=%s msg=%s',
                            ctx['tenant'], pid, uid, error.code, error.msg)
            _reply(conn, msgid, result, sock, error)
            if error is not None and error.code == 'EMSGSIZE':
                return
    except OSError as e:
        log.warning('client error: %s', e)
    finally:
        conn.close()
        ctx['clients'].release()


def _resolve_uids(uids, users):
    allowed = set(uids or ())
    for user in users or ():
        allowed.add(pwd.getpwnam(user).pw_uid)
    return allowed


def main(argv=None):
    parser = argparse.ArgumentParser(description='confluent per-tenant network broker')
    parser.add_argument('--tenant', required=True)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--allow-uid', type=int, action='append', default=[])
    parser.add_argument('--allow-user', action='append', default=[])
    args = parser.parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format='nsbroker[%(process)d] %(message)s')
    if os.getuid() == 0:
        log.error('refusing to run as root')
        return 2
    allowed = _resolve_uids(args.allow_uid, args.allow_user)
    if not allowed:
        log.error('no allowed peers given')
        return 2
    ctx = {'tenant': args.tenant, 'limiter': RateLimiter(),
           'clients': threading.BoundedSemaphore(MAX_CLIENTS)}
    try:
        os.unlink(args.socket)
    except FileNotFoundError:
        pass
    os.umask(0o117)  # socket 0660; its directory is setgid to the service group
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(args.socket)
    server.listen(MAX_CLIENTS)

    def terminate(*_):
        try:
            os.unlink(args.socket)
        except OSError:
            pass
        os._exit(0)
    signal.signal(signal.SIGTERM, terminate)
    log.info('tenant=%s listening on %s netns_ino=%d uid=%d', args.tenant, args.socket,
             os.stat('/proc/self/ns/net').st_ino, os.getuid())
    while True:
        conn, _ = server.accept()
        peer = peercred(conn)
        if peer[1] not in allowed:
            log.warning('audit tenant=%s rejected peer pid=%d uid=%d',
                        args.tenant, peer[0], peer[1])
            conn.close()
            continue
        if not ctx['clients'].acquire(False):
            conn.close()
            continue
        threading.Thread(target=serve_client, args=(ctx, conn, peer),
                         daemon=True).start()


if __name__ == '__main__':
    sys.exit(main())
