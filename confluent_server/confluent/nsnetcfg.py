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

"""Per-tenant network configuration helper (confluent-netcfg@<tenant>).

Runs inside one tenant's network namespace as an unprivileged user of its
own, holding only CAP_NET_ADMIN, and sets what the tenant's administrator
manages there: addresses, routes, link state and MTU of the interfaces
the platform put in the namespace, and the tenant's name servers.

It is separate from the network broker on purpose. The broker hands out
sockets and cannot change the network; this helper changes the network
and hands out nothing:

* No file descriptor is ever passed to a peer.
* The operation set is closed, with strict argument checks. It cannot
  create, rename or delete interfaces, nor move one between namespaces,
  so it only ever acts on what the platform attached to this namespace.
* It cannot enter another namespace (no CAP_SYS_ADMIN): nothing it does
  reaches the host's network or another tenant's.
* Only peers with an allowed uid (SO_PEERCRED) are served.

The wire format and the serving loop are the broker's (see nsbroker).
"""

import fcntl
import importlib.util
import ipaddress
import os
import socket
import struct
import sys
import threading


def _load_broker():
    # Next to this file when run on its own (the broker is a single file
    # too), otherwise from the package.
    sibling = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nsbroker.py')
    if __name__ == '__main__' and os.path.exists(sibling):
        spec = importlib.util.spec_from_file_location('nsbroker', sibling)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    import confluent.nsbroker
    return confluent.nsbroker


nsbroker = _load_broker()
RpcError = nsbroker.RpcError
_args = nsbroker._args
_int = nsbroker._int
_bool = nsbroker._bool
_ifname = nsbroker._ifname

NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP = 0x1, 0x4, 0x300
NLM_F_CREATE, NLM_F_EXCL = 0x400, 0x200
NLMSG_ERROR, NLMSG_DONE = 2, 3
RTM_NEWADDR, RTM_DELADDR = 20, 21
RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE = 24, 25, 26
RT_TABLE_MAIN, RTPROT_STATIC, RTN_UNICAST = 254, 4, 1
RT_SCOPE_UNIVERSE, RT_SCOPE_LINK = 0, 253
PROTOCOLS = {2: 'kernel', 3: 'boot', 4: 'static', 9: 'ra', 16: 'dhcp'}
SIOCGIFFLAGS, SIOCSIFFLAGS = 0x8913, 0x8914
SIOCGIFMTU, SIOCSIFMTU = 0x8921, 0x8922
IFF_UP = 0x1
MAX_NAMESERVERS = 3
MAX_SEARCH = 6
RESOLV_HEADER = '# Written by confluent for this tenant; managed through its API.\n'


def _attr(kind, data):
    length = 4 + len(data)
    return struct.pack('HH', length, kind) + data + b'\0' * (-length % 4)


def _netlink(msgtype, flags, payload):
    """Send one rtnetlink request and return the messages of the answer;
    a refusal by the kernel is the RpcError it describes."""
    nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    try:
        nl.bind((0, 0))
        nl.settimeout(5)
        nl.send(struct.pack('IHHII', 16 + len(payload), msgtype,
                            flags | NLM_F_REQUEST, 1, 0) + payload)
        messages = []
        while True:
            data = nl.recv(65536)
            while len(data) >= 16:
                length, kind = struct.unpack('IH', data[:6])
                if length < 16:
                    return messages
                if kind == NLMSG_ERROR:
                    code = -struct.unpack('i', data[16:20])[0]
                    if code:
                        raise RpcError(_errname(code), os.strerror(code))
                    return messages
                if kind == NLMSG_DONE:
                    return messages
                messages.append((kind, data[16:length]))
                data = data[(length + 3) & ~3:]
    except socket.timeout:
        raise RpcError('ETIMEDOUT', 'no answer from the kernel')
    except OSError as e:
        raise RpcError(_errname(e.errno), str(e))
    finally:
        nl.close()


def _errname(code):
    import errno
    return errno.errorcode.get(code, 'EIO')


def _interface_address(value):
    """A host address with its prefix, as an ipaddress interface."""
    if not isinstance(value, str) or '/' not in value:
        raise RpcError('EINVAL', 'address must be given as address/prefix')
    try:
        addr = ipaddress.ip_interface(value)
    except ValueError:
        raise RpcError('EINVAL', 'invalid address')
    ip = addr.ip
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise RpcError('EINVAL', 'not an address a host can have')
    if addr.network.prefixlen == 0:
        raise RpcError('EINVAL', 'invalid prefix length')
    return addr


def _address_message(ifname, addr):
    index = socket.if_nametoindex(ifname)
    family = socket.AF_INET if addr.version == 4 else socket.AF_INET6
    scope = RT_SCOPE_LINK if addr.ip.is_link_local else RT_SCOPE_UNIVERSE
    payload = struct.pack('BBBBI', family, addr.network.prefixlen, 0, scope, index)
    payload += _attr(2, addr.ip.packed) + _attr(1, addr.ip.packed)  # LOCAL, ADDRESS
    if addr.version == 4 and addr.network.prefixlen < 31:
        payload += _attr(4, addr.network.broadcast_address.packed)  # BROADCAST
    return payload


def op_addr_add(ctx, args):
    _args(args, ('ifname', 'address'))
    addr = _interface_address(args['address'])
    _netlink(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
             _address_message(_ifname(args['ifname']), addr))
    return {}, None


def op_addr_del(ctx, args):
    _args(args, ('ifname', 'address'))
    addr = _interface_address(args['address'])
    _netlink(RTM_DELADDR, NLM_F_ACK, _address_message(_ifname(args['ifname']), addr))
    return {}, None


def _route_message(args):
    _args(args, ('destination',), ('gateway', 'ifname', 'metric'))
    destination = args['destination']
    gateway = args.get('gateway')
    ifname = args.get('ifname')
    if gateway is None and ifname is None:
        raise RpcError('EINVAL', 'a route needs a gateway or an interface')
    if gateway is not None:
        try:
            gateway = ipaddress.ip_address(gateway)
        except (TypeError, ValueError):
            raise RpcError('EINVAL', 'invalid gateway')
    if destination == 'default':
        if gateway is None:
            raise RpcError('EINVAL', 'a default route needs a gateway')
        network = ipaddress.ip_network('0.0.0.0/0' if gateway.version == 4 else '::/0')
    else:
        try:
            if not isinstance(destination, str):
                raise ValueError(destination)
            network = ipaddress.ip_network(destination)
        except ValueError:
            raise RpcError('EINVAL', 'destination must be a network (address/prefix) or default')
    if gateway is not None and gateway.version != network.version:
        raise RpcError('EINVAL', 'gateway and destination differ in address family')
    family = socket.AF_INET if network.version == 4 else socket.AF_INET6
    scope = RT_SCOPE_UNIVERSE if gateway is not None else RT_SCOPE_LINK
    payload = struct.pack('BBBBBBBBI', family, network.prefixlen, 0, 0,
                          RT_TABLE_MAIN, RTPROT_STATIC, scope, RTN_UNICAST, 0)
    if network.prefixlen:
        payload += _attr(1, network.network_address.packed)  # DST
    if gateway is not None:
        payload += _attr(5, gateway.packed)  # GATEWAY
    if ifname is not None:
        payload += _attr(4, struct.pack('I', socket.if_nametoindex(_ifname(ifname))))  # OIF
    if args.get('metric') is not None:
        payload += _attr(6, struct.pack('I', _int(args['metric'], 'metric', 0, 0xffffffff)))
    return payload


def op_route_add(ctx, args):
    _netlink(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, _route_message(args))
    return {}, None


def op_route_del(ctx, args):
    _netlink(RTM_DELROUTE, NLM_F_ACK, _route_message(args))
    return {}, None


def _routes(family):
    version = 4 if family == socket.AF_INET else 6
    found = []
    for kind, body in _netlink(RTM_GETROUTE, NLM_F_DUMP, struct.pack('BBBBBBBBI', family,
                                                                    0, 0, 0, 0, 0, 0, 0, 0)):
        if kind != RTM_NEWROUTE or len(body) < 12:
            continue
        _, dstlen, _, _, table, protocol, _, rtype, _ = struct.unpack('BBBBBBBBI', body[:12])
        if table != RT_TABLE_MAIN or rtype != RTN_UNICAST:
            continue
        route = {'destination': None, 'gateway': None, 'ifname': None, 'metric': 0,
                 'protocol': PROTOCOLS.get(protocol, str(protocol))}
        destination = b'\0' * (4 if version == 4 else 16)
        attrs = body[12:]
        while len(attrs) >= 4:
            length, attr = struct.unpack('HH', attrs[:4])
            if length < 4:
                break
            value = attrs[4:length]
            if attr == 1:
                destination = value
            elif attr == 5:
                route['gateway'] = str(ipaddress.ip_address(value))
            elif attr == 4:
                try:
                    route['ifname'] = socket.if_indextoname(struct.unpack('I', value)[0])
                except OSError:
                    pass
            elif attr == 6:
                route['metric'] = struct.unpack('I', value)[0]
            attrs = attrs[(length + 3) & ~3:]
        network = ipaddress.ip_network((destination, dstlen))
        route['destination'] = 'default' if dstlen == 0 else str(network)
        found.append(route)
    return found


def op_route_list(ctx, args):
    _args(args)
    return {'routes': _routes(socket.AF_INET) + _routes(socket.AF_INET6)}, None


def _ifreq_int(probe, request, ifname, value=None):
    name = ifname.encode()[:15]
    if value is None:
        raw = fcntl.ioctl(probe.fileno(), request, struct.pack('16si12x', name, 0))
        return struct.unpack('16si12x', raw)[1]
    fcntl.ioctl(probe.fileno(), request, struct.pack('16si12x', name, value))
    return value


def _ifreq_flags(probe, ifname, flags=None):
    name = ifname.encode()[:15]
    if flags is None:
        raw = fcntl.ioctl(probe.fileno(), SIOCGIFFLAGS, struct.pack('16sH14x', name, 0))
        return struct.unpack('16sH14x', raw)[1]
    fcntl.ioctl(probe.fileno(), SIOCSIFFLAGS, struct.pack('16sH14x', name, flags))
    return flags


def op_link_list(ctx, args):
    """The interfaces of this namespace, with their MTU."""
    result, _ = nsbroker.op_list_interfaces(ctx, args)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for iface in result['interfaces']:
            try:
                iface['mtu'] = _ifreq_int(probe, SIOCGIFMTU, iface['name'])
            except OSError:
                iface['mtu'] = None
    finally:
        probe.close()
    return result, None


def op_link_set(ctx, args):
    """Bring an interface of this namespace up or down, or set its MTU."""
    _args(args, ('ifname',), ('up', 'mtu'))
    ifname = _ifname(args['ifname'])
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if args.get('mtu') is not None:
            _ifreq_int(probe, SIOCSIFMTU, ifname, _int(args['mtu'], 'mtu', 68, 65535))
        if args.get('up') is not None:
            flags = _ifreq_flags(probe, ifname)
            if _bool(args['up'], 'up'):
                flags |= IFF_UP
            else:
                flags &= ~IFF_UP
            _ifreq_flags(probe, ifname, flags)
    except OSError as e:
        raise RpcError(_errname(e.errno), str(e))
    finally:
        probe.close()
    return {}, None


def op_dns_set(ctx, args):
    """Set the tenant's name servers and search domains (its resolv.conf,
    which its broker resolves names with)."""
    _args(args, ('nameservers',), ('search',))
    if not ctx.get('resolv'):
        raise RpcError('EOPNOTSUPP', 'name resolution is not managed here')
    nameservers = args['nameservers']
    search = args.get('search') or []
    if not isinstance(nameservers, list) or len(nameservers) > MAX_NAMESERVERS:
        raise RpcError('EINVAL', 'nameservers must be a list of at most %d' % MAX_NAMESERVERS)
    if not isinstance(search, list) or len(search) > MAX_SEARCH:
        raise RpcError('EINVAL', 'search must be a list of at most %d' % MAX_SEARCH)
    lines = [RESOLV_HEADER]
    for server in nameservers:
        try:
            if not isinstance(server, str):
                raise ValueError(server)
            lines.append('nameserver %s\n' % ipaddress.ip_address(server))
        except ValueError:
            raise RpcError('EINVAL', 'name servers must be IP addresses')
    for domain in search:
        if not isinstance(domain, str) or not nsbroker.HOSTNAME_RE.match(domain):
            raise RpcError('EINVAL', 'invalid search domain')
    if search:
        lines.append('search %s\n' % ' '.join(search))
    try:
        # In place: the broker has this very file mounted as its
        # resolv.conf, and the helper cannot create files next to it.
        fd = os.open(ctx['resolv'], os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        with os.fdopen(fd, 'w') as out:
            out.write(''.join(lines))
    except OSError as e:
        raise RpcError(_errname(e.errno), str(e))
    return {}, None


def op_state(ctx, args):
    """A counter that changes whenever a link or address of this namespace
    does, and this helper's pid: for noticing that the configuration needs
    to be applied again (a new namespace, an interface that came back)."""
    _args(args)
    return {'generation': ctx['generation'][0], 'pid': os.getpid()}, None


def _watch_links(ctx):
    try:
        nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        nl.bind((0, 0x1 | 0x10 | 0x100))  # link, IPv4 and IPv6 address changes
    except OSError:
        return
    while True:
        try:
            nl.recv(65536)
        except OSError:
            continue
        ctx['generation'][0] += 1


OPS = {
    'hello': nsbroker.op_hello,
    'state': op_state,
    'link_list': op_link_list,
    'link_set': op_link_set,
    'addr_add': op_addr_add,
    'addr_del': op_addr_del,
    'route_list': op_route_list,
    'route_add': op_route_add,
    'route_del': op_route_del,
    'dns_set': op_dns_set,
}


def _arguments(parser):
    parser.add_argument('--resolv', help='the resolv.conf of this tenant (existing, writable)')


def _prepare(ctx, args):
    ctx['resolv'] = args.resolv
    ctx['generation'] = [0]
    threading.Thread(target=_watch_links, args=(ctx,), daemon=True).start()


def main(argv=None):
    return nsbroker.main(argv, ops=OPS, name='nsnetcfg',
                         description='confluent per-tenant network configuration helper',
                         arguments=_arguments, prepare=_prepare)


if __name__ == '__main__':
    sys.exit(main())
