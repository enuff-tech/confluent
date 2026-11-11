# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017,2022 Lenovo
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
# this will implement noderange grammar


import asyncio
import contextvars
import ipaddress
import confluent.exceptions as exc
import codecs
try:
    import psutil
except ImportError:
    psutil = None
    import netifaces
import struct
import os
import socket
import confluent.tasks as tasks
import time
import confluent.neighutil as neighutil



def mask_to_cidr(mask):
    cidr = 32
    fam = socket.AF_INET
    if ':' in mask:  # ipv6
        fam = socket.AF_INET6
        cidr = 128
    maskn = socket.inet_pton(fam, mask)
    if len(maskn) == 4:
        maskn = struct.unpack('!I', maskn)[0]
    else:
        first, second = struct.unpack('!QQ', maskn)
        maskn = first << 64 | second
    while maskn & 0b1 == 0 and cidr > 0:
        cidr -= 1
        maskn >>= 1
    return cidr

def cidr_to_mask(cidr):
    return socket.inet_ntop(
        socket.AF_INET, struct.pack('!I', (2**32 - 1) ^ (2**(32 - cidr) - 1)))

niclist = []
niclistexpiry = 0


def _tenantnet():
    # imported on first use, as configmanager imports this module
    import confluent.tenantnet as tenantnet
    return tenantnet


# Within a tenant, addresses, interfaces and names are those of the
# tenant's network namespace, learned through its broker; the host's
# (/sys, netlink, psutil, the host resolver) are never consulted.

async def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """loop.getaddrinfo, answered within the current tenant's network."""
    net = _tenantnet().current_network()
    if net is None:
        return await asyncio.get_running_loop().getaddrinfo(
            host, port, family=family, type=type, proto=proto, flags=flags)
    if isinstance(host, bytes):
        host = host.decode()
    found = []
    for fam, sockaddr in await net.getaddrinfo(host, port or 0):
        if family and fam != family:
            continue
        found.append((fam, type or socket.SOCK_STREAM, proto, '', sockaddr))
    if not found:
        raise socket.gaierror(socket.EAI_NONAME, 'cannot resolve {0}'.format(host))
    return found


def _is_global(fam, addr):
    # what netlink reports as scope global: not loopback, not link-local
    if fam == socket.AF_INET:
        return addr[0] != 127
    return addr != socket.inet_pton(socket.AF_INET6, '::1') and \
        not (addr[0] == 0xfe and addr[1] & 0xc0 == 0x80)


# Sockets opened for a tenant's discovery listeners, so that stopping them
# closes every socket they opened (see listener_scope).
_listener_sockets = contextvars.ContextVar('listener_sockets', default=None)


def listener_scope():
    """Collect the tenant sockets the current task (and the tasks it
    starts) open from here on; returns the list they are added to."""
    opened = []
    _listener_sockets.set(opened)
    return opened


def tenant_udp_socket(family, port=0, broadcast=False, pktinfo=False,
                      reuseaddr=True):
    """A UDP socket of the current tenant's network, from its broker
    (bound to port, 0 for any)."""
    net = _tenantnet().current_network()
    sock = net.udp_socket(family, port=port, broadcast=broadcast,
                          pktinfo=pktinfo, reuseaddr=reuseaddr)
    opened = _listener_sockets.get()
    if opened is not None:
        opened[:] = [s for s in opened if s.fileno() != -1]
        opened.append(sock)
    return sock


def tenant_packet_socket(ifname, ethertype, kind='raw'):
    net = _tenantnet().current_network()
    sock, ifindex = net.packet_socket(ifname, ethertype, kind)
    opened = _listener_sockets.get()
    if opened is not None:
        opened.append(sock)
    return sock


def stream_socket(family):
    """An unconnected TCP socket of the current task's network."""
    net = _tenantnet().current_network()
    if net is None:
        return socket.socket(family, socket.SOCK_STREAM)
    return net.socket_factory((family, socket.SOCK_STREAM, 0, '', None))


def interface_indexes():
    """util.list_interface_indexes for the current task's network."""
    net = _tenantnet().current_network()
    if net is None:
        return list(util_list_interface_indexes())
    return [iface['index'] for iface in net.list_interfaces()]


def ipv4_interfaces():
    """util.list_ips (address and broadcast of each IPv4 interface
    address) for the current task's network."""
    net = _tenantnet().current_network()
    if net is None:
        return list(util_list_ips())
    found = []
    for iface in net.list_interfaces():
        for addr in iface.get('ipv4', []):
            ifaddr = ipaddress.IPv4Interface(addr)
            if ifaddr.ip.is_loopback:
                continue
            found.append({'addr': str(ifaddr.ip),
                          'broadcast': str(ifaddr.network.broadcast_address)})
    return found


def interface_name(ifidx):
    """The name of an interface of the current task's network."""
    net = _tenantnet().current_network()
    if net is None:
        return socket.if_indextoname(ifidx)
    for iface in net.list_interfaces():
        if iface['index'] == ifidx:
            return iface['name']
    raise OSError('no interface with index {0}'.format(ifidx))


def util_list_interface_indexes():
    import confluent.util as util
    return util.list_interface_indexes()


def util_list_ips():
    import confluent.util as util
    return util.list_ips()


async def _tenant_addresses(net, idx=0, family=0, matchlla=None):
    interfaces = await net.alist_interfaces()
    if matchlla:
        for iface in interfaces:
            for addr in iface.get('ipv6', []):
                addr = addr.split('/')[0]
                if socket.inet_pton(socket.AF_INET6, addr) == matchlla:
                    return await _tenant_addresses(net, idx=iface['index'])
        return []
    addrs = []
    for iface in interfaces:
        if idx and iface['index'] != idx:
            continue
        for fam, key in ((socket.AF_INET, 'ipv4'), (socket.AF_INET6, 'ipv6')):
            if family and fam != family:
                continue
            for addr in iface.get(key, []):
                addr, plen = addr.split('/')
                addr = socket.inet_pton(fam, addr)
                if _is_global(fam, addr):
                    addrs.append((fam, addr, int(plen), iface['index']))
    return addrs


def list_viable_nics():
    _tenantnet().refuse_for_tenant('Listing network interfaces')
    global niclist
    global niclistexpiry
    if niclist and niclistexpiry > time.time():
        return niclist
    niclist = []
    niclistexpiry = time.time() + 10  # cache for 10 seconds
    # Nics that are not loopback, are up, with carrier are considered viable
    for iname in os.listdir('/sys/class/net'):
        if os.path.isdir(f'/sys/class/net/{iname}'):
            with open(f'/sys/class/net/{iname}/flags') as f:
                flags = int(f.read().strip(), 16)
                # IFF_LOOPBACK is 0x8, skip loopback interfaces
                if (flags & 0x8):  # loopback
                    continue
                if not flags & 0x1:  # IFF_UP is 0x1, skip interfaces that are down
                    continue
                with open(f'/sys/class/net/{iname}/carrier') as f:
                    carrier = f.read().strip()
                    if carrier != '1':
                        continue
                niclist.append(iname)
    return niclist


async def peer_reachable(address):
    checkports = 22, 443
    if _tenantnet().current_network() is not None:
        reachable_ports = []
        for port in checkports:
            try:
                sock = await _tenantnet().aconnect(address, port, timeout=0.5)
            except Exception:
                continue
            sock.close()
            reachable_ports.append(port)
        return reachable_ports
    testtasks = []
    for port in checkports:
        async def check_port(port):
            conn = None
            try:
                conn = await asyncio.wait_for(
                    asyncio.open_connection(address, port), timeout=0.5)
                return port
            except Exception:
                return False
            finally:
                if conn:
                    conn[1].close()
                    await conn[1].wait_closed()
        testtasks.append(check_port(port))
    results = await asyncio.gather(*testtasks, return_exceptions=True)
    reachable_ports = []
    for res in results:
        if not isinstance(res, Exception) and res:
            reachable_ports.append(res)
    return reachable_ports


async def add_zone(lla):
    # take an lla input without a zone and try to detect the right zone for it
    if '%' in lla:
        return lla
    tocheck = list(list_viable_nics())
    checktasks = []
    for link in tocheck:
        zone_addr = lla + '%' + link
        checktasks.append(peer_reachable(zone_addr))
    results = await asyncio.gather(*checktasks, return_exceptions=True)
    for link, reachable in zip(tocheck, results):
        if reachable and not isinstance(reachable, Exception):
            return lla + '%' + link
    return lla


def mac2lla(mac):
    """Convert MAC address to IPv6 link-local address."""
    # Remove colons from MAC address
    mac_clean = mac.replace(':', '').lower()
    # Insert fe80:: prefix and convert to lowercase
    # Split MAC into first 3 octets and last 3 octets
    first_half = mac_clean[:6]
    second_half = mac_clean[6:]
    # Flip the universal/local bit in the first octet
    first_octet = int(first_half[:2], 16)
    first_octet ^= 0x02
    first_half = f'{first_octet:02x}' + first_half[2:]
    # Format as IPv6 link-local address
    lla = f'fe80::{first_half[0:4]}:{first_half[4:]}ff:fe{second_half[0:2]}:{second_half[2:6]}'
    return lla

async def my_ip_facing(target):
    addrinfo = await _getaddrinfo(target, 0, type=socket.SOCK_DGRAM)
    family, socktype, proto, _, destination = addrinfo[0]
    myip = None
    net = _tenantnet().current_network()
    if net is not None:
        sock = net.udp_socket(family)
    else:
        sock = socket.socket(family, socktype, proto)
    with sock:
        # UDP connect selects the route and local address without
        # transmitting a packet.
        sock.connect(destination)
        myip = sock.getsockname()[0]
    return myip

async def mac2ip(mac):
    _tenantnet().refuse_for_tenant('Looking up neighbors')
    lla = None
    ipaddr = None
    try:
        addrs = await neighutil.get_ipaddr(mac)
        for addr in addrs:
            ip = addr.get('ip', None)
            ifidx = addr.get('ifidx', None)
            if ip:
                ipaddr = socket.inet_ntop(socket.AF_INET6 if len(ip) == 16 else socket.AF_INET, ip)
                if ipaddr.startswith('fe80::'):
                    lla = ipaddr
                    if ifidx:
                        lla += '%' + socket.if_indextoname(ifidx)
                        return lla  # prefer LLA if possible
    except Exception:
        pass
    if ipaddr:
        # we don't have LLA, but we do have some IP address that should work, return that
        return ipaddr
    # not in our neighbor table, try to convert from mac, which is not a guarantee
    if not lla:
        lla = mac2lla(mac)
    if '%' not in lla:
        lla = await add_zone(lla)
    return lla


async def ping_everywhere():
    pingtasks = []
    pingresponders = {}
    for interface in list_viable_nics():
        async def ping_task(iface):
            addrs = await ping6('ff02::1', interface=iface, multi=True)
            pingresponders[iface] = addrs
        pingtasks.append(ping_task(interface))
    await asyncio.gather(*pingtasks)
    return pingresponders

async def ping6(target, interface=None, multi=False):
    _tenantnet().refuse_for_tenant('IPv6 ping')
    # Do an IPv6 ping.  Notably interesting target is ff02::1, to induce all local
    # peers to transmit a reply
    respondingpeers = set([])
    respondingaddrs = set([])
    loop = asyncio.get_running_loop()
    addrinf = (await loop.getaddrinfo(
        target, None, family=socket.AF_INET6,
        type=socket.SOCK_DGRAM))[0]
    sockaddr = addrinf[-1]
    if interface:
        scopeid = socket.if_nametoindex(interface)
        sockaddr = (sockaddr[0], sockaddr[1], sockaddr[2], scopeid)
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM,
                      socket.IPPROTO_ICMPV6)
    try:
        s.setblocking(False)
        ident = os.getpid() & 0xffff
        payload = b'confluent'
        header = struct.pack('!BBHHH', 128, 0, 0, ident, 1)
        packet = header + payload
        try:
            await loop.sock_sendto(s, packet, sockaddr)
        except AttributeError:
            await loop.run_in_executor(
                None, lambda: s.sendto(packet, sockaddr))
        deadline = loop.time() + 1
        while loop.time() < deadline:
            try:
                currtimeout = deadline - loop.time()
                try:
                    data, peer = await asyncio.wait_for(
                        loop.sock_recvfrom(s, 1024), timeout=currtimeout)
                except AttributeError:
                    # Ugly workaround for python less than 3.11, blocking wrapped in thread
                    def blocking_recvfrom(currtimeo):
                        s.setblocking(True)
                        s.settimeout(currtimeo)
                        try:
                            return s.recvfrom(1024)
                        finally:
                            s.setblocking(False)
                    try:
                        data, peer = await loop.run_in_executor(
                            None, blocking_recvfrom, currtimeout)
                    except socket.timeout:
                        raise asyncio.TimeoutError()
            except asyncio.TimeoutError:
                break
            ifname = None
            respondingpeers.add(peer)
            if len(peer) > 3 and peer[3]:
                try:
                    ifname = socket.if_indextoname(peer[3])
                except OSError:
                    ifname = f'{peer[3]}'
            if ifname:
                respondingaddrs.add(f'{peer[0]}%{ifname}')
            else:
                respondingaddrs.add(f'{peer[0]}')
            if not multi:
                return respondingaddrs
        # likely in multi scenario, meaning our neighbor table could use some fill-out

        for peer in respondingpeers:
            try:
                tmpsock = socket.socket(s.family, socket.SOCK_DGRAM)
                tmpsock.setblocking(False)
                try:
                    if len(peer) == 4:
                        peer = (peer[0], 9, peer[2], peer[3])
                    else:
                        peer = (peer[0], 9)
                    await loop.sock_connect(tmpsock, peer)
                    await loop.sock_sendall(tmpsock, b'')
                except (OSError, socket.gaierror):
                    pass
            finally:
                tmpsock.close()
        return respondingaddrs
    except OSError:
        return respondingaddrs
    finally:
        s.close()


def ipn_on_same_subnet(fam, first, second, prefix):
    return neighutil.ipn_on_same_subnet(fam, first, second, prefix)

async def ip_on_same_subnet(first, second, prefix):
    if first.startswith('::ffff:') and '.' in first:
        first = first.replace('::ffff:', '')
    if second.startswith('::ffff:') and '.' in second:
        second = second.replace('::ffff:', '')
    addrinf = (await _getaddrinfo(first, 0, type=socket.SOCK_STREAM))[0]
    fam = addrinf[0]
    if '%' in addrinf[-1][0]:
        return False
    ip = socket.inet_pton(fam, addrinf[-1][0])
    ip = int(codecs.encode(bytes(ip), 'hex'), 16)
    addrinf = (await _getaddrinfo(second, 0, type=socket.SOCK_STREAM))[0]
    if fam != addrinf[0]:
        return False
    txtaddr = addrinf[-1][0].split('%')[0]
    oip = socket.inet_pton(fam, txtaddr)
    oip = int(codecs.encode(bytes(oip), 'hex'), 16)
    if fam == socket.AF_INET:
        addrlen = 32
    elif fam == socket.AF_INET6:
        addrlen = 128
    else:
        raise Exception("Unknown address family {0}".format(fam))
    mask = 2 ** prefix - 1 << (addrlen - prefix)
    return ip & mask == oip & mask


async def ipn_is_local(ipn):
    net = _tenantnet().current_network()
    if net is not None:
        for fam, addr, plen, _ in await _tenant_addresses(net):
            if len(addr) == len(ipn) and ipn_on_same_subnet(fam, addr, ipn, plen):
                return True
        return False
    return await neighutil.ipn_is_local(ipn)

async def address_is_local(address):
    net = _tenantnet().current_network()
    if net is not None:
        for fam, addr, plen, _ in await _tenant_addresses(net):
            if await ip_on_same_subnet(socket.inet_ntop(fam, addr), address, plen):
                return True
        return False
    if psutil:
        ifas = psutil.net_if_addrs()
        for iface in ifas:
            for addr in ifas[iface]:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    cidr = mask_to_cidr(addr.netmask)
                    if await ip_on_same_subnet(addr.address, address, cidr):
                        return True
    else:
        for iface in netifaces.interfaces():
            for i4 in netifaces.ifaddresses(iface).get(2, []):
                cidr = mask_to_cidr(i4['netmask'])
                if await ip_on_same_subnet(i4['addr'], address, cidr):
                    return True
            for i6 in netifaces.ifaddresses(iface).get(10, []):
                cidr = int(i6['netmask'].split('/')[1])
                laddr = i6['addr'].split('%')[0]
                if await ip_on_same_subnet(laddr, address, cidr):
                    return True
    return False


_idxtoifnamemap = {}
def _rebuildidxmap():
    _idxtoifnamemap.clear()
    for iname in os.listdir('/sys/class/net'):
        try:
            ci = int(open('/sys/class/net/{0}/ifindex'.format(iname)).read())
            _idxtoifnamemap[ci] = iname
        except Exception:  # there may be non interface in /sys/class/net
            pass


async def myiptonets(svrip):
    _tenantnet().refuse_for_tenant('Listing network interfaces')
    fam = socket.AF_INET
    if ':' in svrip:
        fam = socket.AF_INET6
    relevantnic = None
    if psutil:
        ifas = psutil.net_if_addrs()
        for iface in ifas:
            for addr in ifas[iface]:
                if addr.fam != fam:
                    continue
                addr = addr.address
                addr = addr.split('%')[0]
                if await addresses_match(addr, svrip):
                    relevantnic = iface
                    break
            else:
                continue
            break
    else:
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(fam, []):
                addr = addr.get('addr', '')
                addr = addr.split('%')[0]
                if await addresses_match(addr, svrip):
                    relevantnic = iface
                    break
            else:
                continue
            break
    return inametonets(relevantnic)


def _iftonets(ifidx):
    if isinstance(ifidx, int):
        _rebuildidxmap()
        ifidx = _idxtoifnamemap.get(ifidx, None)
    return inametonets(ifidx)

def inametonets(iname):
    _tenantnet().refuse_for_tenant('Listing network interfaces')
    addrs = []
    if psutil:
        ifaces = psutil.net_if_addrs()
        if iname not in ifaces:
            return
        for iface in ifaces:
            for addrent in ifaces[iface]:
                if addrent.family != socket.AF_INET:
                    continue
                addrs.append({'addr': addrent.address, 'netmask': addrent.netmask})
    else:
        addrs = netifaces.ifaddresses(iname)
        try:
            addrs = addrs[netifaces.AF_INET]
        except KeyError:
            return
    for addr in addrs:
        ip = struct.unpack('!I', socket.inet_aton(addr['addr']))[0]
        mask = struct.unpack('!I', socket.inet_aton(addr['netmask']))[0]
        net = ip & mask
        net = socket.inet_ntoa(struct.pack('!I', net))
        yield (net, mask_to_cidr(addr['netmask']), addr['addr'])


class NetManager(object):
    def __init__(self, myaddrs, node, configmanager):
        self.myaddrs = myaddrs
        self._allmyaddrs = None
        self.cfm = configmanager
        self.node = node
        self.myattribs = {}
        self.consumednames4 = set([])
        self.consumednames6 = set([])
        self.consumedaddrs = set([])

    async def finalize(self):
        for netname in self.myattribs:
            myattribs = self.myattribs[netname]
            if 'ipv4_address_from_name' in myattribs:
                if myattribs['ipv4_address_from_name'] in self.consumedaddrs:
                    del myattribs['ipv4_address']
                    del myattribs['ipv4_method']
                del myattribs['ipv4_address_from_name']
            if 'ipv6_address_from_name' in myattribs:
                if myattribs['ipv6_address_from_name'] in self.consumedaddrs:
                    del myattribs['ipv6_address']
                    del myattribs['ipv6_method']
                del myattribs['ipv6_address_from_name']

    async def allmyaddrs(self):
        if not self._allmyaddrs:
            self._allmyaddrs = await get_my_addresses()
        return self._allmyaddrs

    async def process_attribs(self, netname, attribs):
        self.myattribs[netname] = {}
        ipv4addr = None
        ipv6addr = None
        myattribs = self.myattribs[netname]
        hwaddr = attribs.get('hwaddr', None)
        if hwaddr:
            myattribs['hwaddr'] = hwaddr
        lease_time = attribs.get('lease_time', None)
        if lease_time:
            myattribs['lease_time'] = lease_time
        conname = attribs.get('connection_name', None)
        if conname:
            myattribs['connection_name'] = conname
        iname = attribs.get('interface_names', None)
        if iname:
            myattribs['interface_names'] = iname
        vlanid = attribs.get('vlan_id', None)
        if vlanid:
            myattribs['vlan_id'] = vlanid
        mtuinfo = attribs.get('mtu', None)
        if mtuinfo:
            myattribs['mtu'] = int(mtuinfo)
        teammod = attribs.get('team_mode', None)
        if teammod:
            myattribs['team_mode'] = teammod
        extrastgs = attribs.get('extra_settings', None)
        if extrastgs:
            myattribs['extra_settings'] = extrastgs
        method = attribs.get('ipv4_method', None)
        if method != 'dhcp':
            ipv4addr = attribs.get('ipv4_address', None)
            if ipv4addr:
                try:
                    luaddr = ipv4addr.split('/', 1)[0]
                    for ai in await _getaddrinfo(luaddr, 0, family=socket.AF_INET, type=socket.SOCK_STREAM):
                        ipv4addr.replace(luaddr, ai[-1][0])
                except socket.gaierror:
                    pass
                if ipv4addr:
                    self.consumedaddrs.add(ipv4addr.split('/', 1)[0])
            else:
                currname = attribs.get('hostname', self.node).split()[0]
                if currname and currname not in self.consumednames4:
                    try:
                        for ai in await _getaddrinfo(currname, 0, family=socket.AF_INET, type=socket.SOCK_STREAM):
                            if ai[-1][0] not in self.consumedaddrs:
                                ipv4addr = ai[-1][0]
                                self.consumednames4.add(currname)
                        if ipv4addr:
                            myattribs['ipv4_address_from_name'] = ipv4addr
                    except socket.gaierror:
                        pass
            if ipv4addr:
                myattribs['ipv4_method'] = 'static'
                myattribs['ipv4_address'] = ipv4addr
        else:
            myattribs['ipv4_method'] = 'dhcp'
        if attribs.get('ipv4_gateway', None) and 'ipv4_method' in myattribs:
            myattribs['ipv4_gateway'] = attribs['ipv4_gateway']
        method = attribs.get('ipv6_method', None)
        if method != 'dhcp':
            ipv6addr = attribs.get('ipv6_address', None)
            if ipv6addr:
                try:
                    for ai in await _getaddrinfo(ipv6addr, 0, family=socket.AF_INET6, type=socket.SOCK_STREAM):
                        ipv6addr = ai[-1][0]
                except socket.gaierror:
                    pass
                if ipv6addr:
                    self.consumedaddrs.add(ipv6addr.split('/', 1)[0])
            else:
                currname = attribs.get('hostname', self.node).split()[0]
                if currname and currname not in self.consumednames6:
                    try:
                        for ai in await _getaddrinfo(currname, 0, family=socket.AF_INET6, type=socket.SOCK_STREAM):
                            if ai[-1][0] not in self.consumedaddrs:
                                ipv6addr = ai[-1][0]
                                self.consumednames6.add(currname)
                    except socket.gaierror:
                        pass
                    if ipv6addr:
                        myattribs['ipv6_address_from_name'] = ipv6addr
            if ipv6addr:
                myattribs['ipv6_method'] = 'static'
                myattribs['ipv6_address'] = ipv6addr
        else:
            myattribs['ipv6_method'] = 'dhcp'
        if attribs.get('ipv6_gateway', None) and 'ipv6_method' in myattribs:
            myattribs['ipv6_gateway'] = attribs['ipv6_gateway']
        if 'ipv4_method' not in myattribs and 'ipv6_method' not in myattribs:
            del self.myattribs[netname]
            return
        if ipv4addr:
            if '/' in ipv4addr:
                ipv4addr, _ = ipv4addr.split('/', 1)
            ipv4bytes = socket.inet_pton(socket.AF_INET, ipv4addr.split('/')[0])
            for addr in self.myaddrs:
                if addr[0] != socket.AF_INET:
                    continue
                if ipn_on_same_subnet(addr[0], addr[1], ipv4bytes, addr[2]):
                    myattribs['current_nic'] = True
                    myattribs['ipv4_address'] = '{0}/{1}'.format(ipv4addr, addr[2])
        if not myattribs.get('current_nic', False) and ipv6addr:
            if '/' in ipv6addr:
                ipv6addr, _ = ipv6addr.split('/', 1)
            ipv6bytes = socket.inet_pton(socket.AF_INET6, ipv6addr)
            for addr in self.myaddrs:
                if addr[0] != socket.AF_INET6:
                    continue
                if ipn_on_same_subnet(addr[0], addr[1], ipv6bytes, addr[2]):
                    myattribs['current_nic'] = True
                    myattribs['ipv6_address'] = '{0}/{1}'.format(ipv6addr, addr[2])
        if '/' not in myattribs.get('ipv6_address', '/'):
            ipn = socket.inet_pton(socket.AF_INET6, myattribs['ipv6_address'])
            plen = 64
            for addr in await self.allmyaddrs():
                if addr[0] != socket.AF_INET6:
                    continue
                if ipn_on_same_subnet(addr[0], ipn, addr[1], addr[2]):
                    plen = addr[2]
            myattribs['ipv6_address'] += '/{0}'.format(plen)
        if '/' not in myattribs.get('ipv4_address', '/'):
            ipn = socket.inet_pton(socket.AF_INET, myattribs['ipv4_address'])
            plen = 16
            for addr in await self.allmyaddrs():
                if addr[0] != socket.AF_INET:
                    continue
                if ipn_on_same_subnet(addr[0], ipn, addr[1], addr[2]):
                    plen = addr[2]
            myattribs['ipv4_address'] += '/{0}'.format(plen)
        if 'current_nic' not in myattribs:
            myattribs['current_nic'] = False


async def get_flat_net_config(configmanager, node):
    fnc = await get_full_net_config(configmanager, node)
    dft = fnc.get('default', {})
    if dft:
        ret = [dft]
    else:
        ret = []
    for nc in fnc.get('extranets', {}):
        nc = fnc['extranets'][nc]
        if nc:
            ret.append(nc)
    return ret

def add_netmask(ncfg):
    if '/' in ncfg.get('ipv4_address', ''):
        plen = ncfg['ipv4_address'].split('/', 1)[1]
        ncfg['ipv4_netmask'] = cidr_to_mask(int(plen))

async def get_full_net_config(configmanager, node, serverip=None):
    cfd = configmanager.get_node_attributes(node, ['net.*'])
    cfd = cfd.get(node, {})
    bmc = configmanager.get_node_attributes(
        node, 'hardwaremanagement.manager').get(node, {}).get(
            'hardwaremanagement.manager', {}).get('value', None)
    bmc4 = None
    bmc6 = None
    if bmc:
        try:
            bmc4 = (await _getaddrinfo(bmc, 0, family=socket.AF_INET, type=socket.SOCK_DGRAM))[0][-1][0]
        except Exception:
            pass
        try:
            bmc6 = (await _getaddrinfo(bmc, 0, family=socket.AF_INET6, type=socket.SOCK_DGRAM))[0][-1][0]
        except Exception:
            pass
    attribs = {}
    for attrib in cfd:
        val = cfd[attrib].get('value', None)
        if val is None:
            continue
        if attrib.startswith('net.'):
            attrib = attrib.replace('net.', '', 1).rsplit('.', 1)
            if len(attrib) == 1:
                iface = None
                attrib = attrib[0]
            else:
                iface, attrib = attrib
            if attrib in ('switch', 'switchport', 'bootable'):
                continue
            if iface not in attribs:
                attribs[iface] = {}
            attribs[iface][attrib] = val
    myaddrs = []
    if serverip:
        myaddrs = await get_addresses_by_serverip(serverip)
    nm = NetManager(myaddrs, node, configmanager)
    defaultnic = {}
    ppool = tasks.TaskPool()
    if None in attribs:
        ppool.schedule(nm.process_attribs, None, attribs[None])
        del attribs[None]
    for netname in sorted(attribs):
        ppool.schedule(nm.process_attribs, netname, attribs[netname])
    await ppool.waitall()
    await nm.finalize()
    for iface in list(nm.myattribs):
        if bmc4 and nm.myattribs[iface].get('ipv4_address', None) == bmc4:
            del nm.myattribs[iface]
            continue
        if bmc6 and nm.myattribs[iface].get('ipv6_address', None) == bmc6:
            del nm.myattribs[iface]
    retattrs = {}
    if None in nm.myattribs:
        retattrs['default'] = nm.myattribs[None]
        add_netmask(retattrs['default'])
        del nm.myattribs[None]
    else:
        nnc = await get_nic_config(configmanager, node, serverip=serverip)
        if nnc.get('ipv4_address', None):
            defaultnic['ipv4_address'] = '{}/{}'.format(nnc['ipv4_address'], nnc['prefix'])
        if nnc.get('ipv4_gateway', None):
            defaultnic['ipv4_gateway'] = nnc['ipv4_gateway']
        if nnc.get('ipv4_method', None):
            defaultnic['ipv4_method'] = nnc['ipv4_method']
        if nnc.get('ipv6_address', None):
            defaultnic['ipv6_address'] = '{}/{}'.format(nnc['ipv6_address'], nnc['ipv6_prefix'])
        if nnc.get('ipv6_method', None):
            defaultnic['ipv6_method'] = nnc['ipv6_method']
    retattrs['extranets'] = nm.myattribs
    for attri in retattrs['extranets']:
        add_netmask(retattrs['extranets'][attri])
        if retattrs['extranets'][attri].get('ipv4_address', None) == defaultnic.get('ipv4_address', 'NOPE'):
            defaultnic = {}
        if retattrs['extranets'][attri].get('ipv6_address', None) == defaultnic.get('ipv6_address', 'NOPE'):
            defaultnic = {}
    if defaultnic:
        retattrs['default'] = defaultnic
        add_netmask(retattrs['default'])
        ipv4addr = defaultnic.get('ipv4_address', None)
        if ipv4addr and '/' in ipv4addr:
            ipv4bytes = socket.inet_pton(socket.AF_INET, ipv4addr.split('/')[0])
            for addr in nm.myaddrs:
                if addr[0] != socket.AF_INET:
                    continue
                if ipn_on_same_subnet(addr[0], addr[1], ipv4bytes, addr[2]):
                    defaultnic['current_nic'] = True
        ipv6addr = defaultnic.get('ipv6_address', None)
        if ipv6addr and '/' in ipv6addr:
            ipv6bytes = socket.inet_pton(socket.AF_INET6, ipv6addr.split('/')[0])
            for addr in nm.myaddrs:
                if addr[0] != socket.AF_INET6:
                    continue
                if ipn_on_same_subnet(addr[0], addr[1], ipv6bytes, addr[2]):
                    defaultnic['current_nic'] = True
    return retattrs


def noneify(cfgdata):
    for key in cfgdata:
        if cfgdata[key] == '':
            cfgdata[key] = None
    return cfgdata

# TODO(jjohnson2): have a method to arbitrate setting methods, to aid
# in correct matching of net.* based on parameters, mainly for pxe
# The scheme for pxe:
# For one: the candidate net.* should have pxe set to true, to help
# disambiguate from interfaces meant for bmc access
# bmc relies upon hardwaremanagement.manager, plus we don't collect
# that mac address
# the ip as reported by recvmsg to match the subnet of that net.* interface
# if switch and port available, that should match.
async def get_nic_config(configmanager, node, ip=None, mac=None, ifidx=None,
                   serverip=None, relayipn=b'\x00\x00\x00\x00',
                   clientip=None, onlyfamily=None):
    """Fetch network configuration parameters for a nic

    For a given node and interface, find and retrieve the pertinent network
    configuration data.  The desired configuration can be searched
    either by ip or by mac.

    :param configmanager: The relevant confluent.config.ConfigManager
        instance.
    :param node:  The name of the node
    :param ip:  An IP address on the intended subnet
    :param mac: The mac address of the interface
    :param ifidx: The local index relevant to the network.

    :returns: A dict of parameters, 'ipv4_gateway', ....
    """
    # ip parameter *could* be the result of recvmsg with cmsg to tell
    # pxe *our* ip address, or it could be the desired ip address
    #TODO(jjohnson2): ip address, prefix length, mac address,
    # join a bond/bridge, vlan configs, etc.
    # also other nic criteria, physical location, driver and index...
    if not onlyfamily:
        onlyfamily = 0
    clientfam = None
    clientipn = None
    serverfam = None
    serveripn = None
    llaipn = socket.inet_pton(socket.AF_INET6, 'fe80::')
    if serverip is not None:
        if '.' in serverip:
            serverfam = socket.AF_INET
        elif ':' in serverip:
            serverfam = socket.AF_INET6
        if serverfam:
            serveripn = socket.inet_pton(serverfam, serverip)
    if clientip is not None:
        if '%' in clientip:
            # link local, don't even bother'
            clientfam = None
        elif '.' in clientip:
            clientfam = socket.AF_INET
        elif ':' in clientip:
            clientfam = socket.AF_INET6
        if clientfam:
            clientipn = socket.inet_pton(clientfam, clientip)
    nodenetattribs = configmanager.get_node_attributes(
        node, 'net*').get(node, {})
    bmc = configmanager.get_node_attributes(
        node, 'hardwaremanagement.manager').get(node, {}).get('hardwaremanagement.manager', {}).get('value', None)
    bmc4 = None
    bmc6 = None
    if bmc:
        try:
            if onlyfamily in (0, socket.AF_INET):
                bmc4 = (await _getaddrinfo(bmc, 0, family=socket.AF_INET, type=socket.SOCK_DGRAM))[0][-1][0]
        except Exception:
            pass
        try:
            if onlyfamily in (0, socket.AF_INET6):
                bmc6 = (await _getaddrinfo(bmc, 0, family=socket.AF_INET6, type=socket.SOCK_DGRAM))[0][-1][0]
        except Exception:
            pass
    cfgbyname = {}
    for attrib in nodenetattribs:
        segs = attrib.split('.')
        if len(segs) == 2:
            name = None
        else:
            name = segs[1]
        if name not in cfgbyname:
            cfgbyname[name] = {}
        cfgbyname[name][segs[-1]] = nodenetattribs[attrib].get('value',
                                                                None)
    cfgdata = {
        'ipv4_gateway': None,
        'ipv4_address': None,
        'ipv4_method': None,
        'prefix': None,
        'ipv6_prefix': None,
        'ipv6_address': None,
        'ipv6_method': None,
        'lease_time': None,
        'config_name': None,
    }
    myaddrs = []
    if ifidx is not None:
        dhcprequested = False
        myaddrs = await get_my_addresses(ifidx, family=onlyfamily)
        v4broken = True
        v6broken = True
        for addr in myaddrs:
            if addr[0] == socket.AF_INET:
                v4broken = False
            elif addr[0] == socket.AF_INET6:
                v6broken = False
        if v4broken:
            cfgdata['ipv4_broken'] = True
        if v6broken:
            cfgdata['ipv6_broken'] = True
    isremote = False
    if serverip is not None:
        dhcprequested = False
        myaddrs = await get_addresses_by_serverip(serverip)
        if serverfam == socket.AF_INET6 and ipn_on_same_subnet(serverfam, serveripn, llaipn, 64):
            isremote = False
        elif clientfam:
            for myaddr in myaddrs:
                # we may have received over a local vlan, wrong aliased subnet
                # so have to check for *any* potential matches
                fam, svrip, prefix = myaddr[:3]
                if fam == clientfam:
                    if ipn_on_same_subnet(fam, clientipn, svrip, prefix):
                        break
            else:
                isremote = True
    genericmethod = 'static'
    ipbynodename = None
    ip6bynodename = None
    try:
        if onlyfamily in (socket.AF_INET, 0):
            for addr in await _getaddrinfo(node, 0, family=socket.AF_INET, type=socket.SOCK_DGRAM):
                ipbynodename = addr[-1][0]
    except socket.gaierror:
        pass
    try:
        if onlyfamily in (socket.AF_INET6, 0):
            for addr in await _getaddrinfo(node, 0, family=socket.AF_INET6, type=socket.SOCK_DGRAM):
                    ip6bynodename = addr[-1][0]
    except socket.gaierror:
        pass
    if myaddrs:
        foundaddr = False
        candgws = []
        candsrvs = []
        bestsrvbyfam = {}
        for myaddr in myaddrs:
            fam, svrip, prefix = myaddr[:3]
            if fam == socket.AF_INET and relayipn != b'\x00\x00\x00\x00':
                bootsvrip = relayipn
            else:
                bootsvrip = svrip
            candsrvs.append((fam, svrip, prefix))
            if fam == socket.AF_INET:
                nver = '4'
                srvkey = 'deploy_server'
            elif fam == socket.AF_INET6:
                nver = '6'
                srvkey = 'deploy_server_v6'
            if fam not in bestsrvbyfam:
                cfgdata[srvkey] = socket.inet_ntop(fam, svrip)
            for candidate in cfgbyname:
                ipmethod = cfgbyname[candidate].get('ipv{}_method'.format(nver), 'static')
                leasetime = cfgbyname[candidate].get('lease_time', None)
                if leasetime:
                    cfgdata['lease_time'] = leasetime
                if not ipmethod:
                    ipmethod = 'static'
                if ipmethod == 'dhcp':
                    dhcprequested = True
                    continue
                if ipmethod == 'firmwaredhcp':
                    genericmethod = ipmethod
                candip = cfgbyname[candidate].get('ipv{}_address'.format(nver), None)
                if candip and '/' in candip:
                    candip, candprefix = candip.split('/')
                    if fam == socket.AF_INET and relayipn != b'\x00\x00\x00\x00':
                        prefix = int(candprefix)
                    if (not isremote) and int(candprefix) != prefix:
                        continue
                candgw = cfgbyname[candidate].get('ipv{}_gateway'.format(nver), None)
                if candip:
                    if bmc4 and candip == bmc4:
                        continue
                    if bmc6 and candip == bmc6:
                        continue
                    try:
                        for inf in await _getaddrinfo(candip, 0, family=fam, type=socket.SOCK_STREAM):
                            candipn = socket.inet_pton(fam, inf[-1][0])
                        if ((isremote and ipn_on_same_subnet(fam, clientipn, candipn, int(candprefix)))
                                or ipn_on_same_subnet(fam, bootsvrip, candipn, prefix)):
                            bestsrvbyfam[fam] = svrip
                            cfgdata['config_name'] = candidate
                            cfgdata['ipv{}_address'.format(nver)] = candip
                            cfgdata['ipv{}_method'.format(nver)] = ipmethod
                            cfgdata['ipv{}_gateway'.format(nver)] = cfgbyname[candidate].get(
                                'ipv{}_gateway'.format(nver), None)
                            if nver == '4':
                                cfgdata['prefix'] = prefix
                            else:
                                cfgdata['ipv{}_prefix'.format(nver)] = prefix
                            if candip in (ipbynodename, ip6bynodename):
                                cfgdata['matchesnodename'] = True
                            foundaddr = True
                    except Exception as e:
                        cfgdata['error_msg'] = "Error trying to evaluate net.*ipv4_address attribute value '{0}' on {1}: {2}".format(candip, node, str(e))
                elif candgw:
                    for inf in await _getaddrinfo(candgw, 0, family=fam, type=socket.SOCK_STREAM):
                        candgwn = socket.inet_pton(fam, inf[-1][0])
                    if ipn_on_same_subnet(fam, bootsvrip, candgwn, prefix):
                        candgws.append((fam, candgwn, prefix))
        if foundaddr:
            return noneify(cfgdata)
        if dhcprequested:
            if not cfgdata.get('ipv4_method', None):
                cfgdata['ipv4_method'] = 'dhcp'
            if not cfgdata.get('ipv6_method', None):
                cfgdata['ipv6_method'] = 'dhcp'
            return noneify(cfgdata)
        if ipbynodename is None and ip6bynodename is None:
            return noneify(cfgdata)
        for myaddr in myaddrs:
            fam, svrip, prefix = myaddr[:3]
            if fam == socket.AF_INET:
                bynodename = ipbynodename
                nver = '4'
            else:
                bynodename = ip6bynodename
                nver = '6'
            if not bynodename:  # node is missing either ipv6 or ipv4, ignore
                continue
            ipbynodenamn = socket.inet_pton(fam, bynodename)
            if ipn_on_same_subnet(fam, svrip, ipbynodenamn, prefix):
                cfgdata['matchesnodename'] = True
                cfgdata['ipv{}_address'.format(nver)] = bynodename
                cfgdata['ipv{}_method'.format(nver)] = genericmethod
                if nver == '4':
                    cfgdata['prefix'] = prefix
                else:
                    cfgdata['ipv{}_prefix'.format(nver)] = prefix
        for svr in candsrvs:
            fam, svr, prefix = svr
            if fam == socket.AF_INET:
                bynodename = ipbynodename
            elif fam == socket.AF_INET6:
                bynodename = ip6bynodename
            if not bynodename:
                continue  # ignore undefined family
            bynodenamn = socket.inet_pton(fam, bynodename)
            if ipn_on_same_subnet(fam, svr, bynodenamn, prefix):
                svrname = socket.inet_ntop(fam, svr)
                if fam == socket.AF_INET:
                    cfgdata['deploy_server'] = svrname
                else:
                    cfgdata['deploy_server_v6'] = svrname
        for gw in candgws:
            fam, candgwn, prefix = gw
            if fam == socket.AF_INET:
                nver = '4'
                bynodename = ipbynodename
            elif fam == socket.AF_INET6:
                nver = '6'
                bynodename = ip6bynodename
            if bynodename:
                bynodenamn = socket.inet_pton(fam, bynodename)
                if ipn_on_same_subnet(fam, candgwn, bynodenamn, prefix):
                    cfgdata['ipv{}_gateway'.format(nver)] = socket.inet_ntop(fam, candgwn)
        return noneify(cfgdata)
    if ip is not None:
        async for prefixinfo in get_prefix_len_for_ip(ip):
            fam, prefix = prefixinfo
            ip = ip.split('/', 1)[0]
            if fam == socket.AF_INET:
                cfgdata['prefix'] = prefix
                nver = '4'
            else:
                nver = '6'
                cfgdata['ipv{}_prefix'.format(nver)] = prefix
            for setting in nodenetattribs:
                if 'ipv{}_gateway'.format(nver) not in setting:
                    continue
                gw = nodenetattribs[setting].get('value', None)
                if gw is None or not gw:
                    continue
                gwn = socket.inet_pton(fam, gw)
                ip = (await _getaddrinfo(ip, 0, proto=socket.IPPROTO_TCP, family=fam))[-1][-1][0]
                ipn = socket.inet_pton(fam, ip)
                if ipn_on_same_subnet(fam, ipn, gwn, prefix):
                    cfgdata['ipv{}_gateway'.format(nver)] = gw
                    break
    return noneify(cfgdata)

async def get_addresses_by_serverip(serverip):
    if '.' in serverip:
        fam = socket.AF_INET
    elif ':' in serverip:
        fam = socket.AF_INET6
    else:
        raise ValueError('"{0}" is not a valid ip argument'.format(serverip))
    ipbytes = socket.inet_pton(fam, serverip)
    if ipbytes[:8] == b'\xfe\x80\x00\x00\x00\x00\x00\x00':
        myaddrs = await get_my_addresses(matchlla=ipbytes)
    else:
        myaddrs = [x for x in await get_my_addresses() if x[1] == ipbytes]
    return myaddrs

nlhdrsz = struct.calcsize('IHHII')
ifaddrsz = struct.calcsize('BBBBI')

async def get_my_addresses(idx=0, family=0, matchlla=None):
    net = _tenantnet().current_network()
    if net is not None:
        return await _tenant_addresses(net, idx=idx, family=family, matchlla=matchlla)
    return await neighutil.get_my_addresses(idx=idx, family=family, matchlla=matchlla)


async def get_prefix_len_for_ip(ip):
    plen = None
    if '/' in ip:
        ip, plen = ip.split('/', 1)
        plen = int(plen)
    myaddrs = await get_my_addresses()
    found = False
    for inf in await _getaddrinfo(ip, 0, type=socket.SOCK_DGRAM):
        if plen:
            yield (inf[0], plen)
            return
        for myaddr in myaddrs:
            if inf[0] != myaddr[0]:
                continue
            if ipn_on_same_subnet(myaddr[0], myaddr[1], socket.inet_pton(myaddr[0], inf[-1][0]), myaddr[2]):
                found = True
                yield (myaddr[0], myaddr[2])
    if not found:
        raise exc.NotImplementedException("Non local addresses not supported")

async def addresses_match(addr1, addr2):
    """Check two network addresses for similarity

    Is it zero padded in one place, not zero padded in another?  Is one place by name and another by IP??
    Is one context getting a normal IPv4 address and another getting IPv4 in IPv6 notation?
    This function examines the two given names, performing the required changes to compare them for equivalency

    :param addr1:
    :param addr2:
    :return: True if the given addresses refer to the same thing
    """
    if '%' in addr1 or '%' in addr2:
        return False
    for addrinfo in await _getaddrinfo(addr1, 0, type=socket.SOCK_STREAM):
        rootaddr1 = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        if addrinfo[0] == socket.AF_INET6 and rootaddr1[:12] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff':
            # normalize to standard IPv4
            rootaddr1 = rootaddr1[-4:]
        for otherinfo in await _getaddrinfo(addr2, 0, type=socket.SOCK_STREAM):
            otheraddr = socket.inet_pton(otherinfo[0], otherinfo[4][0])
            if otherinfo[0] == socket.AF_INET6 and otheraddr[:12] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff':
                otheraddr = otheraddr[-4:]
            if otheraddr == rootaddr1:
                return True
    return False
