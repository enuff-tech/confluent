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

"""The network a tenant manages for itself.

The platform decides which interfaces a tenant's namespace has (its
uplinks). What happens on them is the tenant administrator's:

    /networking/interfaces/<name>   addresses, link state, MTU
    /networking/routes              static routes
    /networking/dns                 name servers and search domains

The configuration is kept in the tenant's own store and applied in the
tenant's namespace by its configuration helper (nsnetcfg), which can act
on nothing else. Two tenants can therefore use the same networks, routes
and addresses. It is applied again whenever the namespace is new (after a
reboot) or one of its interfaces comes back.

It is the configuration of this member of a collective: each member has
its own namespace for the tenant, with addresses of its own.
"""

import asyncio
import copy
import ipaddress

import confluent.config.configmanager as configmanager
import confluent.exceptions as exc
import confluent.log as log
import confluent.messages as msg
import confluent.tasks as tasks
import confluent.tenantnet as tenantnet

GLOBAL = 'netcfg'
POLL = 10
_monitors = {}
_applied = {}


def _stored(cfm):
    stored = copy.deepcopy(cfm.get_scoped_global(GLOBAL) or {})
    stored.setdefault('interfaces', {})
    stored.setdefault('routes', [])
    stored.setdefault('dns', {})
    return stored


async def _call(tenant, op, args=None):
    """One operation of the tenant's configuration helper."""
    def call():
        return tenantnet.netcfg_for(tenant).call(op, args or {})[0]
    return await asyncio.get_running_loop().run_in_executor(None, call)


def _global(address):
    return not ipaddress.ip_interface(address).ip.is_link_local


def _route_key(route):
    return (route['destination'], route.get('gateway'), route.get('ifname'),
            route.get('metric') or 0)


def _route_args(route):
    return dict((k, v) for k, v in route.items()
                if k in ('destination', 'gateway', 'ifname', 'metric') and v is not None)


async def apply(tenant):
    """Make the tenant's namespace match its stored configuration.

    Interfaces the tenant configured get exactly the addresses it listed
    (link-local ones aside); the static routes become exactly the listed
    ones. Interfaces it has not configured are left as they are. Returns
    what changed and what could not be done.
    """
    stored = _stored(configmanager.ConfigManager(tenant))
    changes, errors = [], []

    async def attempt(what, op, args):
        try:
            await _call(tenant, op, args)
            changes.append(what)
        except tenantnet.BrokerError as e:
            if e.code != 'EEXIST':
                errors.append('{0}: {1}'.format(what, e))
    links = dict((i['name'], i) for i in (await _call(tenant, 'link_list'))['interfaces'])
    for name, wanted in sorted(stored['interfaces'].items()):
        link = links.get(name)
        if link is None:
            errors.append('{0}: no such interface in the tenant network'.format(name))
            continue
        linkargs = {'ifname': name}
        if wanted.get('mtu') and wanted['mtu'] != link.get('mtu'):
            linkargs['mtu'] = wanted['mtu']
        if wanted.get('up') is not None and wanted['up'] != link.get('up'):
            linkargs['up'] = wanted['up']
        if len(linkargs) > 1:
            await attempt('{0}: link'.format(name), 'link_set', linkargs)
        live = set(a for a in link.get('ipv4', []) + link.get('ipv6', []) if _global(a))
        desired = set(str(ipaddress.ip_interface(a)) for a in wanted.get('addresses', []))
        for address in sorted(desired - live):
            await attempt('{0}: + {1}'.format(name, address), 'addr_add',
                          {'ifname': name, 'address': address})
        for address in sorted(live - desired):
            await attempt('{0}: - {1}'.format(name, address), 'addr_del',
                          {'ifname': name, 'address': address})
    live = dict((_route_key(r), r) for r in (await _call(tenant, 'route_list'))['routes']
                if r['protocol'] == 'static')
    desired = dict((_route_key(r), r) for r in stored['routes'])
    for key in sorted(set(live) - set(desired), key=repr):
        await attempt('route - {0}'.format(key[0]), 'route_del', _route_args(live[key]))
    for key in sorted(set(desired) - set(live), key=repr):
        await attempt('route + {0}'.format(key[0]), 'route_add', _route_args(desired[key]))
    if stored['dns'] != _applied.get(tenant, {}).get('dns'):
        try:
            await _call(tenant, 'dns_set', {
                'nameservers': stored['dns'].get('nameservers', []),
                'search': stored['dns'].get('search', [])})
            if stored['dns'] or _applied.get(tenant, {}).get('dns'):
                changes.append('dns')
        except tenantnet.BrokerError as e:
            if e.code != 'EOPNOTSUPP':
                errors.append('dns: {0}'.format(e))
    state = await _call(tenant, 'state')
    _applied[tenant] = {'dns': copy.deepcopy(stored['dns']),
                        'state': (state['pid'], state['generation'])}
    if changes:
        _restart_listeners(tenant)
    return {'changed': changes, 'errors': errors}


def _restart_listeners(tenant):
    """Discovery and the services for the tenant's nodes are bound to the
    addresses the tenant had when they started (multicast memberships, the
    names in the server certificate): start them again on the new ones."""
    import confluent.discovery.core as disco
    import confluent.tenantservices as tenantservices
    for stop, start in ((disco.stop_tenant_detection, disco.start_tenant_detection),
                        (tenantservices.stop, tenantservices.start)):
        try:
            stop(tenant)
            start(tenant)
        except Exception:
            log.logtrace()


async def _monitor(tenant):
    """Apply the tenant's configuration whenever its namespace is new or
    its links changed behind our back."""
    while True:
        try:
            state = await _call(tenant, 'state')
            if (state['pid'], state['generation']) != _applied.get(tenant, {}).get('state'):
                result = await apply(tenant)
                if result['errors']:
                    log.service_log({'error': 'Network configuration of tenant {0} was not '
                                              'applied completely ({1} problems)'.format(
                                                  tenant, len(result['errors']))})
        except tenantnet.TenantNetworkError:
            pass  # no helper (yet): the platform configures this network
        except asyncio.CancelledError:
            raise
        except Exception:
            log.logtrace()
        await asyncio.sleep(POLL)


def start(tenant):
    """Keep a tenant's network configured (while it is in use)."""
    record = configmanager.get_tenant(tenant) if tenant is not None else None
    if not (record and record['state'] == 'active' and configmanager.multitenancy_enabled()):
        return False
    if tenant not in _monitors or _monitors[tenant].done():
        try:
            _monitors[tenant] = tasks.spawn_task(_monitor(tenant))
        except RuntimeError:  # no event loop (configuration tools)
            return False
    return True


def stop(tenant):
    monitor = _monitors.pop(tenant, None)
    _applied.pop(tenant, None)
    if monitor is not None:
        tasks.cancel_all([monitor])


def start_all():
    if configmanager.multitenancy_enabled():
        for tenant in configmanager.list_tenants():
            start(tenant)


def _tenant_state_changed(tenant, state):
    if state == 'active':
        start(tenant)
    else:
        stop(tenant)


configmanager.watch_tenant_state(_tenant_state_changed, first=True)


# ----------------------------------------------------------------- API

def _addresses(value):
    if isinstance(value, str):
        value = [v for v in value.replace(',', ' ').split() if v]
    if not isinstance(value, (list, tuple)):
        raise exc.InvalidArgumentException('addresses must be a list of address/prefix')
    result = []
    for address in value:
        try:
            if not isinstance(address, str) or '/' not in address:
                raise ValueError(address)
            parsed = ipaddress.ip_interface(address)
        except ValueError:
            raise exc.InvalidArgumentException(
                'Invalid address {0!r}: give address/prefix'.format(address))
        if parsed.ip.is_loopback or parsed.ip.is_multicast or parsed.ip.is_unspecified:
            raise exc.InvalidArgumentException(
                '{0} is not an address a host can have'.format(address))
        result.append(str(parsed))
    return sorted(set(result))


def _routes(value):
    if not isinstance(value, (list, tuple)):
        raise exc.InvalidArgumentException('routes must be a list')
    result = []
    for route in value:
        if not isinstance(route, dict) or set(route) - {'destination', 'gateway',
                                                        'ifname', 'interface', 'metric'}:
            raise exc.InvalidArgumentException(
                'A route has a destination, and a gateway and/or an interface')
        clean = {'destination': route.get('destination')}
        ifname = route.get('ifname', route.get('interface'))
        try:
            gateway = route.get('gateway')
            if gateway:
                clean['gateway'] = str(ipaddress.ip_address(gateway))
            if clean['destination'] != 'default':
                clean['destination'] = str(ipaddress.ip_network(clean['destination']))
            elif not gateway:
                raise ValueError('a default route needs a gateway')
        except (TypeError, ValueError) as e:
            raise exc.InvalidArgumentException('Invalid route: {0}'.format(e))
        if ifname:
            clean['ifname'] = str(ifname)
        if 'gateway' not in clean and 'ifname' not in clean:
            raise exc.InvalidArgumentException('A route needs a gateway or an interface')
        if route.get('metric') not in (None, ''):
            try:
                clean['metric'] = int(route['metric'])
            except (TypeError, ValueError):
                raise exc.InvalidArgumentException('Invalid route metric')
        result.append(clean)
    return result


def _dns(value):
    clean = {}
    for key in ('nameservers', 'search'):
        entries = value.get(key, [])
        if isinstance(entries, str):
            entries = [v for v in entries.replace(',', ' ').split() if v]
        if not isinstance(entries, (list, tuple)):
            raise exc.InvalidArgumentException('{0} must be a list'.format(key))
        clean[key] = [str(e) for e in entries]
    try:
        clean['nameservers'] = [str(ipaddress.ip_address(n)) for n in clean['nameservers']]
    except ValueError:
        raise exc.InvalidArgumentException('Name servers must be IP addresses')
    if set(value) - {'nameservers', 'search'}:
        raise exc.InvalidArgumentException('Only nameservers and search can be set')
    return clean


def _bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ('true', 'yes', '1', 'up'):
        return True
    if isinstance(value, str) and value.lower() in ('false', 'no', '0', 'down'):
        return False
    raise exc.InvalidArgumentException('up must be true or false')


async def _live(tenant):
    try:
        links = (await _call(tenant, 'link_list'))['interfaces']
        routes = (await _call(tenant, 'route_list'))['routes']
    except tenantnet.TenantNetworkError as e:
        raise exc.TargetEndpointUnreachable(
            'The network of this tenant cannot be configured here: {0}'.format(e))
    return dict((i['name'], i) for i in links if i['name'] != 'lo'), routes


def _interface_view(name, link, stored):
    view = {'name': name, 'configured': stored['interfaces'].get(name, {})}
    if link is None:
        view['present'] = False
    else:
        view.update(present=True, up=link.get('up'), mtu=link.get('mtu'),
                    mac=link.get('mac'),
                    addresses=link.get('ipv4', []) + link.get('ipv6', []))
    return view


async def _save_and_apply(cfm, stored):
    cfm.set_scoped_global(GLOBAL, stored)
    try:
        return await apply(cfm.tenant)
    except tenantnet.TenantNetworkError as e:
        raise exc.TargetEndpointUnreachable(
            'Saved, but the network of this tenant cannot be configured '
            'now: {0}'.format(e))


async def handle_api_request(configmanager_, inputdata, operation, pathcomponents):
    """/networking/{interfaces,routes,dns} for the tenant of the request."""
    cfm = configmanager_
    if cfm.tenant is None:
        raise exc.NotFoundException(
            'Only the network of a tenant is managed here; the network of '
            'the default tenant is the host\'s own')
    tenant = cfm.tenant
    kind = pathcomponents[1]
    stored = _stored(cfm)
    inputdata = inputdata or {}
    if operation not in ('retrieve', 'update', 'delete'):
        raise exc.InvalidArgumentException('Unsupported operation')
    if kind == 'interfaces':
        links, _ = await _live(tenant)
        if len(pathcomponents) == 2:
            if operation != 'retrieve':
                raise exc.InvalidArgumentException('Configure an interface by name')
            return [msg.ChildCollection(name) for name in sorted(
                set(links) | set(stored['interfaces']))]
        name = pathcomponents[2]
        if len(pathcomponents) != 3:
            raise exc.NotFoundException()
        if operation == 'retrieve':
            if name not in links and name not in stored['interfaces']:
                raise exc.NotFoundException('No such interface in this tenant\'s network')
            return [msg.KeyValueData(_interface_view(name, links.get(name), stored))]
        if operation == 'delete':
            stored['interfaces'].pop(name, None)
            # what the tenant had put on it goes with its configuration
            if name in links:
                stored['interfaces'][name] = {'addresses': []}
                await _save_and_apply(cfm, stored)
                del stored['interfaces'][name]
            cfm.set_scoped_global(GLOBAL, stored)
            return [msg.DeletedResource('networking/interfaces/' + name)]
        if name not in links:
            # only what the platform attached to this tenant exists for it
            raise exc.NotFoundException('No such interface in this tenant\'s network')
        if set(inputdata) - {'addresses', 'up', 'mtu'}:
            raise exc.InvalidArgumentException('Only addresses, up and mtu can be set')
        wanted = stored['interfaces'].setdefault(name, {})
        if 'addresses' in inputdata:
            wanted['addresses'] = _addresses(inputdata['addresses'])
        if 'up' in inputdata:
            wanted['up'] = _bool(inputdata['up'])
        if 'mtu' in inputdata:
            try:
                wanted['mtu'] = int(inputdata['mtu'])
            except (TypeError, ValueError):
                raise exc.InvalidArgumentException('mtu must be a number')
            if not 68 <= wanted['mtu'] <= 65535:
                raise exc.InvalidArgumentException('mtu must be between 68 and 65535')
        result = await _save_and_apply(cfm, stored)
        links, _ = await _live(tenant)
        view = _interface_view(name, links.get(name), stored)
        view['errors'] = result['errors']
        return [msg.KeyValueData(view)]
    if len(pathcomponents) != 2:
        raise exc.NotFoundException()
    if kind == 'routes':
        if operation == 'retrieve':
            _, routes = await _live(tenant)
            return [msg.KeyValueData({'configured': stored['routes'], 'active': routes})]
        stored['routes'] = [] if operation == 'delete' else _routes(inputdata.get('routes'))
        result = await _save_and_apply(cfm, stored)
        _, routes = await _live(tenant)
        return [msg.KeyValueData({'configured': stored['routes'], 'active': routes,
                                  'errors': result['errors']})]
    if kind == 'dns':
        if operation == 'retrieve':
            return [msg.KeyValueData(dict(stored['dns']))]
        stored['dns'] = {} if operation == 'delete' else _dns(inputdata)
        result = await _save_and_apply(cfm, stored)
        return [msg.KeyValueData(dict(stored['dns'], errors=result['errors']))]
    raise exc.NotFoundException()
