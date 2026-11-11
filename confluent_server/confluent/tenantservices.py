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

"""The services a tenant's nodes reach, within the tenant's network.

Each active tenant gets its own listeners, on sockets its network broker
opens in its namespace:

* HTTPS (443), with a certificate of the tenant's own authority, serving
  the node self-service API (/confluent-api/self/...) as the web server in
  front of the service does for the default tenant.
* The credential server (13001), where a node presents the API key it
  wants to use.

A node never names its tenant: the tenant is the one whose listener it
reached. So nodes with the same name, address and identifiers in two
tenants are two different nodes, each answered from its own tenant's
configuration, and nothing a node sends can select another tenant.
"""

import asyncio
import ipaddress

from aiohttp import web

import confluent.config.configmanager as configmanager
import confluent.credserver as credserver
import confluent.log as log
import confluent.selfservice as selfservice
import confluent.tasks as tasks
import confluent.tenantca as tenantca
import confluent.tenantnet as tenantnet

HTTPS_PORT = 443
CRED_PORT = 13001
RETRY = 30
_services = {}

_SECURITY_HEADERS = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'self'",
    'X-Frame-Options': 'deny',
    'Strict-Transport-Security': 'max-age=86400',
}


def _wanted(tenant):
    record = configmanager.get_tenant(tenant)
    return bool(configmanager.multitenancy_enabled() and record
                and record['state'] == 'active')


def start(tenant):
    """Serve a tenant's nodes in its network (if it is active); returns
    whether its services are (being) set up."""
    if tenant is None or tenant in _services:
        return tenant in _services
    if not _wanted(tenant):
        return False
    state = {'tasks': [], 'sockets': [], 'servers': [], 'runner': None,
             'serving': False}
    _services[tenant] = state
    try:
        state['tasks'].append(tasks.spawn_task(_serve(tenant, state)))
    except RuntimeError:  # no event loop (configuration tools)
        del _services[tenant]
        return False
    return True


def stop(tenant):
    """Stop serving a tenant's nodes and close its listeners."""
    state = _services.pop(tenant, None)
    if state is None:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None  # no event loop: nothing is being served
    # At once, and in this order: the event loop lets go of each listener
    # before it is closed (or a later socket with the same descriptor
    # would inherit its registration).
    for server in state['servers']:
        server.close()
    for task in state['tasks']:
        try:
            task.cancel()
        except RuntimeError:  # its event loop is gone
            pass
    for sock in state['sockets']:
        try:
            if loop is not None and sock.fileno() != -1:
                loop.remove_reader(sock)
            sock.close()
        except (OSError, ValueError):
            pass
    del state['servers'][:]
    del state['sockets'][:]
    runner, state['runner'] = state['runner'], None
    if loop is not None and runner is not None:
        # connections still open are closed in the background
        tasks.spawn_task(_cleanup(runner))


async def _cleanup(runner):
    try:
        await runner.cleanup()
    except Exception:
        log.logtrace()


def start_all():
    if configmanager.multitenancy_enabled():
        for tenant in configmanager.list_tenants():
            start(tenant)


def status(tenant):
    """None if the tenant's nodes are not served, else whether its
    listeners are up (False while its network is not reachable yet)."""
    state = _services.get(tenant)
    return None if state is None else state['serving']


def _plain(address):
    address = address.split('%')[0]
    try:
        mapped = ipaddress.ip_address(address)
    except ValueError:
        return address
    if mapped.version == 6 and mapped.ipv4_mapped:
        return str(mapped.ipv4_mapped)
    return address


def _handler(tenant):
    async def handle(request):
        # The tenant is this listener's: nothing in the request selects it.
        tenantnet.enter(tenant)
        made = []

        async def make_response(mimetype='application/json', status=200,
                                reason=None, headers=None, cookies=None, body=None):
            rspheaders = dict(_SECURITY_HEADERS)
            if headers:
                rspheaders.update(headers)
            rsp = web.StreamResponse(status=status, reason=reason, headers=rspheaders)
            rsp.content_type = mimetype
            made.append(rsp)
            await rsp.prepare(request)
            if body:
                if isinstance(body, str):
                    body = body.encode('utf8')
                await rsp.write(body)
            return rsp

        path = request.rel_url.path
        if path.startswith('/confluent-api/'):
            path = path[len('/confluent-api'):]
        if not path.startswith('/self/'):
            # only what nodes need is served in a tenant's network
            return await make_response('text/plain', 404, 'Not Found', body='Not Found')
        peer = request.transport.get_extra_info('peername') or ('',)
        local = request.transport.get_extra_info('sockname') or ('',)
        try:
            rsp = await selfservice.handle_request(
                request, make_response, 'application/json', tenant=tenant,
                clientip=_plain(peer[0]), myip=_plain(local[0]), reqpath=path)
        except Exception:
            log.logtrace()
            if made:
                return made[-1]  # already answering: nothing more to say
            return await make_response('text/plain', 500, 'Internal Server Error',
                                       body='Internal Server Error')
        if rsp is None:
            # some paths answer without returning the response they wrote
            if made:
                return made[-1]
            return await make_response('text/plain', 404, 'Not Found', body='Not Found')
        return rsp
    return handle


async def _accept_credentials(tenant, sock):
    creds = credserver.CredServer(tenant)
    loop = asyncio.get_running_loop()
    while True:
        try:
            client, peer = await loop.sock_accept(sock)
        except OSError:
            return
        if peer[1] < 1000:
            # as for the default tenant: a privileged source port, so a
            # process of the node's administrator
            tasks.spawn(creds.handle_client(client, (_plain(peer[0]),) + tuple(peer[1:])))
        else:
            client.close()


async def _serve(tenant, state):
    tenantnet.enter(tenant)
    net = tenantnet.current_network()
    reported = False
    while True:
        try:
            interfaces = await net.alist_interfaces()
            break
        except tenantnet.TenantNetworkError as e:
            if not reported:
                reported = True
                log.log({'info': 'Nodes of tenant {0} are not served until its '
                                 'network is available: {1}'.format(tenant, e)})
            await asyncio.sleep(RETRY)
    names = set()
    for iface in interfaces:
        for key in ('ipv4', 'ipv6'):
            for addr in iface.get(key, []):
                addr = ipaddress.ip_interface(addr).ip
                if not addr.is_loopback:
                    names.add(str(addr))
    context = await tenantca.server_context(tenant, names or {'localhost'})
    app = web.Application()
    app.router.add_route('*', '/{path_info:.*}', _handler(tenant))
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    state['runner'] = runner
    loop = asyncio.get_running_loop()
    for family in ('inet', 'inet6'):
        try:
            sock = net.listen_tcp(HTTPS_PORT, family)
            state['servers'].append(await loop.create_server(
                runner.server, sock=sock, ssl=context))
            sock = net.listen_tcp(CRED_PORT, family)
            state['sockets'].append(sock)
            state['tasks'].append(tasks.spawn_task(_accept_credentials(tenant, sock)))
        except tenantnet.BrokerError as e:
            if family == 'inet':
                raise
            log.log({'info': 'Tenant {0} is not served over IPv6: {1}'.format(tenant, e)})
    state['serving'] = True
    log.log({'info': 'Serving the nodes of tenant {0} in its network '
                     '({1})'.format(tenant, ', '.join(sorted(names)))})


def _tenant_state_changed(tenant, state):
    if state == 'active':
        start(tenant)
    else:
        stop(tenant)


configmanager.watch_tenant_state(_tenant_state_changed, first=True)
