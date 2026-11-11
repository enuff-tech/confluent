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

"""Fail-closed backstop for tenant network isolation.

Work done for a tenant must reach the network only through sockets that
came from that tenant's broker (confluent.tenantnet). While the current
task runs in a tenant context, this audit hook refuses connecting,
binding or sending to an address on any other socket, host name lookups
and starting processes. That covers code paths not yet ported to
tenantnet, including those inside libraries, since CPython raises these
audit events from C. In the default tenant's context nothing changes.

The tenant context is a context variable: asyncio tasks inherit it, and
install() gives the event loop a default executor that carries it into
run_in_executor threads (asyncio.to_thread already does).
"""

import concurrent.futures
import contextlib
import contextvars
import ipaddress
import sys
import weakref

current_tenant = contextvars.ContextVar('confluent_tenant', default=None)

_brokered = {}  # tenant -> WeakSet of sockets received from its broker
_control = weakref.WeakSet()  # tenantnet's own connections to brokers
_installed = [False]

_SOCKET_EVENTS = frozenset(['socket.connect', 'socket.bind', 'socket.sendto',
                            'socket.sendmsg'])
_LOOKUP_EVENTS = frozenset(['socket.getaddrinfo', 'socket.gethostbyname',
                            'socket.gethostbyname_ex', 'socket.gethostbyaddr',
                            'socket.getnameinfo'])
_PROCESS_EVENTS = frozenset(['subprocess.Popen', 'os.system', 'os.exec',
                             'os.posix_spawn', 'os.spawn', 'os.fork',
                             'os.forkpty'])


class TenantNetworkViolation(PermissionError):
    """Refused: the operation would not have used the tenant's network."""


def register(tenant, sock):
    """Mark a socket as obtained from this tenant's broker."""
    _brokered.setdefault(tenant, weakref.WeakSet()).add(sock)
    return sock


def register_control(sock):
    """Mark a socket as tenantnet's own connection to a broker."""
    _control.add(sock)
    return sock


def _is_literal(host):
    if isinstance(host, bytes):
        host = host.decode('utf8', 'replace')
    if not isinstance(host, str):
        return host is None  # getaddrinfo(None, port) needs no lookup
    try:
        ipaddress.ip_address(host.split('%', 1)[0])
        return True
    except ValueError:
        return False


def _hook(event, args):
    tenant = current_tenant.get()
    if tenant is None:
        return
    if event in _SOCKET_EVENTS:
        sock = args[0]
        if sock in _control or sock in _brokered.get(tenant, ()):
            return
        raise TenantNetworkViolation(
            'tenant {0}: {1} on a socket not from its broker'.format(tenant, event))
    if event in _LOOKUP_EVENTS:
        if event == 'socket.getaddrinfo' and _is_literal(args[0]):
            return  # address literals are not looked up
        raise TenantNetworkViolation(
            'tenant {0}: {1} refused; resolve names through the broker'.format(tenant, event))
    if event in _PROCESS_EVENTS:
        raise TenantNetworkViolation(
            'tenant {0}: {1} refused'.format(tenant, event))


class ContextThreadPoolExecutor(concurrent.futures.ThreadPoolExecutor):
    """A thread pool whose work runs in the submitter's context."""

    def submit(self, fn, *args, **kwargs):
        ctx = contextvars.copy_context()
        return super(ContextThreadPoolExecutor, self).submit(ctx.run, fn, *args, **kwargs)


def install(loop=None):
    """Install the audit hook (once per process) and, given an event loop,
    make its default executor carry the tenant context."""
    if not _installed[0]:
        sys.addaudithook(_hook)
        _installed[0] = True
    if loop is not None:
        loop.set_default_executor(ContextThreadPoolExecutor())


def enter(tenant):
    """Run the rest of the current task (and the tasks it starts) as work
    for tenant; None is the default tenant."""
    current_tenant.set(tenant)


@contextlib.contextmanager
def tenant_context(tenant):
    token = current_tenant.set(tenant)
    try:
        yield
    finally:
        current_tenant.reset(token)
