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

"""Which network aiohmi reaches BMCs through.

By default aiohmi uses the host's own network. A caller may instead give a
network object, either explicitly (net= on IPMI sessions and commands and
on web connections) or for everything the current task does, through
current_network. A network object provides:

    key                          hashable; sessions and sockets are never
                                 shared between different keys
    udp_socket(family)           a bound, non-blocking UDP socket
    async getaddrinfo(host, port)
                                 [(family, sockaddr)], resolved within it
    socket_factory(addrinfo)     an unconnected TCP socket for addrinfo's
                                 family (aiohttp's socket_factory)
    resolver()                   an aiohttp.abc.AbstractResolver
"""

import contextvars

current_network = contextvars.ContextVar('aiohmi_network', default=None)


def resolve(net=None):
    """The explicitly given network, else the current task's, else None
    (the host's own)."""
    if net is not None:
        return net
    return current_network.get()
