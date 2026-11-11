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

"""aiohmi's IPMI client against aiohmi's own BMC, on the host network."""

import asyncio
import socket

import aiohmi.ipmi.bmc as bmc
import aiohmi.ipmi.command as command
import aiohmi.ipmi.private.session as session
import aiohmi.util.netcontext as netcontext


class FakeBmc(bmc.Bmc):
    state = 'on'

    def get_power_state(self):
        return self.state


def _free_udp_port():
    probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    probe.bind(('::', 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


async def test_client_logs_in_to_a_sha1_only_bmc():
    # Regression: the simulator answers a SHA-256 open session request
    # with SHA-1; the client used to fail with struct.error in RAKP2.
    port = _free_udp_port()
    server = FakeBmc({'admin': 'pw'}, port=port)
    listener = asyncio.ensure_future(server.listen())
    try:
        await asyncio.sleep(0.2)
        cmd = await asyncio.wait_for(command.Command.create(
            bmc='127.0.0.1', userid='admin', password='pw', port=port), 30)
        assert (await asyncio.wait_for(cmd.get_power(), 30))['powerstate'] == 'on'
        assert cmd.net is None and cmd.ipmi_session.netkey is None
    finally:
        listener.cancel()


def test_network_resolution_prefers_the_explicit_one():
    marker = object()
    assert netcontext.resolve(marker) is marker
    token = netcontext.current_network.set('ctx')
    try:
        assert netcontext.resolve() == 'ctx'
        assert netcontext.resolve(marker) is marker
    finally:
        netcontext.current_network.reset(token)
    assert netcontext.resolve() is None


async def test_watcher_runs_outside_its_first_callers_context():
    # The shared socket watcher must not inherit the context of whichever
    # caller happened to start it.
    if session.iothread is None:
        return  # started by an earlier test in this process only
    assert netcontext.current_network.get() is None
