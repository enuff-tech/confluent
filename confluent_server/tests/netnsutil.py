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

"""Helpers for tests that need real Linux network namespaces.

Everything created here carries a per-factory random prefix so parallel
runs and leftovers from an interrupted run never collide, and cleanup only
ever removes objects that carry that prefix.
"""

import os
import shutil
import subprocess
import sys
import uuid


def unavailable_reason():
    """None when namespace tests can run here, else why they cannot."""
    if not sys.platform.startswith('linux'):
        return 'network namespaces need Linux'
    if os.geteuid() != 0:
        return 'network namespace tests need root (run with sudo)'
    if shutil.which('ip') is None:
        return 'iproute2 (ip) not installed'
    return None


def _ip(*args, **kwargs):
    return subprocess.run(('ip',) + args, check=True, capture_output=True,
                          text=True, **kwargs)


class NetnsFactory(object):
    def __init__(self):
        self.prefix = 'cft%s' % uuid.uuid4().hex[:6]
        self.namespaces = []
        self.processes = []
        self._count = 0

    def _name(self, tag):
        self._count += 1
        return '%s%s%d' % (self.prefix, tag, self._count)

    def create(self):
        """Create a namespace with loopback up and return its name."""
        name = self._name('n')
        _ip('netns', 'add', name)
        self.namespaces.append(name)
        _ip('-n', name, 'link', 'set', 'lo', 'up')
        return name

    def veth(self, ns_a, name_a, addr_a, ns_b, name_b, addr_b, mac_a=None, mac_b=None):
        """Connect two namespaces with a veth pair.

        The caller picks the interface names inside each namespace, so two
        tenants can both have an ``up0`` with the same MAC and address.
        ns_a may be None for the host's own namespace; the host end then
        keeps a generated name (returned) and goes away with ns_b.
        """
        tmp_a, tmp_b = self._name('a'), self._name('b')
        _ip('link', 'add', tmp_a, 'type', 'veth', 'peer', 'name', tmp_b)
        if ns_a is None:
            name_a = tmp_a
        for ns, tmp, name, addr, mac in ((ns_a, tmp_a, name_a, addr_a, mac_a),
                                         (ns_b, tmp_b, name_b, addr_b, mac_b)):
            prefix = []
            if ns is not None:
                _ip('link', 'set', tmp, 'netns', ns)
                prefix = ['-n', ns]
            args = prefix + ['link', 'set', tmp, 'name', name]
            if mac:
                args += ['address', mac]
            _ip(*args)
            if addr:
                _ip(*(prefix + ['addr', 'add', addr, 'dev', name]))
            _ip(*(prefix + ['link', 'set', name, 'up']))
        return name_a

    def spawn(self, ns, *cmd, **kwargs):
        """Start a long-running process inside a namespace; stopped on
        cleanup."""
        kwargs.setdefault('stdout', subprocess.DEVNULL)
        kwargs.setdefault('stderr', subprocess.DEVNULL)
        proc = subprocess.Popen(('ip', 'netns', 'exec', ns) + cmd, **kwargs)
        self.processes.append(proc)
        return proc

    def run(self, ns, *cmd, **kwargs):
        """Run a command inside a namespace."""
        kwargs.setdefault('check', True)
        kwargs.setdefault('capture_output', True)
        kwargs.setdefault('text', True)
        return subprocess.run(('ip', 'netns', 'exec', ns) + cmd, **kwargs)

    def inode(self, ns):
        return os.stat(os.path.join('/run/netns', ns)).st_ino

    def cleanup(self):
        for proc in self.processes:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.processes = []
        for ns in reversed(self.namespaces):
            if ns.startswith(self.prefix):
                subprocess.run(('ip', 'netns', 'del', ns), capture_output=True)
        self.namespaces = []
