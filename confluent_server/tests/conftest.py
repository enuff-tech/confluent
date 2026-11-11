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

"""Shared fixtures for confluent_server tests.

The server keeps its configuration in module-level state inside
confluent.config.configmanager and persists it under
ConfigManager._cfgdir (normally /etc/confluent/cfg). The ``confluent_config``
fixture points that at a per-test temporary directory and resets the
module state before and after each test, so tests never touch a real
installation and never see each other's data.
"""

import os
import sys

import pytest

_TESTS = os.path.dirname(os.path.abspath(__file__))
_SERVER = os.path.dirname(_TESTS)
_REPO = os.path.dirname(_SERVER)
# 'confluent' is a namespace package split across the server and client
# trees, exactly as it is once installed.
for _path in (_SERVER, os.path.join(_REPO, 'confluent_client'), _TESTS):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import confluent.auth as auth
import confluent.config.configmanager as configmanager
import netnsutil


def _flush():
    if configmanager._cfgstore is not None:
        configmanager.ConfigManager.wait_for_sync()


def _reset_module_state():
    """Forget everything configmanager and auth hold in memory."""
    cm = configmanager.ConfigManager
    if cm._cfgwriter is not None:
        cm._cfgwriter.join()
    cm._cfgwriter = None
    cm._syncrunning = False
    cm._writepending = False
    cm._attribwatchers = {}
    cm._nodecollwatchers = {}
    cm._notifierids = {}
    configmanager._cfgstore = None
    configmanager._masterkey = None
    configmanager._masterintegritykey = None
    configmanager._ready = False
    configmanager._hasquorum = True
    configmanager.cfgleader = None
    configmanager.cfgstreams = {}
    configmanager._pendingchangesets.clear()
    auth._passcache.clear()
    auth._passchecking.clear()


class ConfluentConfig(object):
    """Handle for a throwaway configuration store."""

    def __init__(self, root):
        self.root = root
        self.cfgdir = os.path.join(root, 'cfg')
        self.logdir = os.path.join(root, 'log')

    def start(self):
        configmanager.init(cfgdir=self.cfgdir)
        configmanager.set_global('logdirectory', self.logdir)

    def manager(self, tenant=None, **kwargs):
        return configmanager.ConfigManager(tenant, **kwargs)

    def flush(self):
        _flush()

    def restart(self):
        """Simulate a service restart: write everything out, drop all
        in-memory state and load the store again from disk."""
        _flush()
        _reset_module_state()
        self.start()


@pytest.fixture
def confluent_config(tmp_path):
    _flush()
    _reset_module_state()
    cfg = ConfluentConfig(str(tmp_path))
    cfg.start()
    yield cfg
    _flush()
    _reset_module_state()


def pytest_collection_modifyitems(config, items):
    reason = netnsutil.unavailable_reason()
    if reason is None:
        return
    skip = pytest.mark.skip(reason=reason)
    for item in items:
        if 'netns' in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def netns():
    """Factory for throwaway network namespaces, removed after the test."""
    factory = netnsutil.NetnsFactory()
    yield factory
    factory.cleanup()
