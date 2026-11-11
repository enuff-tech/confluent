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

"""Module-level state kept separately for each tenant.

Several subsystems (discovery among them) keep their working state in
module-level dictionaries. Replacing such a dictionary with a TenantScoped
one keeps the code that uses it unchanged, while each task sees only the
entries of the tenant it works for (tenantguard.current_tenant; None is
the default tenant, whose entries are exactly what the dictionary held
before).
"""

import collections.abc

import confluent.config.configmanager as configmanager
import confluent.tenantguard as tenantguard

_scoped = []


class TenantScoped(collections.abc.MutableMapping):
    """A dictionary per tenant, chosen by the current task's tenant."""

    def __init__(self, factory=dict):
        self._factory = factory
        self._stores = {}
        _scoped.append(self)

    def current(self):
        """The underlying dictionary of the current task's tenant."""
        tenant = tenantguard.current_tenant.get()
        store = self._stores.get(tenant)
        if store is None:
            store = self._stores[tenant] = self._factory()
        return store

    def for_tenant(self, tenant):
        """The underlying dictionary of a given tenant."""
        store = self._stores.get(tenant)
        if store is None:
            store = self._stores[tenant] = self._factory()
        return store

    def drop_tenant(self, tenant):
        self._stores.pop(tenant, None)

    def __getitem__(self, key):
        return self.current()[key]

    def __setitem__(self, key, value):
        self.current()[key] = value

    def __delitem__(self, key):
        del self.current()[key]

    def __iter__(self):
        return iter(self.current())

    def __len__(self):
        return len(self.current())

    def __contains__(self, key):
        return key in self.current()

    def clear(self):
        self.current().clear()

    def __repr__(self):
        return 'TenantScoped({0!r})'.format(self.current())


def drop_tenant(tenant):
    """Forget everything kept for a tenant (it was deleted)."""
    if tenant is None:
        return
    for scoped in _scoped:
        scoped.drop_tenant(tenant)


def _tenant_state_changed(tenant, state):
    if state == 'deleted':
        drop_tenant(tenant)


configmanager.watch_tenant_state(_tenant_state_changed)
