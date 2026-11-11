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

import pytest

import confluent.auth as auth


@pytest.fixture
async def users(confluent_config):
    cfm = confluent_config.manager()
    await cfm.create_user('admin', role='Administrator')
    await cfm.create_user('op', role='Operator')
    await cfm.create_user('mon', role='Monitor')
    return cfm


def _allowed(user, path, operation):
    return bool(auth.authorize(user, path, operation=operation))


@pytest.mark.parametrize('user,path,operation,expected', [
    ('admin', '/nodes/n1/configuration/management_controller/users/1', 'update', True),
    ('op', '/nodes/n1/power/state', 'update', True),
    ('op', '/nodes/n1/console/session', 'create', True),
    ('op', '/nodes/n1/configuration/management_controller/users/1', 'update', False),
    ('mon', '/nodes/n1/power/state', 'retrieve', True),
    ('mon', '/nodes/', 'retrieve', True),
    ('mon', '/nodes/n1/power/state', 'update', False),
    ('mon', '/nodes/n1/console/session', 'create', False),
])
async def test_role_rules(users, user, path, operation, expected):
    assert _allowed(user, path, operation) is expected


async def test_unknown_operation_is_refused(users):
    assert auth.authorize('admin', '/nodes/', operation='execute') is False


async def test_account_without_confluent_user_is_refused(users):
    # 'nobody' exists as an OS account but has no confluent user or group.
    assert auth.authorize('nobody', '/nodes/', operation='retrieve') is False


async def test_authorize_returns_default_tenant_manager(users):
    userobj, cfm, username, tenant, _ = auth.authorize('admin', '/nodes/', operation='retrieve')
    assert username == 'admin'
    assert tenant is None
    assert cfm.tenant is None
    assert userobj['role'] == 'Administrator'


@pytest.mark.parametrize('name,expected', [
    (b'alice', ['alice', None]),
    (b'acme/bob', ['bob', 'acme']),
])
async def test_tenant_scoped_login_names_are_parsed(confluent_config, name, expected):
    assert list(auth._get_usertenant(name)) == expected


async def test_unknown_tenant_is_refused(users):
    assert auth.authorize('ghosttenant/admin', '/nodes/', operation='retrieve') is False
