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

"""Tenant lifecycle API for platform administrators, and enrollment of a
tenant's first administrator.

Platform administrators (local root, or main-store users with the
PlatformAdmin role) create, disable, enable and delete tenants and see
their metadata. They never get access to a tenant's configuration: a new
tenant gets a one-time enrollment token instead, which the tenant's first
administrator redeems to set their own credentials.
"""

import asyncio
import hashlib
import json
import re
import secrets
import time

import confluent.config.configmanager as configmanager
import confluent.exceptions as exc
import confluent.messages as msg

ENROLLMENT_LIFETIME = 86400
_username_re = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
MIN_PASSWORD_LENGTH = 8


def _token_hash(token):
    return hashlib.sha256(token.encode('utf8')).hexdigest()


def _lookup(name_or_id):
    """A tenant id from an id or a name, or NotFoundException."""
    if configmanager.valid_tenant_id(name_or_id) and configmanager.get_tenant(name_or_id):
        return name_or_id
    tenantid = configmanager.find_tenant(name_or_id)
    if tenantid is None:
        raise exc.NotFoundException('No such tenant')
    return tenantid


def _has_administrator(tenantid):
    # (as authorization sees it: a user or group without a role is an
    # administrator)
    cfm = configmanager.ConfigManager(tenantid)
    for user in cfm.list_users():
        if (cfm.get_user(user) or {}).get('role', 'Administrator') == 'Administrator':
            return True
    for group in cfm.list_usergroups():
        if (cfm.get_usergroup(group) or {}).get('role', 'Administrator') == 'Administrator':
            return True
    return False


def public_record(tenantid):
    """What platform administrators may see of a tenant: metadata and
    counts, never its configuration or the enrollment token hash."""
    record = configmanager.get_tenant(tenantid)
    cfm = configmanager.ConfigManager(tenantid)
    enrollment = record.get('enrollment')
    return {
        'id': tenantid,
        'name': record['name'],
        'state': record['state'],
        'created': record['created'],
        'nodes': len(list(cfm.list_nodes())),
        'users': len(list(cfm.list_users())),
        'enrollment_pending': bool(enrollment) and enrollment['expires'] > time.time(),
    }


async def issue_enrollment(tenantid):
    """A new one-time enrollment token for a tenant without an
    administrator. Only its hash is stored."""
    if _has_administrator(tenantid):
        raise exc.InvalidArgumentException(
            'The tenant already has an administrator')
    token = secrets.token_urlsafe(32)
    expires = int(time.time()) + ENROLLMENT_LIFETIME
    await configmanager.set_tenant_enrollment(tenantid, _token_hash(token), expires)
    return token, expires


async def create(name):
    tenantid = await configmanager.create_tenant(name)
    token, expires = await issue_enrollment(tenantid)
    result = public_record(tenantid)
    result['enrollment_token'] = token
    result['enrollment_expires'] = expires
    return result


async def redeem_enrollment(tenant, token, username, password):
    """Create a tenant's first administrator with a valid enrollment token.

    Raises ForbiddenRequest for any token, tenant or state problem, without
    saying which, and InvalidArgumentException for an unusable user name or
    password (checked first, so a bad request does not use up the token).
    """
    if not isinstance(username, str) or not _username_re.match(username):
        raise exc.InvalidArgumentException('Invalid user name')
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise exc.InvalidArgumentException(
            'Password must be at least {0} characters'.format(MIN_PASSWORD_LENGTH))
    if not isinstance(tenant, str) or not isinstance(token, str):
        raise exc.ForbiddenRequest()
    try:
        tenantid = _lookup(tenant)
    except exc.NotFoundException:
        raise exc.ForbiddenRequest()
    record = configmanager.get_tenant(tenantid)
    if not configmanager.multitenancy_enabled() or record['state'] != 'active':
        raise exc.ForbiddenRequest()
    if not await configmanager.consume_tenant_enrollment(tenantid, _token_hash(token)):
        raise exc.ForbiddenRequest()
    cfm = configmanager.ConfigManager(tenantid)
    await cfm.create_user(username, role='Administrator',
                          attributemap={'password': password})
    return {'tenant': record['name'], 'username': username}


async def redeem_enrollment_request(reqbody):
    """HTTP form of redeem_enrollment; returns (status, body)."""
    try:
        body = json.loads(reqbody) if reqbody else None
    except (TypeError, ValueError):
        body = None
    if not isinstance(body, dict) or set(body) != {'tenant', 'token', 'username', 'password'}:
        return 400, {'error': 'Expected tenant, token, username and password'}
    try:
        return 200, await redeem_enrollment(body['tenant'], body['token'],
                                            body['username'], body['password'])
    except exc.InvalidArgumentException as e:
        return 400, {'error': str(e)}
    except exc.ForbiddenRequest:
        await asyncio.sleep(0.05)  # as for a failed password check
        return 403, {'error': 'Enrollment refused'}


def _param(inputdata, name):
    if isinstance(inputdata, dict):
        value = inputdata.get(name)
        if isinstance(value, list) and len(value) == 1:  # query string form
            value = value[0]
        return value
    return None


def _require_enabled():
    if not configmanager.multitenancy_enabled():
        raise exc.NotFoundException('Multi-tenancy is not enabled')


async def handle_tenants_request(pathcomponents, operation, inputdata):
    """/tenants/ for platform administrators (authorization is done by the
    caller: auth.authorize admits only the PlatformAdmin role)."""
    _require_enabled()
    if len(pathcomponents) == 1:
        if operation == 'retrieve':
            return [msg.ChildCollection(t + '/') for t in configmanager.list_tenants()]
        if operation == 'create':
            name = _param(inputdata, 'name')
            if not isinstance(name, str):
                raise exc.InvalidArgumentException('name is required')
            return [msg.KeyValueData(await create(name))]
        raise exc.InvalidArgumentException('Unsupported operation')
    tenantid = _lookup(pathcomponents[1])
    rest = pathcomponents[2:]
    if rest == ['enrollment']:
        if operation != 'create':
            raise exc.InvalidArgumentException('Unsupported operation')
        token, expires = await issue_enrollment(tenantid)
        return [msg.KeyValueData({'id': tenantid, 'enrollment_token': token,
                                  'enrollment_expires': expires})]
    if rest:
        raise exc.NotFoundException('No such resource')
    if operation == 'retrieve':
        return [msg.KeyValueData(public_record(tenantid))]
    if operation == 'update':
        state = _param(inputdata, 'state')
        if state is None:
            raise exc.InvalidArgumentException('state is required')
        await configmanager.set_tenant_state(tenantid, state)
        return [msg.KeyValueData(public_record(tenantid))]
    if operation == 'delete':
        name = configmanager.get_tenant(tenantid)['name']
        if _param(inputdata, 'confirm') != name:
            raise exc.InvalidArgumentException(
                'Deleting a tenant requires confirm={0}'.format(name))
        await configmanager.delete_tenant(tenantid)
        return [msg.DeletedResource(tenantid)]
    raise exc.InvalidArgumentException('Unsupported operation')


async def handle_platform_request(pathcomponents, operation, inputdata):
    if pathcomponents[1:] != ['multitenancy']:
        raise exc.NotFoundException('No such resource')
    if operation == 'update':
        enabled = _param(inputdata, 'enabled')
        if isinstance(enabled, str):
            enabled = enabled.lower() in ('1', 'true', 'yes', 'enable', 'enabled')
        if not isinstance(enabled, bool):
            raise exc.InvalidArgumentException('enabled must be true or false')
        if enabled and configmanager.get_global('tenancy.schema') != configmanager.TENANCY_SCHEMA:
            raise exc.InvalidArgumentException(
                'Run "confluentdbutil migrate-tenancy" before enabling multi-tenancy')
        await configmanager.set_multitenancy_enabled(enabled)
    elif operation != 'retrieve':
        raise exc.InvalidArgumentException('Unsupported operation')
    return [msg.KeyValueData({
        'enabled': configmanager.multitenancy_enabled(),
        'schema': configmanager.get_global('tenancy.schema'),
        'tenants': len(configmanager.list_tenants())})]
