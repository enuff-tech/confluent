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

"""The broker's request handling: closed operation set, strict arguments,
allowlists and rate limit. These run unprivileged; the namespace
behaviour is covered by test_tenantnet.py."""

import json
import socket

import pytest

import confluent.nsbroker as nsbroker


@pytest.fixture
def ctx():
    return {'tenant': 't0123456789ab', 'limiter': nsbroker.RateLimiter()}


def _call(ctx, op, args=None, raw=None, version=1):
    data = raw if raw is not None else json.dumps(
        {'v': version, 'id': 7, 'op': op, 'args': args or {}}).encode()
    msgid, opname, result, sock, error = nsbroker.handle_request(ctx, data)
    if sock is not None:
        sock.close()
    return result, sock is not None, error


def test_hello_reports_identity(ctx):
    result, _, error = _call(ctx, 'hello')
    assert error is None
    assert result['tenant'] == 't0123456789ab' and result['version'] == 1
    assert result['netns_ino'] > 0 and 'CapEff' in result['proc']


def test_unprivileged_operations(ctx):
    result, sock, error = _call(ctx, 'udp_socket', {'family': 'inet'})
    assert error is None and sock and result['port'] > 0
    result, _, error = _call(ctx, 'list_interfaces')
    names = [i['name'] for i in result['interfaces']]
    assert error is None and 'lo' in names
    lo = [i for i in result['interfaces'] if i['name'] == 'lo'][0]
    assert lo['ipv4'] == ['127.0.0.1/8'] and lo['up']


@pytest.mark.parametrize('op,args,code', [
    ('exec', {'argv': ['/bin/sh']}, 'EOPNOTSUPP'),
    ('setsockopt', {}, 'EOPNOTSUPP'),
    ('listen_tcp', {'family': 'inet', 'port': 22}, 'EACCES'),
    ('listen_tcp', {'family': 'inet', 'port': 0}, 'EACCES'),
    ('udp_socket', {'family': 'inet', 'port': 5000}, 'EACCES'),
    ('udp_socket', {'family': 'unix'}, 'EINVAL'),
    ('udp_socket', {'family': 'inet', 'broadcast': 'yes'}, 'EINVAL'),
    ('packet_socket', {'ifname': 'lo', 'ethertype': 3}, 'EACCES'),
    ('packet_socket', {'ifname': 'lo', 'ethertype': 0x88b5}, 'EACCES'),
    ('packet_socket', {'ifname': 'nosuchif0', 'ethertype': 0x0800}, 'ENODEV'),
    ('packet_socket', {'ifname': '../x', 'ethertype': 0x0800}, 'EINVAL'),
    ('connect_tcp', {'family': 'inet', 'host': 'bmc1', 'port': 443}, 'EINVAL'),
    ('connect_tcp', {'family': 'inet', 'host': '::1', 'port': 443}, 'EINVAL'),
    ('connect_tcp', {'family': 'inet', 'host': '127.0.0.1', 'port': 0}, 'EINVAL'),
    ('connect_tcp', {'family': 'inet', 'host': '127.0.0.1', 'port': 443, 'bind': '0.0.0.0'}, 'EINVAL'),
    ('connect_tcp', {'family': 'inet', 'host': '127.0.0.1'}, 'EINVAL'),
    ('connect_tcp', {'family': 'inet', 'host': '127.0.0.1', 'port': 443, 'timeout': 600}, 'EINVAL'),
    ('resolve', {'name': 'bad name!'}, 'EINVAL'),
    ('hello', {'x': 1}, 'EINVAL'),
])
def test_refused_requests(ctx, op, args, code):
    result, sock, error = _call(ctx, op, args)
    assert error is not None and error.code == code, (result, error)
    assert not sock


@pytest.mark.parametrize('raw,code', [
    (b'{' + b' ' * 5000 + b'}', 'EMSGSIZE'),
    (b'not json', 'EINVAL'),
    (b'[1, 2]', 'EINVAL'),
    (json.dumps({'v': 1, 'id': 1, 'op': 'hello', 'extra': 1}).encode(), 'EINVAL'),
    (json.dumps({'v': 1, 'id': True, 'op': 'hello'}).encode(), 'EINVAL'),
    (json.dumps({'v': 1, 'id': 'one', 'op': 'hello'}).encode(), 'EINVAL'),
])
def test_malformed_requests(ctx, raw, code):
    _, _, error = _call(ctx, None, raw=raw)
    assert error.code == code


def test_protocol_version_is_checked(ctx):
    _, _, error = _call(ctx, 'hello', version=2)
    assert error.code == 'EPROTO'


def test_connect_failure_is_reported(ctx):
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()
    _, sock, error = _call(ctx, 'connect_tcp', {'family': 'inet', 'host': '127.0.0.1',
                                                'port': port, 'timeout': 2})
    assert error.code == 'ECONNECT' and not sock


def test_rate_limit(ctx):
    ctx['limiter'] = nsbroker.RateLimiter(rate=0.0001, burst=3)
    codes = [(_call(ctx, 'hello')[2] or nsbroker.RpcError('ok', '')).code for _ in range(5)]
    assert codes == ['ok', 'ok', 'ok', 'EAGAIN', 'EAGAIN']


def test_broker_refuses_to_run_as_root_or_without_peers(monkeypatch):
    monkeypatch.setattr(nsbroker.os, 'getuid', lambda: 0)
    assert nsbroker.main(['--tenant', 't0123456789ab', '--socket', '/nonexistent/x',
                          '--allow-uid', '1000']) == 2
    monkeypatch.setattr(nsbroker.os, 'getuid', lambda: 1000)
    assert nsbroker.main(['--tenant', 't0123456789ab', '--socket', '/nonexistent/x']) == 2
