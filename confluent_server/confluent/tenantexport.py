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

"""Moving one tenant's configuration between installations.

A tenant of a shared installation can be exported and imported as the
whole (default) configuration of an installation of its own, and the
configuration of a standalone installation can be imported into an empty
tenant of a shared one. The package ("confluent-tenant-export" version 1)
is a directory:

    manifest.json   format, source, and the SHA-256 of every other file
    store/main.json nodes, groups, users and user groups (as a dump has them)
    store/globals.json   the tenant's own settings (discovery)
    netcfg.yaml     the network the tenant managed in its namespace
    keys.json       the key the package's secrets are encrypted with,
                    wrapped by a key derived from a passphrase (scrypt)

Secrets never leave in the clear, and neither does any key of the source
installation: each secret is encrypted again under a key made for this
package alone, and on import under the destination's own key. A redacted
package carries no secrets and no key (it can be read, not imported).

Import validates the whole package (checksums, passphrase, every secret)
before anything is changed, only goes into an empty destination, and
records the package it imported: importing the same package again does
nothing, a different one is refused.
"""

import base64
import copy
import datetime
import hashlib
import json
import os

import yaml

import confluent
import confluent.config.configmanager as configmanager
import confluent.exceptions as exc

FORMAT = 'confluent-tenant-export'
VERSION = 1
SCRYPT_N = 2 ** 17
# What a package to import may ask for and bring (it comes from elsewhere):
# a work factor between these, files of at most this size.
SCRYPT_MIN_N, SCRYPT_MAX_N = 2 ** 14, 2 ** 18
MAX_FILES = 64
MAX_FILE_SIZE = 256 * 2 ** 20
MAX_SALT = 64


def _limited_read(path, name):
    with open(path, 'rb') as f:
        data = f.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        raise PackageError('The package is not acceptable: {0} is too large'.format(name))
    return data
STORE_GLOBALS = ('discovery.autosense',)
IMPORTED = 'import.manifest_sha256'
SUBSCRIPTIONS = '/etc/confluent/discovery_subscriptions.json'


class PackageError(exc.InvalidArgumentException):
    """The package cannot be used (damaged, wrong passphrase, redacted)."""


class DestinationNotEmpty(exc.InvalidArgumentException):
    """Import only goes into an empty tenant (or installation)."""


def _b64(data):
    return base64.b64encode(data).decode()


def _derive(passphrase, salt, n):
    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf8')
    return hashlib.scrypt(passphrase, salt=salt, n=n, r=8, p=1,
                          maxmem=256 * n * 8 + 2 ** 20, dklen=32)


def _encode(cryptvalue):
    return '!'.join(_b64(part) for part in cryptvalue)


def _decode(text):
    return tuple(base64.b64decode(part) for part in text.split('!'))


def _recrypt(store, decrypt, encrypt):
    """Encrypt every secret of a dumped store again; returns how many."""
    count = 0
    for area in store.values():
        for element in area.values():
            for value in element.values():
                if isinstance(value, dict) and isinstance(value.get('cryptvalue'), str):
                    value['cryptvalue'] = _encode(encrypt(decrypt(_decode(value['cryptvalue']))))
                    count += 1
    return count


def _source_key(cfm):
    # None: the service's master key (the default tenant, and tenants
    # from before they had a key of their own)
    return cfm._cryptkey()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def build(cfm, passphrase=None, redact=False):
    """The package of one configuration (a tenant's, or the default one)
    as {relative file name: bytes}."""
    if not redact and not passphrase:
        raise PackageError('A passphrase is needed to protect the secrets of '
                           'the package (or export it redacted)')
    store = json.loads(cfm._real_dump_to_json(redact=True if redact else None))
    files = {}
    if not redact:
        packagekey = os.urandom(32)
        sourcekey = _source_key(cfm)
        _recrypt(store,
                 lambda value: configmanager.decrypt_value(value, key=sourcekey)
                 if sourcekey is not None else configmanager.decrypt_value(value),
                 lambda value: configmanager.crypt_value(value, key=packagekey))
        salt = os.urandom(16)
        wrapped = configmanager.crypt_value(
            packagekey, key=_derive(passphrase, salt, SCRYPT_N))
        files['keys.json'] = json.dumps({
            'kdf': 'scrypt', 'n': SCRYPT_N, 'r': 8, 'p': 1, 'salt': _b64(salt),
            'packagekey': _encode(wrapped)}, indent=1, sort_keys=True).encode()
    files['store/main.json'] = json.dumps(store, indent=1, sort_keys=True).encode()
    settings = {}
    for name in STORE_GLOBALS:
        value = cfm.get_scoped_global(name)
        if value is not None:
            settings[name] = value
    if cfm.tenant is None and os.path.exists(SUBSCRIPTIONS):
        # of a standalone installation: reported on import, as discovery
        # subscriptions belong to the installation, not to a tenant
        try:
            with open(SUBSCRIPTIONS) as subs:
                settings['discovery.subscriptions'] = json.load(subs)
        except (OSError, ValueError):
            pass
    files['store/globals.json'] = json.dumps(settings, indent=1, sort_keys=True).encode()
    netcfg = cfm.get_scoped_global('netcfg') if cfm.tenant is not None else None
    files['netcfg.yaml'] = yaml.safe_dump(netcfg or {}, default_flow_style=False).encode()
    record = configmanager.get_tenant(cfm.tenant) if cfm.tenant is not None else None
    manifest = {
        'format': FORMAT, 'version': VERSION,
        'confluent_version': getattr(confluent, '__version__', 'unknown'),
        'source': {'kind': 'default' if cfm.tenant is None else 'tenant',
                   'id': cfm.tenant, 'name': record['name'] if record else None},
        'created': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'redacted': bool(redact),
        'files': dict((name, _sha(data)) for name, data in files.items()),
    }
    files['manifest.json'] = json.dumps(manifest, indent=1, sort_keys=True).encode()
    return files


def write(files, directory):
    """Write a package to a directory nobody else can read."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    for name, data in files.items():
        path = os.path.join(directory, name)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(data)


def read(directory):
    """Read a package from a directory, checking it against its manifest."""
    try:
        manifestdata = _limited_read(os.path.join(directory, 'manifest.json'), 'manifest.json')
        manifest = json.loads(manifestdata)
    except (OSError, ValueError) as e:
        raise PackageError('Not a tenant export package: {0}'.format(e))
    if not isinstance(manifest, dict):
        raise PackageError('Not a tenant export package')
    if manifest.get('format') != FORMAT or manifest.get('version') != VERSION:
        raise PackageError('Unsupported package format or version')
    if not isinstance(manifest.get('files', {}), dict) or len(manifest.get('files', {})) > MAX_FILES:
        raise PackageError('The package is not acceptable: too many files')
    files = {'manifest.json': manifestdata}
    for name, digest in sorted(manifest.get('files', {}).items()):
        path = os.path.realpath(os.path.join(directory, name))
        if not path.startswith(os.path.join(os.path.realpath(directory), '')):
            raise PackageError('Invalid file name in the package: {0}'.format(name))
        try:
            data = _limited_read(path, name)
        except OSError:
            raise PackageError('The package is incomplete: {0} is missing'.format(name))
        if _sha(data) != digest:
            raise PackageError('The package is damaged: {0} does not match '
                               'its checksum'.format(name))
        files[name] = data
    return files


def _empty(cfm):
    groups = [g for g in cfm._cfgstore.get('nodegroups', {}) if g != 'everything']
    return not cfm._cfgstore.get('nodes') and not groups


def _unlock(files, passphrase):
    if 'keys.json' not in files:
        raise PackageError('A redacted package carries no secrets and cannot be imported')
    keys = json.loads(files['keys.json'])
    if keys.get('kdf') != 'scrypt' or not passphrase:
        raise PackageError('A passphrase is needed to import this package')
    try:
        n = int(keys['n'])
        if not SCRYPT_MIN_N <= n <= SCRYPT_MAX_N or n & (n - 1):
            raise ValueError(n)
        if keys.get('r', 8) != 8 or keys.get('p', 1) != 1:
            raise ValueError('parameters')
        salt = base64.b64decode(keys['salt'])
        if not 8 <= len(salt) <= MAX_SALT:
            raise ValueError('salt')
        derived = _derive(passphrase, salt, n)
        return configmanager.decrypt_value(_decode(keys['packagekey']), key=derived)
    except Exception:
        raise PackageError('Wrong passphrase (or damaged package key)')


async def import_package(cfm, files, passphrase, users=True, keep_apikeys=False):
    """Import a package into cfm's (empty) configuration.

    Returns a report: what was imported, and what the package held that
    is not imported (to be reviewed by whoever runs the import).
    """
    manifestsha = _sha(files['manifest.json'])
    already = cfm.get_scoped_global(IMPORTED)
    if already == manifestsha:
        return {'status': 'already imported', 'manifest_sha256': manifestsha}
    if already or not _empty(cfm):
        raise DestinationNotEmpty(
            'Import needs an empty destination: this one has nodes or groups'
            + (' (imported from another package)' if already else ''))
    # Everything that can fail is done before anything is changed.
    packagekey = _unlock(files, passphrase)
    try:
        store = json.loads(files['store/main.json'])
        settings = json.loads(files.get('store/globals.json', b'{}'))
        netcfg = yaml.safe_load(files.get('netcfg.yaml', b'{}')) or {}
    except (KeyError, ValueError) as e:
        raise PackageError('The package cannot be read: {0}'.format(e))
    destkey = cfm._cryptkey()
    try:
        secrets = _recrypt(
            store, lambda value: configmanager.decrypt_value(value, key=packagekey),
            lambda value: configmanager.crypt_value(value, key=destkey)
            if destkey is not None else configmanager.crypt_value(value))
    except Exception:
        raise PackageError('A secret of the package cannot be decrypted')
    report = {'status': 'imported', 'manifest_sha256': manifestsha,
              'nodes': len(store.get('nodes', {})),
              'groups': len(store.get('nodegroups', {})), 'secrets': secrets,
              'users': [], 'users_kept': [], 'not_imported': {}}
    # The destination's own users (whoever runs the import among them)
    # stay as they are; the package's are added beside them.
    existing = json.loads(cfm._real_dump_to_json())
    merged = {'users': existing.get('users', {}), 'usergroups': existing.get('usergroups', {})}
    if users:
        for area in ('users', 'usergroups'):
            for name, record in store.get(area, {}).items():
                if name in merged[area]:
                    if area == 'users':
                        report['users_kept'].append(name)
                    continue
                record = copy.deepcopy(record)
                # user ids are the destination installation's to assign
                record.pop('id', None)
                if not keep_apikeys:
                    record.pop('apikeys', None)
                    record.pop('secret.apikey', None)
                merged[area][name] = record
                if area == 'users':
                    report['users'].append(name)
    else:
        report['not_imported']['users'] = sorted(store.get('users', {}))
    store['users'], store['usergroups'] = merged['users'], merged['usergroups']
    await cfm._load_from_json(json.dumps(store))
    for name in STORE_GLOBALS:
        if name in settings:
            cfm.set_scoped_global(name, settings[name])
    if settings.get('discovery.subscriptions'):
        report['not_imported']['discovery.subscriptions'] = sorted(
            settings['discovery.subscriptions'])
    if netcfg:
        # addresses of another installation's namespace: for the
        # destination's administrator to apply where they fit
        report['not_imported']['netcfg'] = netcfg
    cfm.set_scoped_global(IMPORTED, manifestsha)
    return report


def nmstate(netcfg):
    """A tenant's namespace network configuration as an nmstate document,
    for the host of a standalone installation (which manages its own
    network: this is a starting point, not applied by confluent)."""
    state = {'interfaces': [], 'routes': {'config': []}, 'dns-resolver': {'config': {}}}
    for name, wanted in sorted((netcfg or {}).get('interfaces', {}).items()):
        entry = {'name': name, 'state': 'up' if wanted.get('up', True) else 'down'}
        if wanted.get('mtu'):
            entry['mtu'] = wanted['mtu']
        for version, family in ((4, 'ipv4'), (6, 'ipv6')):
            addresses = [{'ip': a.split('/')[0], 'prefix-length': int(a.split('/')[1])}
                         for a in wanted.get('addresses', []) if (':' in a) == (version == 6)]
            if addresses:
                entry[family] = {'enabled': True, 'dhcp': False, 'address': addresses}
        state['interfaces'].append(entry)
    for route in (netcfg or {}).get('routes', []):
        destination = route['destination']
        if destination == 'default':
            destination = '::/0' if ':' in route.get('gateway', '') else '0.0.0.0/0'
        entry = {'destination': destination}
        if route.get('gateway'):
            entry['next-hop-address'] = route['gateway']
        if route.get('ifname'):
            entry['next-hop-interface'] = route['ifname']
        if route.get('metric') is not None:
            entry['metric'] = route['metric']
        state['routes']['config'].append(entry)
    dns = (netcfg or {}).get('dns', {})
    if dns.get('nameservers'):
        state['dns-resolver']['config']['server'] = list(dns['nameservers'])
    if dns.get('search'):
        state['dns-resolver']['config']['search'] = list(dns['search'])
    return yaml.safe_dump(state, default_flow_style=False)
