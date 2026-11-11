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

"""A certificate authority for each tenant.

The services a tenant's nodes reach (in the tenant's network) present
certificates of the tenant's own authority, never the service's: a tenant
can verify nothing but its own, and one tenant's authority says nothing
to another tenant's nodes.

The authority is kept in the tenant's configuration, its private key
encrypted with a key derived from the tenant's data key, and is the same
on every member of a collective. Server certificates are short-lived and
their keys are never stored.
"""

import datetime
import ipaddress
import os
import shutil
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import confluent.config.configmanager as configmanager

CA_DAYS = 3650
SERVER_DAYS = 90


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _generate_ca(tenant):
    record = configmanager.get_tenant(tenant) or {}
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Confluent tenant'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'{0} ({1}) CA'.format(
            record.get('name', tenant), tenant)[:64]),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(days=1))
            .not_valid_after(_now() + datetime.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA384()))
    return cert, key


async def get_ca(tenant):
    """The tenant's authority as (certificate, private key), created the
    first time it is needed."""
    if tenant is None:
        raise ValueError('the default tenant uses the service certificate authority')
    cfm = configmanager.ConfigManager(tenant)
    passphrase = cfm.derive_secret(b'confluent-tenant-ca')
    stored = configmanager.get_tenant_ca(tenant)
    if stored is None:
        cert, key = _generate_ca(tenant)
        stored = await configmanager.init_tenant_ca(
            tenant,
            cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(passphrase)).decode())
    certpem, keypem = stored
    return (x509.load_pem_x509_certificate(certpem.encode()),
            serialization.load_pem_private_key(keypem.encode(), passphrase))


async def ca_pem(tenant):
    """The tenant's authority certificate (PEM), for its nodes to trust."""
    cert, _ = await get_ca(tenant)
    return cert.public_bytes(serialization.Encoding.PEM)


def _alt_names(names):
    alts = []
    for name in sorted(set(names)):
        try:
            alts.append(x509.IPAddress(ipaddress.ip_address(name.split('%')[0])))
        except ValueError:
            alts.append(x509.DNSName(name))
    return alts


def issue_server_certificate(cacert, cakey, names, days=SERVER_DAYS):
    """A server certificate for names (addresses and DNS names), signed by
    the authority; returns (certificate PEM, private key PEM)."""
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'confluent')])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(cacert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(days=1))
            .not_valid_after(_now() + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(_alt_names(names)), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                cakey.public_key()), critical=False)
            .sign(cakey, hashes.SHA384()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


async def sign_node_certificate(tenant, csrpem, nodename, names, days):
    """A certificate for one of the tenant's nodes, from its signing
    request: for nodename and names, signed by the tenant's authority.
    Returns the certificate (PEM)."""
    cacert, cakey = await get_ca(tenant)
    if isinstance(csrpem, str):
        csrpem = csrpem.encode()
    request = x509.load_pem_x509_csr(csrpem)
    if not request.is_signature_valid:
        raise ValueError('invalid certificate signing request')
    # the subject and names are the node's as configured, never the ones
    # the request asks for
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nodename[:64])])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(cacert.subject)
            .public_key(request.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(minutes=5))
            .not_valid_after(_now() + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(_alt_names(names)), critical=False)
            .add_extension(x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                cakey.public_key()), critical=False)
            .sign(cakey, hashes.SHA384()))
    return cert.public_bytes(serialization.Encoding.PEM)


async def server_context(tenant, names):
    """A TLS server context presenting a fresh certificate of the tenant's
    authority for names. The certificate's key exists only in memory (and
    for a moment in a private temporary directory, as the TLS library
    loads it from a file)."""
    cacert, cakey = await get_ca(tenant)
    certpem, keypem = issue_server_certificate(cacert, cakey, names)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    tmpdir = tempfile.mkdtemp(prefix='cftls')
    try:
        certfile = os.path.join(tmpdir, 'cert.pem')
        keyfile = os.path.join(tmpdir, 'key.pem')
        for path, data in ((certfile, certpem), (keyfile, keypem)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
        context.load_cert_chain(certfile, keyfile)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return context
