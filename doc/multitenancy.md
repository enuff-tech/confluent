# Multi-tenancy

One confluent service can manage the infrastructure of several tenants.
Each tenant has its own nodes, groups, attributes, users, discovery,
network, credentials, logs and deployment content, and controls its own
cluster. Tenants can use the same node names, addresses, networks, MAC
addresses, UUIDs and serial numbers without affecting each other.

Multi-tenancy is off by default. An installation that does not turn it on
behaves exactly as before; everything below describes what is added when
it is on. The installation's own configuration remains as the *default
tenant*.

There is no leasing or sharing: a node, address or discovery record
belongs to exactly one tenant, and nothing can be assigned from one tenant
to another.

## Security boundaries

**What tenant isolation protects against.** On a shared confluent server,
each tenant's infrastructure data, discovery, credentials and network
access are isolated from other tenants and from confluent's
application-level *platform administrators*. Platform administrators
manage the tenant lifecycle and the host plumbing; through confluent's API
and command line they cannot read, change or act on a tenant's
infrastructure. Tenant network traffic is confined by Linux network
namespaces. Confluent obtains tenant sockets only through a per-tenant
broker, and refuses (fails closed) rather than use the host's network for
a tenant's work.

**What it does not protect against.** The host's root user, and anyone who
can run code as the `confluent` service user, keep full visibility and
control over all tenants on that host: memory, the configuration store and
its keys, logs, and the network namespaces. Per-tenant data keys make
exports separable; they do not protect against host root. The same holds
for the shared confluent process: a vulnerability that gives code
execution in it affects all tenants. The service's stack trace log, a file
on the host for its operator, can name a tenant's nodes.

**Where the stronger boundary is.** A customer that needs a boundary that
excludes the service operator's host root should run its own confluent
server.

## Roles

| Who | Logs in as | Can |
|---|---|---|
| Platform administrator (role `PlatformAdmin`, default tenant only) | `user` | Create, enable, disable and delete tenants, issue enrollment tokens, turn multi-tenancy on. No access to any tenant's nodes, discovery, networking, events or users. |
| Tenant administrator (role `Administrator` in a tenant) | `tenant/user` | Everything within the tenant: nodes, groups, attributes, users, discovery, its network, consoles. |
| Other tenant roles (`Operator`, `Monitor`, ...) | `tenant/user` | The same as in a single-tenant installation, within the tenant. |

A tenant's users are checked against the tenant's own user list only:
host accounts (PAM) and host groups never grant access to a tenant.

## Administration

Turn multi-tenancy on (once; in a collective, on any member):

    confluenttenant multitenancy on

An existing installation is brought to the current store layout first,
with the service stopped; this can be repeated safely:

    confluentdbutil migrate-tenancy

Create a tenant and hand its first administrator an enrollment token:

    confluenttenant create acme
    confluenttenant enroll acme

The token is shown once, expires, and can be redeemed once: whoever holds
it chooses the name and password of the tenant's first administrator
(`POST /tenantenrollment`). From then on the platform administrator has no
part in the tenant's users.

    confluenttenant list
    confluenttenant show acme
    confluenttenant disable acme
    confluenttenant enable acme
    confluenttenant delete acme

A tenant has an id (`t` and twelve hexadecimal digits) that never changes
and names everything kept for it. A disabled tenant keeps its data, but
its users and API keys are refused, its discovery, consoles and node
services stop, and every socket in its network is closed. Only a disabled
tenant can be deleted. **Deleting a tenant removes its configuration, its
logs and its deployment content, and cannot be undone**; export it first
if it may be needed (see below).

Tenant users work with the usual commands and API, logging in as
`tenant/user`. API keys (version 2) are bound to the tenant of the user
that created them and carry scopes, an expiry and can be revoked.

## What a tenant can use

| Area | Within a tenant |
|---|---|
| Nodes, groups, attributes, noderanges, users, user groups | Yes |
| Power, boot device, identify, health, sensors, inventory, event log, BMC settings | Yes, with the hardware management plugins that work through the tenant's network: `ipmi`, `redfish`, `affluent`, `cnos`, `cooltera`, `deltapdu`, `eatonpdu`, `enlogic`, `enos`, `geist`, `nxos`, `proxmox`, `raritan`, `srlinux`, `vcenter` |
| Discovery (`/discovery`) | Yes: detection by SSDP, SLP and PXE/DHCP in the tenant's networks, manual registration, rescan, autosense. Subscriptions to remote discovery agents are the installation's. |
| Switches (`/networking/macs`, `/networking/neighbors`) | Yes: MAC tables and LLDP by SNMP or the switch APIs, with the tenant's credentials |
| Its network (`/networking/interfaces`, `/networking/routes`, `/networking/dns`) | Yes, tenant administrators |
| Consoles and shell sessions | Yes: `ipmi`, `redfish`, `openbmc`, `tsmsol` consoles, ssh shells |
| Alert decoding (`/events/decode`) | Yes, for its own nodes |
| Network boot and deployment | UEFI HTTP boot and iPXE from the tenant's own content; see Deployment |
| OS images and profiles (`/deployment`) | Yes, tenant administrators: upload media, import it, list, rebuild boot files, rebase |
| Firmware updates, media, licenses, certificate signing for BMCs, power reseat | Not yet |
| Remote configuration (ansible, file synchronization), SSH certificates, identity images | Not yet |
| The web interface | Default tenant only |

Anything not available answers with an error; it never falls back to the
host's network or the default tenant's data.

## Network isolation

Each tenant's network is a Linux network namespace, `cf-<id>`. The
confluent service itself stays in the host's namespace and never enters
another: every socket it uses for a tenant is opened for it inside the
tenant's namespace by that tenant's *broker* and handed over.

Per tenant there are three systemd units, all owned by the platform:

| Unit | Runs as | Does |
|---|---|---|
| `confluent-netns@<id>` | root, once | Creates the namespace and attaches the uplinks declared in `/etc/confluent/netns/<id>.yaml` |
| `confluent-nsbroker@<id>` | `cfnsb-<id>`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE` only | Opens sockets in the namespace for the service: a closed set of operations, fixed lists of ports and ethertypes, a rate limit. It cannot change the network. |
| `confluent-netcfg@<id>` | `cfnet-<id>`, `CAP_NET_ADMIN` only | Sets addresses, routes, link state, MTU and name servers in the namespace. It hands out nothing, and cannot create, rename, delete or move interfaces. |

The platform decides which interfaces a tenant has:

    confluent-netns setup <id>
    confluent-netns attach <id> eth1 --vlan 100
    confluent-netns status <id>
    systemctl enable --now confluent-netns@<id> confluent-netcfg@<id> confluent-nsbroker@<id>

An uplink can be a physical interface or a VLAN on one. What happens on
the uplinks is the tenant administrator's:

    PUT /networking/interfaces/eth1.100   {"addresses": ["10.0.0.1/24"], "mtu": 9000}
    PUT /networking/routes                {"routes": [{"destination": "default", "gateway": "10.0.0.254"}]}
    PUT /networking/dns                   {"nameservers": ["10.0.0.53"], "search": ["example.com"]}

An interface a tenant configures gets exactly the addresses it lists. The
configuration is kept in the tenant's store and applied again after a
reboot or when an interface comes back. It is the configuration of one
collective member: each member has a namespace of its own for a tenant.

Because the namespaces are separate, two tenants can use identical
networks, addresses and routes. A guard in the service refuses, for work
done for a tenant, any connection, bind or send on a socket that did not
come from that tenant's broker, any name lookup other than through the
broker, and any process start. What cannot be done through the broker is
refused for tenants rather than done from the host.

## Discovery

Each active tenant with autosense enabled has its own listeners in its
namespace (SSDP, SLP, DHCP and proxyDHCP). A packet belongs to the tenant
whose socket it arrived on, never to anything it says. Everything
discovery keeps (detected hardware, pending and unknown records, the
UUID, serial, fingerprint and MAC maps, switch MAC tables and LLDP
neighbors) is kept per tenant, and hardware is identified against the
tenant's own nodes only. The same MAC, UUID, serial or address in two
tenants is two separate records.

## Deployment

A tenant's nodes are served inside the tenant's network:

- HTTPS on 443 with a certificate of the **tenant's own certificate
  authority**: the node self-service API (`/confluent-api/self/...`) and
  the tenant's content (`/confluent-public/...`).
- HTTP on 80 for the content only, for firmware and boot loaders.
- The credential service on 13001.

A node never names its tenant: it is the one whose listener it reached.

The tenant's content lives under `/var/lib/confluent/tenants/<id>/`:
`public` and `private`, laid out like `/var/lib/confluent/public` and
`private`, `distributions` for imported media, and `media` for media
waiting to be imported. What is served for the tenant is its public tree;
a link in it may lead into its own imported media or into the product's
packaged content (`/opt/confluent`), and nowhere else. The site content
(`public/site`: the tenant's certificate authority, the identity of the
service as its nodes know it, and both packed for the boot images) is
made by the service. The certificate authority is also at
`/confluent-public/site/tls/ca.pem`.

A tenant administrator uploads OS installation media, imports it, and
manages the profiles made from it through `/deployment`:

    PUT  /deployment/media/<name>      (the media itself as the body)
    GET  /deployment/media/
    DELETE /deployment/media/<name>
    POST /deployment/importing/        {"filename": "Rocky-9.4-x86_64-dvd.iso"}
    GET  /deployment/importing/<name>
    GET  /deployment/profiles/
    PUT  /deployment/profiles/<name>   {"updateboot": 1}
    PUT  /deployment/profiles/<name>   {"rebase": 1}

For example:

    curl -u acme/admin -T Rocky-9.4-x86_64-dvd.iso \
        https://confluent.example.com/confluent-api/deployment/media/Rocky-9.4-x86_64-dvd.iso

An upload states its size (`Content-Length`) and is refused before any of
it is read when the tenant may not keep it. Media stays in the tenant's
`media` directory, also after it was imported, until it is deleted. What
a tenant may keep there is set in `/etc/confluent/service.cfg`:

    [tenants]
    media_max_gb = 16        # largest single media file
    media_quota_gb = 64      # total a tenant may keep waiting
    media_reserve_gb = 20    # space the volume must keep free

`filename` names a file in the tenant's `media` directory, never a path
of the host. The tools this takes (unpacking media, building boot images)
run as the service itself, on the tenant's trees only. A tenant's media
is not trusted: it is identified and unpacked by worker processes limited
in time, memory and file size, nothing it contains is written outside the
directory it is unpacked into, and the names it gives itself have to be
plain ones. Those workers still run as the service user (see Security
boundaries). Ready-made profile
archives are not imported within a tenant, and rebasing only copies from
the product's packaged profile content. Profiles are not editable through
the API: customizing one (kernel arguments, scripts) is done in the
tenant's tree on the host.

Nodes with a pending deployment are offered UEFI HTTP boot, or iPXE, from
the tenant's content. Firmware PXE needs TFTP, which is not served in
tenant networks. Addressing is the tenant's choice per node, as in a
single-tenant installation (`net.*ipv4_method`): a `static` node is given
its address in the offer (and, with `net.lease_time`, by plain DHCP), a
`dhcp` node is offered boot without an address and left to the tenant's
own DHCP service, `firmwarenone` gets no answer.

## Logs

Events, audit records and console logs of a tenant are written under
`<log directory>/tenants/<id>/`. The service's own log holds what its
operator needs (a tenant's network not being available, for example) and
no tenant data.

## Moving a tenant

A tenant can be exported and imported as the whole configuration of an
installation of its own, and the other way round:

    confluentdbutil -i export-tenant acme /root/acme-export
    confluentdbutil -i import-tenant default /root/acme-export     # on the new server
    confluentdbutil -i import-tenant acme /root/standalone-export  # into an empty tenant

`default` names the installation's own configuration. The package holds
the nodes, groups, attributes, users and discovery settings. Secrets are
encrypted under a key made for the package, protected by the passphrase;
no key of the source installation is in it. `-r` writes a redacted package
without secrets, for reading only.

Import needs the service stopped and an empty destination; it checks the
whole package before changing anything, keeps the users the destination
already has, and does nothing when the same package is imported again.
API keys are left behind unless `--keep-apikeys` is given. Discovery
subscriptions and the network a tenant managed in its namespace are not
imported: they are reported, the network also as an nmstate document.

## Collectives

Tenants, their state, users, keys and certificate authority are replicated
like the rest of the configuration. A tenant's network (namespace, uplinks
and the configuration the tenant gives it) and its deployment content are
per member. All members must run a version with multi-tenancy before it is
turned on.

## Limitations

- The host's root user and the confluent service user can see everything
  (see Security boundaries).
- A tenant's profiles are customized in its tree on the host: that
  cannot be done through the API yet. Firmware updates, virtual media,
  remote configuration, SSH
  certificates and identity images are not available to tenants.
- Each tenant keeps its own copy of the OS images it imports.
- TFTP boot is not available to tenants.
- A tenant's server certificate is issued when its listeners start
  (valid 90 days) and is not renewed without a restart of the service or
  of the tenant.
- Tenants cannot read their own event or audit logs through the API.
- A tenant's switches are queried in the service's main process.
- The terminal buffer service that backs consoles is shared by all
  tenants (one process on the host, separate buffers).
- Export and import are done on the host with `confluentdbutil`, not
  through the API.
- The web interface works for the default tenant only.
