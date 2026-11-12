# Confluent

[![CI](https://github.com/xcat2/confluent/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/xcat2/confluent/actions/workflows/ci.yml?query=branch%3Amaster)
[![Nightly](https://github.com/xcat2/confluent/actions/workflows/nightly.yml/badge.svg?branch=master)](https://github.com/xcat2/confluent/actions/workflows/nightly.yml?query=branch%3Amaster)
[![Release](https://img.shields.io/github/v/release/xcat2/confluent?sort=semver)](https://github.com/xcat2/confluent/releases/latest)
[![Docs](https://img.shields.io/badge/docs-confluent--docs-blueviolet?logo=data:image/svg%2Bxml;base64,PHN2ZyBmaWxsPSJ3aGl0ZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiI%2BPHBhdGggZD0iTTAgMS43NUEuNzUuNzUgMCAwIDEgLjc1IDFoNC4yNTNjMS4yMjcgMCAyLjMxNy41OSAzIDEuNTAxQTMuNzQzIDMuNzQzIDAgMCAxIDExLjAwNiAxaDQuMjQ1YS43NS43NSAwIDAgMSAuNzUuNzV2MTAuNWEuNzUuNzUgMCAwIDEtLjc1Ljc1aC00LjUwN2EyLjI1IDIuMjUgMCAwIDAtMS41OTEuNjU5bC0uNjIyLjYyMWEuNzUuNzUgMCAwIDEtMS4wNiAwbC0uNjIyLS42MjFBMi4yNSAyLjI1IDAgMCAwIDUuMjU4IDEzSC43NWEuNzUuNzUgMCAwIDEtLjc1LS43NVptNy4yNTEgMTAuMzI0LjAwNC01LjA3My0uMDAyLTIuMjUzQTIuMjUgMi4yNSAwIDAgMCA1LjAwMyAyLjVIMS41djloMy43NTdhMy43NSAzLjc1IDAgMCAxIDEuOTk0LjU3NFpNOC43NTUgNC43NWwtLjAwNCA3LjMyMmEzLjc1MiAzLjc1MiAwIDAgMSAxLjk5Mi0uNTcySDE0LjV2LTloLTMuNDk1YTIuMjUgMi4yNSAwIDAgMC0yLjI1IDIuMjVaIi8%2BPC9zdmc%2B)](https://xcat2.github.io/confluent-docs/)
![Python 3](https://img.shields.io/badge/python-3-3776ab?logo=python&logoColor=white)
[![License](https://img.shields.io/github/license/xcat2/confluent)](LICENSE)

Confluent is a software package to handle essential bootstrap and operation of scale-out server configurations.
It supports stateful and stateless deployments for various operating systems.

Check [this page](https://xcat2.github.io/confluent-docs/) for a more detailed list of features.

Confluent is the modern successor of [xCAT](https://github.com/xcat2/xcat-core).
If you're coming from xCAT, check out [this comparison](https://xcat2.github.io/confluent-docs/miscellaneous/confluentvxcat/).

# Multi-tenancy (this fork)

[![CI of this fork](https://github.com/enuff-tech/confluent/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/enuff-tech/confluent/actions/workflows/ci.yml?query=branch%3Amaster)

This repository is a fork of [xcat2/confluent](https://github.com/xcat2/confluent). Its `master`
adds multi-tenancy to the server: one confluent service manages the infrastructure of several
tenants, each of which controls its own cluster and cannot see or reach another's. None of it has
been proposed upstream yet, and the badges at the top of this page are upstream's.

It is off by default, and an installation that does not turn it on behaves as before. The full
description, including what it does and does not protect against, is in
[doc/multitenancy.md](doc/multitenancy.md).

## What a tenant has of its own

| Area | Per tenant |
|---|---|
| Configuration | Nodes, groups, attributes, users and roles, API keys. Two tenants can use the same node names, addresses, MAC addresses, UUIDs and serial numbers. |
| Network | A Linux network namespace with the uplinks the platform gives it (a physical interface or a VLAN). The tenant sets addresses, routes and name servers itself. Identical networks in two tenants do not meet. |
| Hardware management | Power, boot device, health, sensors, inventory, event log, BMC settings, consoles and shells, through the tenant's network. |
| Discovery | SSDP, SLP and PXE/DHCP listeners in the tenant's network; everything discovered is kept per tenant. |
| Switches | MAC tables and LLDP neighbors, with the tenant's credentials. |
| Deployment | OS media uploaded and imported by the tenant, its own profiles, UEFI HTTP boot and iPXE from its own content, DHCP or static addressing per node. |
| Trust | A TLS certificate authority and an SSH certificate authority per tenant; secrets encrypted under a key per tenant. |
| Logs | Events, audit records and console logs in a directory per tenant. |
| Portability | A tenant can be exported and imported as an installation of its own, and the other way round. |

## How it is kept apart

- **Roles.** A *platform administrator* creates, disables and deletes tenants and gives them their
  network uplinks, and has no access to a tenant's nodes, discovery, network, events or users. A
  tenant's users log in as `tenant/user` and are checked against the tenant's own user list only.
- **Network.** The service never enters a tenant's namespace. Every socket it uses for a tenant is
  opened inside that namespace by a small per-tenant broker running as its own user, and work done
  for a tenant is refused rather than done from the host's network.
- **Untrusted media.** OS media a tenant uploads is identified and unpacked by worker processes
  confined with resource limits, namespaces of their own and Landlock, and is refused on a host
  that can provide neither of the last two.
- **The limit of it.** The host's root user and the confluent service user can see everything.
  A customer that needs a boundary against the operator of the host should run its own server.

## Trying it

    confluenttenant multitenancy on
    confluenttenant create acme
    confluenttenant enroll acme           # a one-time token for the tenant's first administrator
    confluent-netns setup <id>
    confluent-netns attach <id> eth1 --vlan 100
    systemctl enable --now confluent-netns@<id> confluent-netcfg@<id> confluent-nsbroker@<id>

`confluent_selfcheck` and `confluent-netns sandbox` report what the host provides for confining
tenant media. An existing installation is first brought to the current store layout with
`confluentdbutil migrate-tenancy`.

## Not available to tenants yet

Firmware updates, virtual media, remote configuration (ansible, file synchronization), identity
images, TFTP boot, editing profiles through the API, reading their own event and audit logs through
the API, and the web interface.

## Other changes in this fork

- A test suite for the server (`confluent_server/tests`, described in its
  [README](confluent_server/tests/README.md)), run on Python 3.9, 3.12 and 3.14 in CI: about 450
  tests without privileges and 70 more that build real network namespaces as root.
- Fixes to the configuration store found on the way: a restore no longer removes files the
  background writer is in, a dump waits for pending writes, and with the sqlite backend of `dbm`
  (Python 3.13 and later) a file is written in one transaction instead of one per key.
- A tool that measures the store at scale (`confluent_server/tests/tools/storescale.py`). On an
  SSD array, a million nodes of 500 tenants took about 10 GB of memory and under a minute to load.

## State

Everything above is covered by the test suite, including two tenants with identical networks side
by side. It has not yet been run as an installed service deploying real machines, in a collective,
or from the built packages; treat it as work in progress until it has.

# Documentation

Confluent documentation is hosted on: https://xcat2.github.io/confluent-docs/

# Download

Get the latest version from: https://xcat2.github.io/confluent-docs/downloads/

Check release notes on: https://xcat2.github.io/confluent-docs/release_notes/

# Open Source License

Confluent is made available under the Apache 2.0 license: https://opensource.org/license/apache-2-0

# Developers

Want to help? Submit a [Pull Request](https://github.com/xcat2/confluent/pulls).

## Versioning and releases

The top-level `VERSION` file names the release the current branch is working toward. Build scripts
call `./mkversion`, which turns it into the version stamped on packages: the tag itself on a release
tag (`4.0.1`), otherwise a development version (`4.0.1~dev5+gdeadbee`). Packages sort it before the
release it leads up to. Only `setup.py` gets the PEP 440 spelling, `4.0.1.dev5+gdeadbee`.

`mkversion` also derives a version from the newest tag reachable from HEAD and uses whichever is
higher, so forgetting to bump `VERSION` after tagging the current branch cannot walk the version
backwards. Staying ahead of tags on *other* branches is what `VERSION` itself is for: patch releases
are tagged on release branches, which master never sees.

Cutting a new series:

1. Land the release commit on master and tag `X.Y.0` there.
2. Create branch `X.Y` from that tag; it inherits `VERSION=X.Y.0`.
3. Only then bump `VERSION` on master. Doing it before step 2 leaves the release branch on the
   wrong series.

Patch releases land on branch `X.Y` and are tagged `X.Y.Z` there; no `VERSION` edit is needed.

## Nightly builds

`.github/workflows/nightly.yml` builds the rpms (EL9, EL10, SUSE 16) and debs (Ubuntu 24.04, 26.04)
for x86_64 and aarch64 every night that something changed, installs each set on a clean container,
and publishes them as the `nightly` pre-release. Every bundle there holds all packages for one
target and an `INSTALL.txt`. Pull requests that touch the packaging run the same build and tests
without publishing. Genesis is not built there yet.
