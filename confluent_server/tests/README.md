# confluent_server tests

Automated tests for the confluent server. They run straight from a source
checkout: no installed package, no `/etc/confluent`, and no running service
are needed.

## Running

```bash
sudo apt-get install libarchive13t64    # or your distribution's libarchive
python3 -m pip install -r confluent_server/tests/requirements.txt
cd confluent_server
python3 -m pytest
```

The tests that build real Linux network namespaces are marked `netns`. They
need root and iproute2, and are reported as skipped otherwise. To run them:

```bash
cd confluent_server
sudo "$(command -v python3)" -m pytest -m netns -p no:cacheprovider
```

CI runs both steps in the `server-tests` job of `.github/workflows/ci.yml`.

## Multi-tenancy

`tests/e2e/test_requirements.py` has one test per requirement of
multi-tenancy (see `doc/multitenancy.md`), using two tenants through
authorization and the API as their users would; the `test_tenant_*.py`
files go deeper into each area. Its last test runs many tenants with
identical networks; the numbers can be raised for a longer soak:

```bash
sudo CONFLUENT_SOAK_TENANTS=100 CONFLUENT_SOAK_ROUNDS=200     "$(command -v python3)" -m pytest -m netns -p no:cacheprovider tests/e2e
```

## How large a configuration store can be

`tests/tools/storescale.py` measures the configuration store at a given
number of tenants and nodes. It is not a test and is not run by pytest.
Each phase is one process and prints one JSON object:

```bash
python3 tests/tools/storescale.py fsync --dir /data/scale       # what one sync costs there
python3 tests/tools/storescale.py populate --dir /data/scale --tenants 300 --nodes 1000
python3 tests/tools/storescale.py load --dir /data/scale        # a restart: time and memory
python3 tests/tools/storescale.py churn --dir /data/scale       # changes, until they are on disk
```

`--dir` should be on the disk the store would be on: nearly all of the time
of a change is waiting for that disk (compare the `fsync` phase on a few).
To hold a run to the resources of a smaller host, start each phase with
`systemd-run --scope -p MemoryMax=16G -p AllowedCPUs=0-7`. The store is
written with the `dbm` of the Python that runs the tool, which differs:
gdbm up to Python 3.12, sqlite from 3.13.

It only writes under `--dir`. On a host with a confluent of its own,
`systemd-run --wait --pipe -p ProtectSystem=strict -p ReadWritePaths=<dir>`
makes that certain.

Measured in November 2026 (store on an SSD array with 0.16 ms syncs, 8
cores): a million nodes of 500 tenants take about 10 GB of memory and
under a minute to load; a tenant changing a thousand nodes has them on
disk in well under a second.

## Fixtures

- `confluent_config` gives each test its own empty configuration store in a
  temporary directory, and resets the in-memory state of
  `confluent.config.configmanager` and `confluent.auth` before and after the
  test. (A test that does not ask for it still gets a directory of its own
  for whatever makes a `ConfigManager`, and the same reset.)
  - `confluent_config.manager(tenant=None)` returns a `ConfigManager`.
  - `confluent_config.restart()` writes everything out, drops all in-memory
    state and loads the store again, which is what a service restart does.
- `netns` is a factory for throwaway network namespaces (`create()`,
  `veth()`, `run()`, `inode()`). Every name it creates carries a random
  per-test prefix, and cleanup only removes names with that prefix.

## Known failures

Tests for known defects are marked `xfail(strict=True)`. They are reported as
`XFAIL` while the defect exists. Once it is fixed they become `XPASS`, which
fails the run, so the marker has to be removed together with the fix.
