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

## Fixtures

- `confluent_config` gives each test its own empty configuration store in a
  temporary directory, and resets the in-memory state of
  `confluent.config.configmanager` and `confluent.auth` before and after the
  test.
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
