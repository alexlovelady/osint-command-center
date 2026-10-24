# example-robots

Reference plugin for the OSINT Command Center plugin SDK (protocol v1).

* `plugin.json` declares everything the host needs to review it: permissions, network domains, rate limits, fixture.
* `main.py` implements `plan` (which URLs) and `parse` (turn responses into findings). It never opens a socket.
* `fixtures/robots.json` is replayed offline by `POST /api/v1/plugins/{id}/{version}/contract-test` (and in CI).

Install: `POST /api/v1/plugins/install {"path": "<this folder>"}` -> review -> `POST .../enable` with the shown hash.
Plugins are OFF until a person enables them, and the tree hash is re-verified before every run.
