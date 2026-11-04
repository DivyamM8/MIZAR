# MIZAR

Local log analysis and investigation tool for SOC analysts, incident
responders, and digital forensic investigators.

> Status: **Phase 7**. Evidence intake, parsing into a normalized event
> schema, 32 detection rules with reproducible analysis runs, a correlated
> timeline with entities and sessions, a web UI, and PDF, JSON and CSV reports.
> See the [user guide](docs/USER_GUIDE.md), the [design](docs/DESIGN.md), the
> [event schema](docs/event-schema.md) and the [rules](docs/rules.md).

## Requirements

- Python 3.13 or newer (tested on 3.14)
- Node.js 20 or newer, to build the web UI (tested on 24)
- Linux or macOS

## Install

```bash
scripts/install.sh
```

This builds the web UI and a Python wheel with the UI inside
(`scripts/build.sh`), installs it with the tested dependency versions into
`~/.local/share/mizar-app`, and links `mizar` into `~/.local/bin`. Run it again
to upgrade. With `pipx`: `scripts/build.sh && pipx install dist/mizar-*.whl`.

## Use

```bash
mizar serve          # then open http://127.0.0.1:8730
```

MIZAR listens on 127.0.0.1 only and refuses a non-loopback `MIZAR_HOST`.
`mizar serve` also runs the background worker; `mizar worker` and
`mizar migrate` run those parts alone. The [user guide](docs/USER_GUIDE.md)
covers the workflow, reports, evidence integrity, backups and troubleshooting.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MIZAR_DATA_DIR` | `~/.local/share/mizar` | Database, evidence store, exports |
| `MIZAR_PORT` | `8730` | Listen port |
| `MIZAR_LOG_LEVEL` | `INFO` | Application log level (JSON to stderr) |
| `MIZAR_MAX_FILE_BYTES` | 2 GiB | Per-file upload limit |
| `MIZAR_MAX_CASE_UNCOMPRESSED_BYTES` | 20 GiB | Per-case limit after archive extraction |
| `MIZAR_JOB_TIMEOUT_SECONDS` | 21600 | Background jobs running longer are stopped |
| `MIZAR_API_TOKEN` | random per launch | Override the API token (development only) |

All settings are listed in the [user guide](docs/USER_GUIDE.md#11-settings).

The data directory holds case evidence. Keep it on encrypted storage and never
commit it.

## Test data

```bash
python3 fixtures/generator/generate.py fixtures/scenarios   # synthetic scenarios + ground truth
```

Native EVTX samples in `fixtures/third_party/evtx` come from the `evtx`
project under Apache-2.0 (see [fixtures/THIRD_PARTY.md](fixtures/THIRD_PARTY.md)).

## Development

Set up a development environment and build the UI:

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -c requirements.lock -e ".[dev]"
cd ../frontend && npm ci && npm run build
```

Checks:

```bash
cd backend
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy

cd ../frontend
npm run typecheck && npm test && npm run build
```

Run from the checkout with `backend/.venv/bin/mizar serve`. UI development with
hot reload: run the backend with a fixed token and the Vite
origin allowed, then start Vite:

```bash
MIZAR_API_TOKEN=dev-token-at-least-32-characters-long \
MIZAR_EXTRA_ALLOWED_ORIGINS='["http://localhost:5173"]' backend/.venv/bin/mizar serve
cd frontend && MIZAR_API_TOKEN=dev-token-at-least-32-characters-long npm run dev
```

Browser tour with screenshots (uses the installed Google Chrome): seed a running
server with `python3 frontend/e2e/seed.py URL TOKEN fixtures/scenarios`, then
`MIZAR_URL=URL MIZAR_CASE=<case id> npm run screenshots` in `frontend/`.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
