# MIZAR

Local log analysis and investigation tool for SOC analysts, incident
responders, and digital forensic investigators.

> Status: **Phase 5**. Evidence intake, parsing into the normalized event
> schema, 32 detection rules with reproducible analysis runs, a correlated
> timeline with entities and sessions, and the web UI are implemented. PDF and
> JSON/CSV reports come next. See [docs/DESIGN.md](docs/DESIGN.md),
> [docs/event-schema.md](docs/event-schema.md) and [docs/rules.md](docs/rules.md).

## Requirements

- Python 3.13 or newer (tested on 3.14)
- Node.js 20 or newer to build the web UI (tested on 24)
- Linux or macOS

## Setup

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -c requirements.lock -e ".[dev]"
```

Build the web UI once (and after updates):

```bash
cd frontend
npm ci
npm run build
```

## Run

```bash
backend/.venv/bin/mizar serve      # http://127.0.0.1:8730, starts the worker too
backend/.venv/bin/mizar worker     # background worker only (normally started by serve)
backend/.venv/bin/mizar migrate    # apply database migrations only
```

Open http://127.0.0.1:8730 in a browser. MIZAR listens on loopback only. It refuses to start with a non-loopback
`MIZAR_HOST`.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MIZAR_DATA_DIR` | `~/.local/share/mizar` | Database, evidence store, exports |
| `MIZAR_PORT` | `8730` | Listen port |
| `MIZAR_LOG_LEVEL` | `INFO` | Application log level (JSON to stderr) |
| `MIZAR_MAX_FILE_BYTES` | 2 GiB | Per-file upload limit |
| `MIZAR_MAX_CASE_UNCOMPRESSED_BYTES` | 20 GiB | Per-case limit after archive extraction |
| `MIZAR_API_TOKEN` | random per launch | Override the API token (development only) |

The data directory holds case evidence. Keep it on encrypted storage and never
commit it.

## Test data

```bash
python3 fixtures/generator/generate.py fixtures/scenarios   # synthetic scenarios + ground truth
```

Native EVTX samples in `fixtures/third_party/evtx` come from the `evtx`
project under Apache-2.0 (see [fixtures/THIRD_PARTY.md](fixtures/THIRD_PARTY.md)).

## Development

```bash
cd backend
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy

cd ../frontend
npm run typecheck && npm test && npm run build
```

UI development with hot reload: run the backend with a fixed token and the Vite
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
