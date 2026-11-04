#!/usr/bin/env bash
# Build the MIZAR wheel with the web UI inside it: dist/mizar-<version>-py3-none-any.whl
# plus dist/constraints.txt (the tested dependency versions).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
python="${PYTHON:-python3}"

echo "Building the web UI"
(cd "$root/frontend" && npm ci --no-audit --no-fund && npm run build)

echo "Bundling the web UI into the package"
rm -rf "$root/backend/mizar/web" "$root/backend/build"
cp -r "$root/frontend/dist" "$root/backend/mizar/web"

echo "Building the wheel"
mkdir -p "$root/dist"
rm -f "$root"/dist/mizar-*.whl
"$python" -m pip wheel --no-deps --wheel-dir "$root/dist" "$root/backend"
cp "$root/backend/requirements.lock" "$root/dist/constraints.txt"
rm -rf "$root/backend/build" "$root/backend/mizar.egg-info"

ls -l "$root"/dist/mizar-*.whl
