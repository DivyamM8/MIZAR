#!/usr/bin/env bash
# Install MIZAR for the current user: builds the wheel if needed, installs it with the
# tested dependency versions into its own virtual environment, and links `mizar` into
# ~/.local/bin. Re-run to upgrade. Case data (MIZAR_DATA_DIR) is never touched.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
python="${PYTHON:-python3}"
app_dir="${MIZAR_APP_DIR:-$HOME/.local/share/mizar-app}"
bin_dir="${MIZAR_BIN_DIR:-$HOME/.local/bin}"

"$python" - <<'PY'
import sys
if sys.version_info < (3, 13):
    sys.exit(f"MIZAR needs Python 3.13 or newer; {sys.version.split()[0]} found. Set PYTHON=/path/to/python3.13.")
PY

if ! ls "$root"/dist/mizar-*.whl >/dev/null 2>&1; then
    "$root/scripts/build.sh"
fi
wheel="$(ls -t "$root"/dist/mizar-*.whl | head -1)"

echo "Installing $(basename "$wheel") into $app_dir"
"$python" -m venv "$app_dir"
"$app_dir/bin/python" -m pip install --quiet --upgrade pip
"$app_dir/bin/python" -m pip install --quiet -c "$root/dist/constraints.txt" "$wheel"
# Same version number but a newer build (upgrade from a source checkout): replace it.
"$app_dir/bin/python" -m pip install --quiet --force-reinstall --no-deps "$wheel"

mkdir -p "$bin_dir"
ln -sf "$app_dir/bin/mizar" "$bin_dir/mizar"
echo
"$bin_dir/mizar" --version
echo "Installed. Start it with:  mizar serve   (then open http://127.0.0.1:8730)"
case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) echo "Note: $bin_dir is not on your PATH; add it, or run $bin_dir/mizar." ;;
esac
