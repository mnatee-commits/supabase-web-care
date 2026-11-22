#!/usr/bin/env bash
# Create .venv and install the pinned packages from wheelhouse/ only.
# Makes no network connection: pip is told there is no package index.
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"

if [ ! -d wheelhouse ]; then
  echo "wheelhouse/ not found. Run scripts/make_offline_bundle.sh while online first." >&2
  exit 1
fi

"$PYTHON" -m venv .venv
.venv/bin/python -m pip install \
  --no-index \
  --find-links wheelhouse \
  --require-hashes \
  -r requirements-dev.lock

.venv/bin/pgrls --version
echo "Installed. Activate with: . .venv/bin/activate"
