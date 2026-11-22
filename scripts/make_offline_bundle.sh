#!/usr/bin/env bash
# Download every pinned wheel into wheelhouse/ so the toolkit can be installed
# on a machine with no internet access.
#
# Wheels are specific to the operating system, CPU and Python version, so run
# this on the machine that will use them (before it goes offline), or on one
# that matches it. pip checks each file against the hashes in the lock file
# and stops on a mismatch.
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"

"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required")'
rm -rf wheelhouse
"$PYTHON" -m pip download \
  --require-hashes \
  --only-binary=:all: \
  --dest wheelhouse \
  -r requirements-dev.lock

echo "wheelhouse/ holds $(find wheelhouse -type f | wc -l) files. Next, offline: scripts/install_offline.sh"
