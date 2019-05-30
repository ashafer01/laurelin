#!/bin/bash
set -e

PYTHON="python3"
PIP="pip3"

cd "$(git rev-parse --show-toplevel)"

echo -n "Generating latest extension requirements file..."
"$PYTHON" ./scripts/generate_extension_reqs.py
echo "done"

echo "=== Installing all extension requirements ==="
"$PIP" install --user -r extensions-requirements.txt
echo "=== Install complete ==="

"$PYTHON" ./scripts/generate_extension_properties.py

echo "Done."
