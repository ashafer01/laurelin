#!/bin/bash
set -e

PYTHON="python3"
PIP="pip3"

cd "$( dirname "${BASH_SOURCE[0]}" )"

echo -n "Generating latest extension requirements file..."
"$PYTHON" generate_extension_reqs.py
echo "done"

echo "=== Installing all extension requirements ==="
"$PIP" install --user -r ../extensions-requirements.txt
echo "=== Install complete ==="

"$PYTHON" generate_extension_properties.py

echo "Done."


