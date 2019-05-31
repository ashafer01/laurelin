#!/bin/bash

PYTHON=${1:-python3}
PIP=${2:-pip3}

echo "Building internal pyasn1"

pushd "$(git rev-parse --show-toplevel)"

rm -rf laurelin/ldap/pyasn1
pushd modules/pyasn1

rm -rf dist build *.egg-info

# do not include tests, docs, etc.
cp MANIFEST.in orig_MANIFSET.in
echo "include LICENSE.rst" > MANIFEST.in

# patch the license into __init__.py as a comment
cp pyasn1/__init__.py _tmp_init
sed -e 's/^/# /' LICENSE.rst | sed -e 's/ $//' > pyasn1/__init__.py
cat _tmp_init >> pyasn1/__init__.py

# replace imports
if [[ "$(uname -s)" == "Darwin" ]]; then
    sed_flags="-i.gdbsd -E"
else
    sed_flags="-i.gdbsd -r"
fi
find . -name '*.py' -exec sed $sed_flags -e 's/^from pyasn1(\.[^ ]+)? import (.+)$/from laurelin.ldap.pyasn1\1 import \2/g' {} \;
find . -name '*.py' -exec sed $sed_flags -e 's/^import pyasn1(\.[^ ]+)?$/import laurelin.ldap.pyasn1\1/g' {} \;
find . -name '*.gdbsd' -delete

# build patched sdist
${PYTHON} setup.py sdist
mv _tmp_init pyasn1/__init__.py

# install the sdist locally
rm -rf build
mkdir build
${PIP} install -t build dist/pyasn1-*.tar.gz

# move the installed package into laurelin.ldap
mv build/pyasn1 ../../laurelin/ldap

# clean
rm -rf build dist *.egg-info
mv orig_MANIFSET.in MANIFEST.in
git reset --hard  # un-patch the submodule
popd
popd
