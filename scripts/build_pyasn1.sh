#!/bin/bash

echo "Building internal pyasn1"

pushd "$( dirname "${BASH_SOURCE[0]}" )"
pushd ..

rm -rf laurelin/ldap/pyasn1
pushd pyasn1

# make a minimal source package and ensure license is included
rm -rf dist build *.egg-info
cp MANIFEST.in orig_MANIFSET.in
echo "include LICENSE.rst" > MANIFEST.in
cp pyasn1/__init__.py _tmp_init
sed -e 's/^/# /' LICENSE.rst | sed -e 's/ $//' > pyasn1/__init__.py
cat _tmp_init >> pyasn1/__init__.py
python3 setup.py sdist
mv _tmp_init pyasn1/__init__.py

# install the sdist locally
rm -rf build
mkdir build
pip3 install -t build dist/pyasn1-*.tar.gz

# move the installed package into laurelin.ldap
mv build/pyasn1 ../laurelin/ldap

# clean
rm -rf build dist *.egg-info
mv orig_MANIFSET.in MANIFEST.in
popd
popd
popd
