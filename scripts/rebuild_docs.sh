#!/bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )"
cd ../docs

rm -rf _build/*
rm -rf reference/*
sphinx-apidoc -T -o reference ../laurelin \
    ../laurelin/ldap/controls.py \
    ../laurelin/ldap/rfc4511.py \
    ../laurelin/extensions \
    ../laurelin/extensions/*.py \
    ../laurelin/ldap/protoutils.py \
    ../laurelin/ldap/rfc4512.py \
    ../laurelin/ldap/rfc4514.py \
    ../laurelin/ldap/rfc4518.py \
    ../laurelin/ldap/utils.py
make html

