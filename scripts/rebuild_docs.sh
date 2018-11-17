#!/bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )"
cd ../docs

rm -rf _build/*
rm -rf reference/*
#export SPHINX_APIDOC_OPTIONS="members,undoc-members,show-inheritance,inherited-members"
sphinx-apidoc -T -e -o reference ../laurelin \
    ../laurelin/ldap/extensible \
    ../laurelin/ldap/extensible/*.py \
    ../laurelin/ldap/attributetype.py \
    ../laurelin/ldap/attrsdict.py \
    ../laurelin/ldap/attrvaluelist.py \
    ../laurelin/ldap/constants.py \
    ../laurelin/ldap/controls.py \
    ../laurelin/ldap/filter.py \
    ../laurelin/ldap/modify.py \
    ../laurelin/ldap/net.py \
    ../laurelin/ldap/objectclass.py \
    ../laurelin/ldap/rfc4511.py \
    ../laurelin/ldap/rfc4512.py \
    ../laurelin/ldap/rfc4514.py \
    ../laurelin/ldap/rfc4518.py \
    ../laurelin/ldap/rules.py \
    ../laurelin/ldap/schema.py \
    ../laurelin/ldap/utils.py \
    ../laurelin/ldap/validation.py
make html

