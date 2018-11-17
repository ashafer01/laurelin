#!/bin/bash

if [[ "$(git rev-parse --abbrev-ref HEAD)" != "master" ]]; then
    echo -n "Not on master branch, continue? "
    read choice
    if [[ ! "$choice" =~ ^[yY] ]]; then
        echo "Bailing."
        exit
    fi
fi

cd "$( dirname "${BASH_SOURCE[0]}" )"
cd ..

echo -n "Building "
cat VERSION

rm -rf dist/*
rm -rf build
rm -rf laurelin_ldap.egg-info

python3.6 setup.py sdist
python3.6 setup.py bdist_wheel --universal
