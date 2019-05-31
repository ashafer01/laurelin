#!/bin/bash

PYTHON=${1:-python3}
PIP=${2:-pip3}

if [[ "$3" != "--force" ]]; then
    if [[ "$(git rev-parse --abbrev-ref HEAD)" != "master" ]]; then
        echo -n "Not on master branch, continue? "
        read choice
        if [[ ! "$choice" =~ ^[yY] ]]; then
            echo "Bailing."
            exit
        fi
    fi
fi

cd "$(git rev-parse --show-toplevel)"

./scripts/build_pyasn1.sh "$PYTHON" "$PIP"

echo -n "Building "
cat VERSION

rm -rf dist/*
rm -rf build
rm -rf laurelin_ldap.egg-info

${PYTHON} setup.py sdist
${PYTHON} setup.py bdist_wheel --universal
