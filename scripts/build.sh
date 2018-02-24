#!/bin/bash

cd "$( dirname "${BASH_SOURCE[0]}" )"
cd ..

echo -n "Building "
cat VERSION

rm -rf dist/*
python3.6 setup.py sdist
python3.6 setup.py bdist_wheel --universal
