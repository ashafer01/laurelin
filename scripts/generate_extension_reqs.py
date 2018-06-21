#!/usr/bin/env python3
"""
This script generates the requirements file needed to run the generate_extension_properties.py script
"""
from laurelin.ldap.extensible import Extensible
from inspect import stack
from os.path import dirname, abspath, join as path_join

BASE_DIR = path_join(dirname(abspath(stack()[0][1])), '..')

STATIC_REQUIRES = [
    'jinja2',
]


def main():
    requires = [] + STATIC_REQUIRES
    for extinfo in Extensible.AVAILABLE_EXTENSIONS.values():
        pip_package = extinfo['pip_package']
        if pip_package:
            requires.append(pip_package)
    requires.sort()
    with open(path_join(BASE_DIR, 'extensions-requirements.txt'), 'w') as f:
        for req in requires:
            f.write(req + "\n")


if __name__ == '__main__':
    main()
