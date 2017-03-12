from __future__ import absolute_import
from setuptools import setup, find_packages

setup(
    name='laurelin-ldap',
    version='0.1',
    author='Alex Shafer',
    author_email='ashafer01@gmail.com',
    namespace_packages=['laurelin', 'laurelin.extensions'],
    packages=find_packages(),
    install_requires=[
        'pyasn1',
        'pure-sasl',
        'six',
    ],
)
