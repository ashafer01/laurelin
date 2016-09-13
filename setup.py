from setuptools import setup, find_packages

setup(
    name='laurelin-ldap',
    version='0.1',
    namespace_packages=['laurelin', 'laurelin.extensions']
    packages=find_packages(),
    install_requires=[
        'pyasn1',
        'pure-sasl',
    ],
)
