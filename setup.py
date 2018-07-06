from __future__ import absolute_import
from setuptools import setup, find_packages

with open('VERSION') as f:
    version = f.read().strip()

with open('README.rst') as f:
    long_description = f.read()

with open('requirements.txt') as f:
    install_requires = f.read().split()

setup(
    name='laurelin-ldap',
    version=version,
    description='A pure-Python ORM-esque LDAP client.',
    long_description=long_description,
    author='Alex Shafer',
    author_email='ashafer01@gmail.com',
    url='https://github.com/ashafer01/laurelin',
    license='LGPLv3+',
    keywords='ldap',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Natural Language :: English',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Programming Language :: Python :: Implementation :: CPython',
        'Operating System :: OS Independent',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
    ],
    namespace_packages=['laurelin', 'laurelin.extensions'],
    packages=find_packages(exclude=['tests']),
    install_requires=install_requires,
)
