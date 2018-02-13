#!/usr/bin/env python
"""
 Since control keyword arguments are generated at runtime, this generates a hard-coded set of
 argument names that cannot be used for this purpose and modifies the file.

 TODO: Make this run in an automated fashion, preferably before each commit. Pre-commit hooks do not
 seem to apply since this modifies a file intended for commit. Suggestions welcome.
"""

from inspect import getargspec, stack
from os import fdopen, remove
from os.path import dirname, abspath, join as path_join
from tempfile import mkstemp
from shutil import move

from laurelin.ldap import LDAP, LDAPObject
from laurelin.ldap.base import ExtendedResponseHandle

reservedKwds = set()

# functions that either call sendMessage or have kwds passed through into them
reserveFrom = [
    LDAPObject.__init__,
    LDAP.obj,
    LDAP.simple_bind,
    LDAP.sasl_bind,
    LDAP.search,
    LDAP.compare,
    LDAP.add,
    LDAP.delete,
    LDAP.modify,
    LDAP.mod_dn,
    LDAP.send_extended_request,
    ExtendedResponseHandle.__init__,
]
for f in reserveFrom:
    reservedKwds.update(getargspec(f).args)

# convert to list so that we can sort it and generate the code in deterministic order
# ensures we don't make unnecessary changes to the file
reservedKwds = list(reservedKwds)
reservedKwds.sort()

# generate the set definition
reservedKwdsStr = 'set({0})'.format(repr(reservedKwds))

## modify the file

baseDir = path_join(dirname(abspath(stack()[0][1])), '..')
controlsFn = path_join(baseDir, 'laurelin/ldap/controls.py')

varname = '_reserved_kwds'

tmpfd, tmpname = mkstemp()
found = False
with fdopen(tmpfd, 'w') as tmpfile:
    with open(controlsFn) as f:
        for line in f:
            # modify the definition in the file
            if line.startswith(varname):
                line = '{0} = {1}\n'.format(varname, reservedKwdsStr)
                found = True

            # copy to the tmp file
            tmpfile.write(line)

if not found:
    raise Exception('Did not find the {0} line'.format(varname))

# remove original and replace with tmp file
remove(controlsFn)
move(tmpname, controlsFn)
