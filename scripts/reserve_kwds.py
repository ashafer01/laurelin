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

BASE_DIR = path_join(dirname(abspath(stack()[0][1])), '..')


def find_kwds_list(reserve_from):
    reserved_kwds = set()

    for f in reserve_from:
        reserved_kwds.update(getargspec(f).args)

    # convert to list so that we can sort it and generate the code in deterministic order
    # ensures we don't make unnecessary changes to the file
    reserved_kwds = list(reserved_kwds)
    reserved_kwds.sort()
    return reserved_kwds


def update_kwds_set_def(filename, varname, reserve_from):
    # generate the set definition
    reserved_kwds_str = 'set({0})'.format(repr(find_kwds_list(reserve_from)))

    tmpfd, tmpname = mkstemp()
    found = False
    lineno = 1
    with fdopen(tmpfd, 'w') as tmpfile:
        with open(filename) as f:
            for line in f:
                # modify the definition in the file
                if line.startswith(varname):
                    orig_line = line
                    line = '{0} = {1}\n'.format(varname, reserved_kwds_str)
                    if orig_line != line:
                        print('Updating {0}:{1}'.format(filename, lineno))
                        print('  Before:')
                        print('    {0}'.format(orig_line.strip()))
                        print('  After:')
                        print('    {0}'.format(line.strip()))
                    found = True

                # copy to the tmp file
                tmpfile.write(line)
                lineno += 1

    if not found:
        raise Exception('Did not find the {0} line'.format(varname))

    # remove original and replace with tmp file
    remove(filename)
    move(tmpname, filename)


def update_control_keywords():
    controls_fn = path_join(BASE_DIR, 'laurelin/ldap/controls.py')
    varname = '_reserved_kwds'
    # functions that either call send_message or have kwds passed through into them
    reserve_from = [
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
    update_kwds_set_def(controls_fn, varname, reserve_from)


def update_object_keywords():
    base_module_fn = path_join(BASE_DIR, 'laurelin/ldap/base.py')
    varname = '_obj_kwds'
    reserve_from = [LDAP.obj, LDAPObject.__init__]
    update_kwds_set_def(base_module_fn, varname, reserve_from)


if __name__ == '__main__':
    update_control_keywords()
    update_object_keywords()
