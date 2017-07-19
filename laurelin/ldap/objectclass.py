from __future__ import absolute_import
from . import rfc4512
from . import utils
from .attributetype import getAttributeType
from .exceptions import LDAPWarning

import re

_reObjectClass = re.compile(utils.reAnchor(rfc4512.ObjectClassDescription))

_oidObjectClasses = {}
_nameObjectClasses = {}

def getObjectClass(ident):
    if ident[0].isdigit():
        return _oidObjectClasses[ident]
    else:
        try:
            return _nameObjectClasses[ident]
        except KeyError:
            return _nameObjectClasses.setdefault(ident, DefaultObjectClass(ident))


def _parseAttrList(spec):
    spec = spec.strip('() ')
    spec = spec.split('$')
    ret = []
    for attr in spec:
        attr = attr.strip()
        if attr[0].isdigit():
            try:
                for name in getAttributeType(attr).names:
                    ret.append(name)
            except KeyError:
                warn('Attribute type OID {0} has not been defined, excluding from '
                    'valid attributes on object class'.format(attr),
                    LDAPWarning,
                )
        else:
            ret.append(attr)
    return ret


class ObjectClass(object):
    def __init__(self, spec):
        spec = utils.collapseWhitespace(spec).strip()
        m = _reObjectClass.match(spec)
        if not m:
            raise LDAPError('Invalid object class description')

        # register OID
        self.oid = m.group('oid')
        _oidObjectClasses[self.oid] = self

        # register names
        self.names = tuple(name.strip("'") for name in m.group('name').strip('()').split(' '))
        for name in self.names:
            _nameObjectClasses[name] = self

        self.supertype = m.group('supertype')

        kind = m.group('kind')
        if kind is not None:
            self.kind = kind
        else:
            self.kind = 'STRUCTURAL'

        obsolete = m.group('obsolete')
        if obsolete is not None:
            self.obsolete = bool(obsolete)
        elif not self.supertype:
            self.obsolete = False

        must = m.group('must')
        if must is not None:
            self.must = _parseAttrList(must)
        elif not self.supertype:
           self.must = []

        may = m.group('may')
        if may is not None:
            self.may = _parseAttrList(may)
        elif not self.supertype:
            self.may = []

    def __getattr__(self, name):
        if self.supertype:
            return getattr(getObjectClass(self.supertype), name)
        else:
            raise AttributeError("No attribute named '{0}' and no supertype specified".format(name))



class DefaultObjectClass(ObjectClass):
    def __init__(self, name):
        self.oid = None
        self.names = (name,)
        self.supertype = None
        self.kind = 'STRUCTURAL'
        self.obsolete = False
        self.must = []
        self.may = []
