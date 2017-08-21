from __future__ import absolute_import
from . import rfc4512
from . import utils
from .attributetype import getAttributeType
from .exceptions import LDAPSchemaError, LDAPWarning
from .protoutils import parseQdescrs

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


def _parseOIDs(spec):
    if not spec:
        return []
    spec = spec.strip('() ')
    spec = spec.split('$')
    return [oid.strip() for oid in spec]


def _parseAttrList(spec):
    ret = []
    for attr in _parseOIDs(spec):
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
            raise LDAPSchemaError('Invalid object class description')

        # register OID
        self.oid = m.group('oid')
        if self.oid in _oidObjectClasses:
            raise LDAPSchemaError('Duplicate object class OID {0}'.format(self.oid))
        _oidObjectClasses[self.oid] = self

        # register names
        self.names = parseQdescrs(m.group('name'))
        for name in self.names:
            if name in _nameObjectClasses:
                raise LDAPSchemaError('Duplicate object class name {0}'.format(name))
            _nameObjectClasses[name] = self

        self.superclasses = _parseOIDs(m.group('superclass'))

        kind = m.group('kind')
        if kind is not None:
            self.kind = kind
        else:
            self.kind = 'STRUCTURAL'

        obsolete = m.group('obsolete')
        if obsolete is not None:
            self.obsolete = bool(obsolete)
        else:
            self.obsolete = False

        self.myMust = _parseAttrList(m.group('must'))
        self.myMay = _parseAttrList(m.group('may'))

        self._must = None
        self._may = None

    @property
    def must(self):
        if self._must is not None:
            return self._must
        elif self.superclasses:
            self._must = self.myMust
            for oc in self.superclasses:
                self._must += getObjectClass(oc).must
            return self._must
        else:
            self._must = self.myMust
            return self._must

    @property
    def may(self):
        if self._may is not None:
            return self._may
        elif self.superclasses:
            self._may = self.myMay
            for oc in self.superclasses:
                self._may += getObjectClass(oc).may
            return self._may
        else:
            self._may = self.myMay
            return self._may


    def allowedAttr(self, name):
        return (name in self.may or name in self.must)

    def requiredAttr(self, name):
        return (name in self.must)


class DefaultObjectClass(ObjectClass):
    def __init__(self, name):
        self.oid = None
        self.names = (name,)
        self.supertype = None
        self.kind = 'STRUCTURAL'
        self.obsolete = False
        self.myMust = []
        self.myMay = []
        self._must = None
        self._may = None


## RFC 4512 4.3 extensibleObject

# The 'extensibleObject' auxiliary object class allows entries that
# belong to it to hold any user attribute.

class ExtensibleObjectClass(ObjectClass):
    def allowedAttr(self, name):
        return True
