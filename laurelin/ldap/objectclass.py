from __future__ import absolute_import
from . import rfc4512
from . import utils
from .attributetype import get_attribute_type
from .exceptions import LDAPSchemaError, LDAPWarning
from .protoutils import parse_qdescrs

import re
from warnings import warn

_re_object_class = re.compile(utils.re_anchor(rfc4512.ObjectClassDescription))

_oid_object_classes = {}
_name_object_classes = {}


def get_object_class(ident):
    if ident[0].isdigit():
        return _oid_object_classes[ident]
    else:
        try:
            return _name_object_classes[ident]
        except KeyError:
            return _name_object_classes.setdefault(ident, DefaultObjectClass(ident))


def _parse_oids(spec):
    if not spec:
        return []
    spec = spec.strip('() ')
    spec = spec.split('$')
    return [oid.strip() for oid in spec]


def _parse_attr_list(spec):
    ret = []
    for attr in _parse_oids(spec):
        if attr[0].isdigit():
            try:
                for name in get_attribute_type(attr).names:
                    ret.append(name)
            except KeyError:
                warn('Attribute type OID {0} has not been defined, excluding from '
                     'valid attributes on object class'.format(attr),
                     LDAPWarning)
        else:
            ret.append(attr)
    return ret


class ObjectClass(object):
    def __init__(self, spec):
        spec = utils.collapse_whitespace(spec).strip()
        m = _re_object_class.match(spec)
        if not m:
            raise LDAPSchemaError('Invalid object class description')

        # register OID
        self.oid = m.group('oid')
        if self.oid in _oid_object_classes:
            raise LDAPSchemaError('Duplicate object class OID {0}'.format(self.oid))
        _oid_object_classes[self.oid] = self

        # register names
        self.names = parse_qdescrs(m.group('name'))
        for name in self.names:
            if name in _name_object_classes:
                raise LDAPSchemaError('Duplicate object class name {0}'.format(name))
            _name_object_classes[name] = self

        self.superclasses = _parse_oids(m.group('superclass'))

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

        self.my_must = _parse_attr_list(m.group('must'))
        self.my_may = _parse_attr_list(m.group('may'))

        self._must = None
        self._may = None

    @property
    def must(self):
        if self._must is not None:
            return self._must
        elif self.superclasses:
            self._must = self.my_must
            for oc in self.superclasses:
                self._must += get_object_class(oc).must
            return self._must
        else:
            self._must = self.my_must
            return self._must

    @property
    def may(self):
        if self._may is not None:
            return self._may
        elif self.superclasses:
            self._may = self.my_may
            for oc in self.superclasses:
                self._may += get_object_class(oc).may
            return self._may
        else:
            self._may = self.my_may
            return self._may

    def allowed_attr(self, name):
        return (name in self.may or name in self.must)

    def required_attr(self, name):
        return (name in self.must)


class DefaultObjectClass(ObjectClass):
    def __init__(self, name):
        self.oid = None
        self.names = (name,)
        self.supertype = None
        self.kind = 'STRUCTURAL'
        self.obsolete = False
        self.my_must = []
        self.my_may = []
        self._must = None
        self._may = None


## RFC 4512 4.3 extensibleObject

# The 'extensibleObject' auxiliary object class allows entries that
# belong to it to hold any user attribute.

class ExtensibleObjectClass(ObjectClass):
    def allowed_attr(self, name):
        return True
