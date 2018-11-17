from __future__ import absolute_import
from . import rfc4512
from . import utils
from .attributetype import get_attribute_type
from .exceptions import LDAPSchemaError, LDAPWarning
from .protoutils import parse_qdescrs
from .utils import CaseIgnoreDict

import logging
import re
from warnings import warn

_re_object_class = re.compile(utils.re_anchor(rfc4512.ObjectClassDescription))

_oid_object_classes = {}
_name_object_classes = CaseIgnoreDict()

logger = logging.getLogger(__name__)


def get_object_class(ident):
    """Get an instance of :class:`ObjectClass` associated with either a name or an OID

    :param str ident: Either the numeric OID of the desired object class spec or one of its specified names
    :return: The ObjectClass associated with the name/OID
    :rtype: ObjectClass
    """
    if ident[0].isdigit():
        return _oid_object_classes[ident]
    else:
        try:
            return _name_object_classes[ident]
        except KeyError:
            return DefaultObjectClass(ident)


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
    """Parses an LDAP object class specification and implements superclass inheritance.

    Each instantiation registers the names and OID specified so that they can later be access with
    :func:`get_object_class`.

    See the :mod:`laurelin.ldap.schema` module source for example usages.

    :param str spec: The LDAP specification for an object class
    :raises LDAPSchemaError:
         * if the schema is syntactically invalid
         * if the OID specified has already been registered
         * if one of the names specified has already been registered

    :var str oid: The specified OID
    :var tuple(str) names: All specified names
    :var list[str] superclasses: The list of all specified superclass names/OIDs.
    :var str kind: One of `ABSTRACT`, `STRUCTURAL`, or `AUXILIARY`
    :var bool obsolete: True if the objectClass has been marked obsolete.
    :var list[str] my_must: The list of required attribute types for this class
    :var list[str] my_may: The list of allowed attribute types for this class
    """
    def __init__(self, spec):
        spec = utils.collapse_whitespace(spec).strip()
        m = _re_object_class.match(spec)
        if not m:
            raise LDAPSchemaError('Invalid object class description')

        self.oid = m.group('oid')

        self.names = parse_qdescrs(m.group('name'))

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

    def register(self):
        # register OID
        if self.oid in _oid_object_classes:
            raise LDAPSchemaError('Duplicate object class OID {0}'.format(self.oid))
        _oid_object_classes[self.oid] = self

        # register names
        for name in self.names:
            if name in _name_object_classes:
                raise LDAPSchemaError('Duplicate object class name {0}'.format(name))
            _name_object_classes[name] = self

    @property
    def must(self):
        """Obtains all required attribute types after ascending the superclass specifications"""
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
        """Obtains all allowed attribute types after ascending the superclass specifications"""
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
        """Check if the given attribute type name is allowed.

        :param name: The name of the attribute type to check
        :return: True if the given attribute type is allowed.
        :rtype: bool
        """
        return (name in self.may or name in self.must)

    def required_attr(self, name):
        """Check if the given attribute type name is required.

        :param name: The name of the attribute type to check
        :return: True if the given attribute type is required.
        :rtype: bool
        """
        return (name in self.must)

    def __repr__(self):
        return '<{0} "{1}">'.format(self.__class__.__name__, self.names[0])


class DefaultObjectClass(ObjectClass):
    """The default ObjectClass returned by :func:`get_object_class` when the requested object class is undefined.

    Users should probably never instantiate this.
    """
    def __init__(self, name):
        logger.debug('Using DefaultObjectClass for name={0}'.format(name))
        self.oid = None
        self.names = (name,)
        self.supertype = None
        self.kind = 'STRUCTURAL'
        self.obsolete = False
        self.superclasses = ()
        self.my_must = []
        self.my_may = []
        self._must = None
        self._may = None


## RFC 4512 4.3 extensibleObject


class ExtensibleObjectClass(ObjectClass):
    """The `extensibleObject` auxiliary objectClass allows entries that belong to it to hold any user attribute."""
    def allowed_attr(self, name):
        return True
