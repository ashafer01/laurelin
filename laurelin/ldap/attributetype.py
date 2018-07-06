from __future__ import absolute_import
from . import rfc4512
from . import rules
from . import utils
from .exceptions import LDAPSchemaError, InvalidSyntaxError
from .protoutils import parse_qdescrs
from .utils import CaseIgnoreDict

import logging
import re

logger = logging.getLogger(__name__)

_re_attr_type = re.compile(utils.re_anchor(rfc4512.AttributeTypeDescription))

_oid_attribute_types = {}
_name_attribute_types = CaseIgnoreDict()


def get_attribute_type(ident):
    """Get an instance of :class:`AttributeType` associated with either a name or OID.

    :param str ident: Either the numeric OID of the desired attribute type spec or any one of its specified names
    :return: The AttributeType containing a parsed specification
    :rtype: AttributeType
    """
    if ident[0].isdigit():
        return _oid_attribute_types[ident]
    else:
        try:
            return _name_attribute_types[ident]
        except KeyError:
            return DefaultAttributeType(ident)


class AttributeType(object):
    """Parses an LDAP attribute type specification and implements supertype inheritance.

    Each instantiation registers the names and OIDs specified so that the spec can be accessed using
    :func:`get_attribute_type`.

    See the :mod:`laurelin.ldap.schema` module source for example usages.

    :param str spec: The LDAP specification for an Attribute Type.
    :raises: LDAPSchemaError:
     * if the specification is invalid
     * if the OID has already been defined
     * if one of the names has already been defined

    :var str oid: The OID of the attribute type
    :var tuple(str) names: A tuple containing all possible names for the attribute type
    :var str supertype: The specified supertype. If the spec does not define optional properties, they will pass through
                        into the supertype.
    :var str equality_oid: The OID of the equality matching rule
    :var str syntax_oid: The OID of the syntax matching rule
    :var int syntax_length: The suggested maximum length of a value
    :var bool obsolete: The type has been flagged as obsolete. Will cause a warning from the :class:`SchemaValidator` if
                        an obsolete attribute type is used.
    :var bool single_value: The attribute may only have one value.
    :var bool collective: The attribute has been marked collective.
    :var bool no_user_mod: The attribute may not be modified by users (e.g., for operational attributes). Will cause a
                           validation failure from the :class:`SchemaValidator` if a write operation is attempted on
                           attribute types with this property set to True.
    :var str usage: A string describing the attribute's usage. May be one of `userApplications`, `directoryOperation`,
                    `distributedOperation`, or `dSAOperation`.
    """
    def __init__(self, spec):
        spec = utils.collapse_whitespace(spec).strip()
        m = _re_attr_type.match(spec)
        if not m:
            raise LDAPSchemaError('Invalid attribute type specification')

        self.oid = m.group('oid')
        if not self.oid:
            raise LDAPSchemaError('No OID defined for attribute type')

        self.names = parse_qdescrs(m.group('name'))
        if not self.names:
            raise LDAPSchemaError('No names defined for attribute type {0}'.format(self.oid))

        self.supertype = m.group('supertype')
        if self.supertype:
            self.supertype = self.supertype.strip()

        equality = m.group('equality')
        if equality is not None:
            self.equality_oid = equality
        elif not self.supertype:
            self.equality_oid = None

        # Note: ordering and substring matching not currently implemented
        # specs stored in m.group('ordering') and m.group('substr')

        syntax = m.group('syntax')
        if syntax is not None:
            syntax_noidlen = syntax.split('{')
            self.syntax_oid = syntax_noidlen[0]
            if len(syntax_noidlen) > 1:
                self.syntax_length = int(syntax_noidlen[1].strip('}'))
            else:
                self.syntax_length = -1
        elif not self.supertype:
            self.syntax_oid = None
            self.syntax_length = -1

        obsolete = m.group('obsolete')
        if obsolete is not None:
            self.obsolete = bool(obsolete)
        elif not self.supertype:
            self.obsolete = False

        single_value = m.group('single_value')
        if single_value is not None:
            self.single_value = bool(single_value)
        elif not self.supertype:
            self.single_value = False

        collective = m.group('collective')
        if collective is not None:
            self.collective = bool(collective)
        elif not self.supertype:
            self.collective = False

        no_user_mod = m.group('no_user_mod')
        if no_user_mod is not None:
            self.no_user_mod = bool(no_user_mod)
        elif not self.supertype:
            self.no_user_mod = False

        usage = m.group('usage')
        if usage:
            self.usage = usage
        elif not self.supertype:
            self.usage = 'userApplications'

    def register(self):
        # register OID
        if self.oid in _oid_attribute_types:
            raise LDAPSchemaError('Duplicate attribute type OID {0}'.format(self.oid))
        _oid_attribute_types[self.oid] = self

        # register name(s)
        for name in self.names:
            if name in _name_attribute_types:
                raise LDAPSchemaError('Duplicate attribute type name {0}'.format(name))
            _name_attribute_types[name] = self

    @property
    def syntax(self):
        """Gets the :class:`SyntaxRule` for this attribute type."""
        if not self.syntax_oid:
            raise LDAPSchemaError('Attribute type {0} does not have a defined syntax'.format(self.oid))
        return rules.get_syntax_rule(self.syntax_oid)

    @property
    def equality(self):
        """Gets the :class:`EqualityMatchingRule` for this attribute type."""
        if not self.equality_oid:
            raise LDAPSchemaError('Attribute type {0} does not have a defined equality matching rule'.format(self.oid))
        return rules.get_matching_rule(self.equality_oid)

    def __getattr__(self, name):
        if self.supertype:
            return getattr(get_attribute_type(self.supertype), name)
        else:
            raise AttributeError("No attribute named '{0}' and no supertype specified for attr {1}".format(
                                 name, self.oid))

    def validate(self, value):
        """Validate a value according to the attribute type's syntax rule.

        :param str value: The potential attribute value
        :return: A truthy value.
        :raises InvalidSyntaxError: if the value is invalid.
        """
        if self.syntax_length > -1:
            length = len(value)
            if length > self.syntax_length:
                raise InvalidSyntaxError('Length {0} greater than allowed {1}'.format(length, self.syntax_length))
        return self.syntax.validate(value)

    def index(self, value_list, assertion_value):
        """Finds the index of a value in a list of attribute values. Raises a
         ValueError if the value is not found in the list. Assumes values in
         value_list are already validated.

         :param list[str] value_list: The list of attribute values. Assumes values are already validated.
         :param str assertion_value: The value to look for in ``value_list``.
         :return: The index of ``assertion_value`` in ``value_list``.
         :rtype: int
         :raises ValueError: if ``assertion_value`` is not found or if ``value_list`` is empty.
         :raises InvalidSyntaxError: if ``assertion_value`` does not meet the syntax requirements of this attribute type
        """
        if not value_list:
            raise ValueError('empty value_list')
        self.validate(assertion_value)
        assertion_value = self.equality.prepare(assertion_value)
        for i, val in enumerate(value_list):
            val = self.equality.prepare(val)
            if self.equality.do_match(val, assertion_value):
                return i
        raise ValueError('assertion_value not found')

    def __repr__(self):
        return '<{0} "{1}">'.format(self.__class__.__name__, self.names[0])


## Defaults used when an attribute type is undefined

class DefaultSyntaxRule(object):
    """The default syntax rule to use for undefined attribute types.

    Users should probably never instantiate this.
    """
    def validate(self, s):
        """Allow all values"""
        pass


class DefaultMatchingRule(object):
    """The default matching rule to use for undefined attribute types.

    Users should probably never instantiate this.
    """
    def validate(self, value):
        """Allow all values"""
        return True

    def prepare(self, a):
        """Do nothing to prepare"""
        return a

    def do_match(self, a, b):
        """Require strict equality"""
        return (a == b)

    def match(self, a, b):
        """Do the match"""
        return self.do_match(a, b)


class DefaultAttributeType(AttributeType):
    """The default attribute type returned by :func:`get_attribute_type` when the requested attribute type is
    undefined.

    Essentially behaves as an unrestricted case-sensitive attribute type.

    Users should probably never instantiate this.
    """
    def __init__(self, name=None):
        logger.debug('Using DefaultAttributeType for name={0}'.format(name))
        self.oid = None
        self.names = (name,)
        self._equality = DefaultMatchingRule()
        self._syntax = DefaultSyntaxRule()
        self.obsolete = False
        self.single_value = False
        self.collective = False
        self.no_user_mod = False
        self.usage = 'userApplications'
        self.supertype = None

    @property
    def syntax(self):
        return self._syntax

    @property
    def equality(self):
        return self._equality

    def index(self, value_list, assertion_value):
        return list.index(value_list, assertion_value)
