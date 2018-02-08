from __future__ import absolute_import
from . import rfc4512
from . import rules
from . import utils
from .exceptions import LDAPSchemaError
from .protoutils import parse_qdescrs

import re

_re_attr_type = re.compile(utils.re_anchor(rfc4512.AttributeTypeDescription))

_oid_attribute_types = {}
_name_attribute_types = {}


def get_attribute_type(ident):
    if ident[0].isdigit():
        return _oid_attribute_types[ident]
    else:
        try:
            return _name_attribute_types[ident]
        except KeyError:
            return _name_attribute_types.setdefault(ident, DefaultAttributeType(ident))


class AttributeType(object):
    def __init__(self, spec):
        spec = utils.collapse_whitespace(spec).strip()
        m = _re_attr_type.match(spec)
        if not m:
            raise LDAPSchemaError('Invalid attribute type specification')

        # register OID
        self.oid = m.group('oid')
        if self.oid in _oid_attribute_types:
            raise LDAPSchemaError('Duplicate attribute type OID {0}'.format(self.oid))
        _oid_attribute_types[self.oid] = self

        # register name(s)
        self.names = parse_qdescrs(m.group('name'))
        for name in self.names:
            if name in _name_attribute_types:
                raise LDAPSchemaError('Duplicate attribute type name {0}'.format(name))
            _name_attribute_types[name] = self

        self.supertype = m.group('supertype')

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
                self.syntaxLength = int(syntax_noidlen[1].strip('}'))
            else:
                self.syntaxLength = -1
        elif not self.supertype:
            self.syntax_oid = None
            self.syntaxLength = -1

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

    @property
    def syntax(self):
        return rules.get_syntax_rule(self.syntax_oid)

    @property
    def equality(self):
        return rules.get_matching_rule(self.equality_oid)

    def __getattr__(self, name):
        if self.supertype:
            return getattr(get_attribute_type(self.supertype), name)
        else:
            raise AttributeError("No attribute named '{0}' and no supertype specified".format(name))

    def validate(self, value):
        """Validate a value according to the attribute type's syntax rule"""
        return self.syntax.validate(value)

    def index(self, value_list, assertion_value):
        """Finds the index of a value in a list of attribute values. Raises a
         ValueError if the value is not found in the list. Assumes values in
         value_list are already validated.
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


## Defaults used when an attribute type is undefined

class DefaultSyntaxRule(object):
    def validate(self, s):
        pass


class DefaultMatchingRule(object):
    def validate(self, value):
        return True

    def prepare(self, a):
        return a

    def do_match(self, a, b):
        return (a == b)

    def match(self, a, b):
        return self.do_match(a, b)


class DefaultAttributeType(AttributeType):
    def __init__(self, name=None):
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
