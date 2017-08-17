from __future__ import absolute_import
from . import rfc4512
from . import rules
from . import utils
from .exceptions import LDAPError

import re

_reAttrType = re.compile(utils.reAnchor(rfc4512.AttributeTypeDescription))

_oidAttributeTypes = {}
_nameAttributeTypes = {}

def getAttributeType(ident):
    if ident[0].isdigit():
        return _oidAttributeTypes[ident]
    else:
        try:
            return _nameAttributeTypes[ident]
        except KeyError:
            return _nameAttributeTypes.setdefault(ident, DefaultAttributeType(ident))

class AttributeType(object):
    def __init__(self, spec):
        spec = utils.collapseWhitespace(spec).strip()
        m = _reAttrType.match(spec)
        if not m:
            raise LDAPError('Invalid attribute type specification')

        # register OID
        self.oid = m.group('oid')
        _oidAttributeTypes[self.oid] = self

        # register name(s)
        self.names = utils.parseQdescrs(m.group('name'))
        for name in self.names:
            _nameAttributeTypes[name] = self

        self.supertype = m.group('supertype')

        equality = m.group('equality')
        if equality is not None:
            self.equalityOID = equality
        elif not self.supertype:
            self.equalityOID = None

        # Note: ordering and substring matching not currently implemented
        # specs stored in m.group('ordering') and m.group('substr')

        syntax = m.group('syntax')
        if syntax is not None:
            syntax_noidlen = syntax.split('{')
            self.syntaxOID = syntax_noidlen[0]
            if len(syntax_noidlen) > 1:
                self.syntaxLength = int(syntax_noidlen[1].strip('}'))
            else:
                self.syntaxLength = -1
        elif not self.supertype:
            self.syntaxOID = None
            self.syntaxLength = -1

        obsolete = m.group('obsolete')
        if obsolete is not None:
            self.obsolete = bool(obsolete)
        elif not self.supertype:
            self.obsolete = False

        singleValue = m.group('single_value')
        if singleValue is not None:
            self.singleValue = bool(singleValue)
        elif not self.supertype:
            self.singleValue = False

        collective = m.group('collective')
        if collective is not None:
            self.collective = bool(collective)
        elif not self.supertype:
            self.collective = False

        noUserMod = m.group('no_user_mod')
        if noUserMod is not None:
            self.noUserMod = bool(noUserMod)
        elif not self.supertype:
            self.noUserMod = False

        usage = m.group('usage')
        if usage:
            self.usage = usage
        elif not self.supertype:
            self.usage = 'userApplications'

    @property
    def syntax(self):
        return rules.getSyntaxRule(self.syntaxOID)

    @property
    def equality(self):
        return rules.getMatchingRule(self.equalityOID)

    def __getattr__(self, name):
        if self.supertype:
            return getattr(getAttributeType(self.supertype), name)
        else:
            raise AttributeError("No attribute named '{0}' and no supertype specified".format(name))

    def validate(self, value):
        return self.syntax.validate(value)

    def match(self, attributeValue, assertionValue):
        self.validate(attributeValue)
        return self.equality.match(attributeValue, assertionValue)


## Defaults used when an attribute type is undefined

class DefaultSyntaxRule(object):
    def validate(self, s):
        pass


class DefaultMatchingRule(object):
    def validate(self, value):
        return True

    def match(self, a, b):
        return (a == b)


class DefaultAttributeType(AttributeType):
    def __init__(self, oid=None, name=None):
        self.oid = None
        self.names = (name,)
        self._equality = DefaultMatchingRule()
        self._syntax = DefaultSyntaxRule()
        self.obsolete = False
        self.singleValue = False
        self.collective = False
        self.noUserMod = False
        self.usage = 'userApplications'
        self.supertype = None

    @property
    def syntax(self):
        return self._syntax

    @property
    def equality(self):
        return self._equality
