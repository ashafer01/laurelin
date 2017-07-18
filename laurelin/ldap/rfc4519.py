"""RFC 4519: Schema for User Applications

https://tools.ietf.org/html/rfc4519
"""

from __future__ import absolute_import

from . import rfc4512
from . import rfc4517
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
        self.names = tuple(name.strip("'") for name in m.group('name').split(' '))
        for name in self.names:
            _nameAttributeTypes[name] = self

        equality = m.group('equality')
        if equality is not None:
            self.equality = rfc4517.getMatchingRule(equality)

        # Note: ordering and substring matching not currently implemented
        # specs stored in m.group('ordering') and m.group('substr')

        syntax = m.group('syntax')
        if syntax is not None:
            syntax_noidlen = syntax.split('{')
            self.syntax = rfc4517.getSyntaxRule(syntax_noidlen[0])
            if len(syntax_noidlen) > 1:
                self.syntaxLength = int(syntax_noidlen[1].strip('}'))

        obsolete = m.group('obsolete')
        if obsolete is not None:
            self.obsolete = bool(obsolete)
        singleValue = m.group('single_value')
        if singleValue is not None:
            self.singleValue = bool(singleValue)
        collective = m.group('collective')
        if collective is not None:
            self.collective = bool(collective)
        noUserMod = m.group('no_user_mod')
        if noUserMod is not None:
            self.noUserMod = bool(noUserMod)

        usage = m.group('usage')
        if usage:
            self.usage = usage

        self.supertype = m.group('supertype')

    def __getattr__(self, name):
        if self.supertype:
            return getattr(getAttributeType(self.supertype), name)
        else:
            raise AttributeError("No attribute named '{0}' and no supertype specified".format(name))


## Defaults used when an attribute type is undefined

class DefaultSyntaxRule(object):
    def validate(self, s):
        pass


class DefaultMatchingRule(object):
    def match(self, a, b):
        return True


class DefaultAttributeType(AttributeType):
    def __init__(self, oid=None, name=None):
        self.oid = None
        self.names = (name,)
        self.equality = DefaultMatchingRule()
        self.syntax = DefaultSyntaxRule()
        self.obsolete = False
        self.singleValue = False
        self.collective = False
        self.noUserMod = False
        self.usage = 'userApplications'
        self.supertype = None

AttributeType("""
      ( 2.5.4.15 NAME 'businessCategory'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.6 NAME 'c'
         SUP name
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.11
         SINGLE-VALUE )
""")

AttributeType("""
      ( 2.5.4.3 NAME 'cn'
         SUP name )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.25 NAME 'dc'
         EQUALITY caseIgnoreIA5Match
         SUBSTR caseIgnoreIA5SubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
         SINGLE-VALUE )
""")

AttributeType("""
      ( 2.5.4.13 NAME 'description'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.27 NAME 'destinationIndicator'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
""")

AttributeType("""
      ( 2.5.4.49 NAME 'distinguishedName'
         EQUALITY distinguishedNameMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
""")

AttributeType("""
      ( 2.5.4.46 NAME 'dnQualifier'
         EQUALITY caseIgnoreMatch
         ORDERING caseIgnoreOrderingMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
""")

AttributeType("""
      ( 2.5.4.47 NAME 'enhancedSearchGuide'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )
""")

AttributeType("""
      ( 2.5.4.23 NAME 'facsimileTelephoneNumber'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.22 )
""")

AttributeType("""
      ( 2.5.4.44 NAME 'generationQualifier'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.42 NAME 'givenName'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.51 NAME 'houseIdentifier'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.43 NAME 'initials'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.25 NAME 'internationalISDNNumber'
         EQUALITY numericStringMatch
         SUBSTR numericStringSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
""")

AttributeType("""
      ( 2.5.4.7 NAME 'l'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.31 NAME 'member'
         SUP distinguishedName )
""")

AttributeType("""
      ( 2.5.4.41 NAME 'name'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.10 NAME 'o'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.11 NAME 'ou'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.32 NAME 'owner'
         SUP distinguishedName )
""")

AttributeType("""
      ( 2.5.4.19 NAME 'physicalDeliveryOfficeName'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.16 NAME 'postalAddress'
         EQUALITY caseIgnoreListMatch
         SUBSTR caseIgnoreListSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
""")

AttributeType("""
      ( 2.5.4.17 NAME 'postalCode'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.18 NAME 'postOfficeBox'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.28 NAME 'preferredDeliveryMethod'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.14
         SINGLE-VALUE )
""")

AttributeType("""
      ( 2.5.4.26 NAME 'registeredAddress'
         SUP postalAddress
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
""")

AttributeType("""
      ( 2.5.4.33 NAME 'roleOccupant'
         SUP distinguishedName )
""")

AttributeType("""
      ( 2.5.4.34 NAME 'seeAlso'
         SUP distinguishedName )
""")

AttributeType("""
      ( 2.5.4.5 NAME 'serialNumber'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
""")

AttributeType("""
      ( 2.5.4.4 NAME 'sn'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.8 NAME 'st'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.9 NAME 'street'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.20 NAME 'telephoneNumber'
         EQUALITY telephoneNumberMatch
         SUBSTR telephoneNumberSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
""")

AttributeType("""
      ( 2.5.4.21 NAME 'telexNumber'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.52 )
""")

AttributeType("""
      ( 2.5.4.12 NAME 'title'
         SUP name )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.1 NAME 'uid'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.50 NAME 'uniqueMember'
         EQUALITY uniqueMemberMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )
""")

AttributeType("""
      ( 2.5.4.35 NAME 'userPassword'
         EQUALITY octetStringMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
""")

AttributeType("""
      ( 2.5.4.24 NAME 'x121Address'
         EQUALITY numericStringMatch
         SUBSTR numericStringSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
""")

AttributeType("""
      ( 2.5.4.45 NAME 'x500UniqueIdentifier'
         EQUALITY bitStringMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )
""")
