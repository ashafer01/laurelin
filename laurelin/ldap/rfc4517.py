"""Implementations of RFC 4517: Syntaxes and Matching Rules

https://tools.ietf.org/html/rfc4517
"""

from __future__ import absolute_import

from . import rfc4512
from . import rfc4514
from . import utils
import re
import six
from six.moves import range

PrintableCharacter = r"[A-Za-z0-9'()+,.=/:? -]"
_PrintableString = PrintableCharacter + r'+'

_IA5String = r"[\x00-\x7f]*"
_BitString = r"'[01]*'B"


## Syntax Rules


_oidSyntaxRules = {}
_oidSyntaxRuleObjects = {}

def getSyntaxRule(oid):
    obj = _oidSyntaxRuleObjects.get(oid)
    if not obj:
        obj = _oidSyntaxRules[oid]()
    return obj


class MetaSyntaxRule(type):
    """Metaclass registering OIDs on subclasses"""
    def __new__(meta, name, bases, dct):
        oid = dct.get('OID')
        cls = type.__new__(meta, name, bases, dct)
        if oid:
            _oidSyntaxRules[oid] = cls
        return cls


@six.add_metaclass(MetaSyntaxRule)
class SyntaxRule(object):
    """Base class for all syntax rules"""
    def __init__(self):
        oid = getattr(self, 'OID', None)
        if oid:
            _oidSyntaxRuleObjects[oid] = self

    def validate(self, s):
        raise NotImplementedError()


class RegexSyntaxRule(SyntaxRule):
    """For validateing rules based on a regular expression
     Subclasses must define the `regex` attribute
    """
    def __init__(self):
        self.compiled_re = re.compile(self.regex)
        SyntaxRule.__init__(self)

    def validate(self, s):
        return bool(self.compiled_re.match(s))


class BitString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.6'
    DESC = 'Bit String'
    regex = utils.reAnchor(_BitString)


class Boolean(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.7'
    DESC = 'Boolean'

    def validate(self, s):
        return (s == 'TRUE' or s == 'FALSE')


class CountryString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.11'
    DESC = 'Country String'
    regex = r'^' + PrintableCharacter + r'{2}$'


class DeliveryMethod(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.14'
    DESC = 'Delivery Method'
    _pdm = r'(any|mhs|physical|telex|teletext|g3fax|g4fax|ia5|videotext|telephone)'
    regex = r'^' + _pdm + r'(\s*\$\s*' + _pdm + r')*$'


class DirectoryString(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.15'
    DESC = 'Directory String'

    def validate(self, s):
        if isinstance(s, six.string_types):
            return (len(s) > 0)
        else:
            return False

class DITContentRuleDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.16'
    DESC = 'DIT Content Rule Description'
    regex = utils.reAnchor(rfc4512.DITContentRuleDescription)


class DITStructureRuleDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.17'
    DESC = 'DIT Structure Rule Description'
    regex = utils.reAnchor(rfc4512.DITStructureRuleDescription)


class DistinguishedName(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.12'
    DESC = 'DN'
    regex = utils.reAnchor(rfc4514.distinguishedName)

class EnhancedGuide(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.21'
    DESC = 'Enhanced Guide'

    _object_class = rfc4512.WSP + rfc4512.oid + rfc4512.WSP
    _subset = r'(base[oO]bject|oneLevel|wholeSubtree)'
    _match_type = r'(EQ|SUBSTR|GE|LE|APPROX)'
    _term = (
        r'!?(' + # TODO (maybe?): circular reference in spec - wants ! _term
        rfc4512.oid + r'\$' + _match_type +
        r'|\(' + r'[^)]+' + r'\)' +  # TODO: circular reference in spec - wants _criteria
        r'|\?true|\?false)'
    )
    _and_term = _term + r'(\&' + _term + r')*'
    _criteria = _and_term + r'(\|' + _and_term + r')*'

    regex = _object_class + r'#' + rfc4512.WSP + _criteria + rfc4512.WSP + r'#' + rfc4512.WSP + _subset

class FacsimilieTelephoneNumber(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.22'
    DESC = 'Facsimile Telephone Number'

    _fax_parameters = (
        'twoDimensional',
        'fineResolution',
        'unlimitedLength',
        'b4Length',
        'a3Width',
        'b4Width',
        'uncompressed',
    )

    def validate(self, s):
        params = s.split('$')
        if not utils.validatePhoneNumber(params[0]):
            return False
        for param in params[1:]:
            if param not in self._fax_parameters:
                return False
        return True


class Fax(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.23'
    DESC = 'Fax'

    def validate(self, s):
        # The LDAP-specific encoding of a value of this syntax is the
        # string of octets for a Group 3 Fax image
        return True

class GeneralizedTime(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.24'
    DESC = 'Generalized Time'
    regex = r'^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})?([0-9]{2})?([.,][0-9]+)?(Z|[+-]([0-9]{2})([0-9]{2})?)$'

    def validate(self, s):
        m = self.compiled_re.match(s)
        if not m:
            return False
        else:
            month = int(m.group(2))
            if month < 1 or month > 12:
                return False

            day = int(m.group(3))
            if day < 1 or day > 31:
                return False

            hour = int(m.group(4))
            if hour < 0 or hour > 23:
                return False

            minute = m.group(5)
            if minute is not None:
                minute = int(minute)
                if minute < 0 or minute > 59:
                    return False

            second = m.group(6)
            if second is not None:
                second = int(second)
                if second < 0 or second > 60:
                    return False

            tz = m.group(8)
            if tz != 'Z':
                tzhour = int(m.group(9))
                if tzhour < 0 or tzhour > 23:
                    return False

                tzminute = m.group(10)
                if tzminute is not None:
                    tzminute = int(tzminute)
                    if tzminute < 0 or tzminute > 59:
                        return False

            return True


class IA5String(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.26'
    DESC = 'IA5 String'
    regex = utils.reAnchor(_IA5String)


class Integer(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.27'
    DESC = 'INTEGER'
    regex = r'^-?[1-9][0-9]*$'


class JPEG(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.28'
    DESC = 'JPEG'

    def validate(self, s):
        # The LDAP-specific encoding of a value of this syntax is the sequence
        # of octets of the JFIF encoding of the image.
        return True


class LDAPSytnaxDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.54'
    DESC = 'LDAP Syntax Description'
    regex = utils.reAnchor(rfc4512.SyntaxDescription)


class MatchingRuleDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.30'
    DESC = 'Matching Rule Description'
    regex = utils.reAnchor(rfc4512.MatchingRuleDescription)


class MatchingRuleUseDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.31'
    DESC = 'Matching Rule Use Description'
    regex = utils.reAnchor(rfc4512.MatchingRuleUseDescription)


class NameAndOptionalUID(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.34'
    DESC = 'Name And Optional UID'
    regex = r'^' + rfc4514.distinguishedName + r'(#' + _BitString + r')?'


class NameFormDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.35'
    DESC = 'Name Form Description'
    regex = utils.reAnchor(rfc4512.NameFormDescription)


class NumericString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.36'
    DESC = 'Numeric String'
    regex = r'^[0-9 ]+$'


class ObjectClassDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.37'
    DESC = 'Object Class Description'
    regex = utils.reAnchor(rfc4512.ObjectClassDescription)


class OctetString(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.40'
    DESC = 'Octet String'

    def validate(self, s):
        # Any arbitrary sequence of octets
        return True


class OID(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.38'
    DESC = 'OID'
    regex = utils.reAnchor(rfc4512.oid)


class OtherMailbox(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.39'
    DESC = 'Other Mailbox'
    regex = r'^' + _PrintableString + r'\$' + _IA5String + r'$'


class PostalAddress(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.41'
    DESC = 'Postal Address'

    _line_char = utils.escapedRegex('\\$')
    _line = _line_char + r'+'
    regex = r'^' + _line + r'(\$' + _line + r')*$'


class PrintableString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.44'
    DESC = 'Printable String'
    regex = utils.reAnchor(_PrintableString)


class SubstringAssertion(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.58'
    DESC = 'Substring Assertion'

    _substring_character = utils.escapedRegex('\\*')
    _substring = _substring_character + r'+'
    regex = r'(' + _substring + r')?\*(' + _substring + r'\*)*(' + _substring + r')?'


class TelephoneNumber(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.50'
    DESC = 'Telephone Number'

    def validate(self, s):
        return utils.validatePhoneNumber(s)


class TelexNumber(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.52'
    DESC = 'Telex Number'
    regex = r'^' + _PrintableString + r'\$' + _PrintableString + r'\$' + _PrintableString + r'$'


## Matching Rules


_oidMatchingRules = {}
_nameMatchingRules = {}
_oidMatchingRuleObjects = {}
_nameMatchingRuleObjects = {}

def getMatchingRule(ident):
    """Obtains matching rule instance for name or OID"""
    if ident[0].isdigit():
        clsDict = _oidMatchingRules
        objDict = _oidMatchingRuleObjects
    else:
        clsDict = _nameMatchingRules
        objDict = _nameMatchingRuleObjects
    obj = objDict.get(ident)
    if not obj:
        obj = clsDict[ident]()
    return obj

class MetaMatchingRule(type):
    """Metaclass registering OIDs and NAMEs on subclasses"""
    def __new__(meta, clsname, bases, dct):
        oid = dct.get('OID')
        names = dct.get('NAME', ())
        if isinstance(names, six.string_types):
            names = (names,)
            dct['NAME'] = names
        cls = type.__new__(meta, clsname, bases, dct)
        if oid:
            _oidMatchingRules[oid] = cls
        for name in names:
            _nameMatchingRules[name] = cls
        return cls


@six.add_metaclass(MetaMatchingRule)
class MatchingRule(object):
    """Base class for all matching rules"""
    def __init__(self):
        oid = getattr(self, 'OID', None)
        if oid:
            _oidMatchingRuleObjects[oid] = self
        names = getattr(self, 'NAME', ())
        if isinstance(names, six.string_types):
            names = (names,)
        for name in names:
            _nameMatchingRuleObjects[name] = self
