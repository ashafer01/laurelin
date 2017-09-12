"""Implementations of RFC 4517: Syntaxes and Matching Rules

https://tools.ietf.org/html/rfc4517
"""

from __future__ import absolute_import

from . import rfc4512
from . import rfc4514
from . import rfc4518
from . import utils
from .exceptions import InvalidSyntaxError
from .rules import (
    SyntaxRule,
    RegexSyntaxRule,
    EqualityMatchingRule,
)
import re
import six
from six.moves import range

PrintableCharacter = r"[A-Za-z0-9'()+,.=/:? -]"
_PrintableString = PrintableCharacter + r'+'

_IA5String = r"[\x00-\x7f]*"
_BitString = r"'[01]*'B"


## Syntax Rules


class BitString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.6'
    DESC = 'Bit String'
    regex = utils.reAnchor(_BitString)


class Boolean(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.7'
    DESC = 'Boolean'

    def validate(self, s):
        if (s != 'TRUE' and s != 'FALSE'):
            raise InvalidSyntaxError('Not a valid {0}'.format(self.DESC))


class CountryString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.11'
    DESC = 'Country String'
    regex = r'^' + PrintableCharacter + r'{2}$'


class DeliveryMethod(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.14'
    DESC = 'Delivery Method'
    _pdm = r'(?:any|mhs|physical|telex|teletext|g3fax|g4fax|ia5|videotext|telephone)'
    regex = r'^' + _pdm + r'(\s*\$\s*' + _pdm + r')*$'


class DirectoryString(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.15'
    DESC = 'Directory String'

    def validate(self, s):
        if not isinstance(s, six.string_types) or (len(s) == 0):
            raise InvalidSyntaxError('Not a valid {0}'.format(self.DESC))

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


class EnhancedGuide(SyntaxRule):
    #3.3.10.  Enhanced Guide
    #
    #   A value of the Enhanced Guide syntax suggests criteria, which consist
    #   of combinations of attribute types and filter operators, to be used
    #   in constructing filters to search for entries of particular object
    #   classes.  The Enhanced Guide syntax improves upon the Guide syntax by
    #   allowing the recommended depth of the search to be specified.
    #
    #   The LDAP-specific encoding of a value of this syntax is defined by
    #   the following ABNF:
    #
    #      EnhancedGuide = object-class SHARP WSP criteria WSP
    #                         SHARP WSP subset
    #      object-class  = WSP oid WSP
    #      subset        = "baseobject" / "oneLevel" / "wholeSubtree"
    #
    #      criteria   = and-term *( BAR and-term )
    #      and-term   = term *( AMPERSAND term )
    #      term       = EXCLAIM term /
    #                   attributetype DOLLAR match-type /
    #                   LPAREN criteria RPAREN /
    #                   true /
    #                   false
    #      match-type = "EQ" / "SUBSTR" / "GE" / "LE" / "APPROX"
    #      true       = "?true"
    #      false      = "?false"
    #      BAR        = %x7C  ; vertical bar ("|")
    #      AMPERSAND  = %x26  ; ampersand ("&")
    #      EXCLAIM    = %x21  ; exclamation mark ("!")
    #
    #   The <SHARP>, <WSP>, <oid>, <LPAREN>, <RPAREN>, <attributetype>, and
    #   <DOLLAR> rules are defined in [RFC4512].
    #
    #   The LDAP definition for the Enhanced Guide syntax is:
    #
    #      ( 1.3.6.1.4.1.1466.115.121.1.21 DESC 'Enhanced Guide' )
    #
    #      Example:
    #         person#(sn$EQ)#oneLevel
    #
    #   The Enhanced Guide syntax corresponds to the EnhancedGuide ASN.1 type
    #   from [X.520].  The EnhancedGuide type references the Criteria ASN.1
    #   type, also from [X.520].  The <true> rule, above, represents an empty
    #   "and" expression in a value of the Criteria type.  The <false> rule,
    #   above, represents an empty "or" expression in a value of the Criteria
    #   type.

    OID = '1.3.6.1.4.1.1466.115.121.1.21'
    DESC = 'Enhanced Guide'


    def __init__(self):
        SyntaxRule.__init__(self)
        self._object_class = re.compile(EnhancedGuide._object_class)
        self._term = re.compile(EnhancedGuide._term)

    _term = (
        r'(?:' +
        rfc4512.oid + r'\$(?:EQ|SUBSTR|GE|LE|APPROX)' +
        r'|\?true|\?false)'
    )

    def _validate_criteria(self, criteria):
        term = ''
        i = 0
        while i < len(criteria):
            c = criteria[i]
            if c == '(':
                e = utils.findClosingParen(criteria[i:])
                pterm = criteria[i+1:i+e]
                self._validate_criteria(pterm)
                i += e+1
            elif c == '|' or c == '&':
                if term != '':
                    if not self._term.match(term):
                        raise InvalidSyntaxError('invalid term')
                    term = ''
                i += 1
            elif c == '!':
                i += 1
            else:
                term += c
                i += 1
        if term != '':
            if not self._term.match(term):
                raise InvalidSyntaxError('invalid term')
            term = ''

    _object_class = rfc4512.WSP + rfc4512.oid + rfc4512.WSP
    _subsets = ('baseobject', 'oneLevel', 'wholeSubtree')

    def validate(self, s):
        try:
            objectclass, criteria, subset = s.split('#')
        except ValueError:
            raise InvalidSyntaxError('Not a valid {0}'.format(self.DESC))
        if not self._object_class.match(objectclass):
            raise InvalidSyntaxError('Not a valid {0} - invalid object class'.format(self.DESC))
        subset = subset.strip()
        if subset not in self._subsets:
            raise InvalidSyntaxError('Not a valid {0} - invalid subset'.format(self.DESC))
        criteria = criteria.strip()
        self._validate_criteria(criteria)


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
            raise InvalidSyntaxError('Not a valid {0} - invalid phone number'.format(self.DESC))
        for param in params[1:]:
            if param not in self._fax_parameters:
                raise InvalidSyntaxError('Not a valid {0} - invalid parameter'.format(self.DESC))


class Fax(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.23'
    DESC = 'Fax'

    def validate(self, s):
        # The LDAP-specific encoding of a value of this syntax is the
        # string of octets for a Group 3 Fax image
        return


class GeneralizedTime(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.24'
    DESC = 'Generalized Time'
    regex = r'^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})?([0-9]{2})?([.,][0-9]+)?(Z|[+-]([0-9]{2})([0-9]{2})?)$'

    def validate(self, s):
        m = self.compiled_re.match(s)
        if not m:
            raise InvalidSyntaxError('Not a valid {0}'.format(self.DESC))
        else:
            month = int(m.group(2))
            if month < 1 or month > 12:
                raise InvalidSyntaxError('Not a valid {0} - invalid month'.format(self.DESC))

            day = int(m.group(3))
            if day < 1 or day > 31:
                raise InvalidSyntaxError('Not a valid {0} - invalid day'.format(self.DESC))

            hour = int(m.group(4))
            if hour < 0 or hour > 23:
                raise InvalidSyntaxError('Not a valid {0} - invalid hour'.format(self.DESC))

            minute = m.group(5)
            if minute is not None:
                minute = int(minute)
                if minute < 0 or minute > 59:
                    raise InvalidSyntaxError('Not a valid {0} - invalid minute'.format(self.DESC))

            second = m.group(6)
            if second is not None:
                second = int(second)
                if second < 0 or second > 60:
                    raise InvalidSyntaxError('Not a valid {0} - invalid second'.format(self.DESC))

            tz = m.group(8)
            if tz != 'Z':
                tzhour = int(m.group(9))
                if tzhour < 0 or tzhour > 23:
                    raise InvalidSyntaxError('Not a valid {0} - invalid timezone hour offset'.format(self.DESC))

                tzminute = m.group(10)
                if tzminute is not None:
                    tzminute = int(tzminute)
                    if tzminute < 0 or tzminute > 59:
                        raise InvalidSyntaxError('Not a valid {0} - invalid timezone minute offset'.format(self.DESC))

            return m


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
        return


class LDAPSyntaxDescription(RegexSyntaxRule):
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
    regex = r'^' + rfc4514.distinguishedName + r'(?:#' + _BitString + r')?'


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
        return


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
    regex = r'(?:' + _substring + r')?\*(?:' + _substring + r'\*)*(?:' + _substring + r')?'


class TelephoneNumber(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.50'
    DESC = 'Telephone Number'

    def validate(self, s):
        if not utils.validatePhoneNumber(s):
            raise InvalidSyntaxError('Not a valid {0}'.format(self.DESC))


class TelexNumber(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.52'
    DESC = 'Telex Number'
    regex = r'^' + _PrintableString + r'\$' + _PrintableString + r'\$' + _PrintableString + r'$'


## Matching Rules


caseExactPrepMethods = (
    rfc4518.Transcode,
    rfc4518.Map.characters,
    rfc4518.Normalize,
    rfc4518.Prohibit,
    rfc4518.Insignificant.space,
)

caseIgnorePrepMethods = (
    rfc4518.Transcode,
    rfc4518.Map.all,
    rfc4518.Normalize,
    rfc4518.Prohibit,
    rfc4518.Insignificant.space,
)

class bitStringMatch(EqualityMatchingRule):
    OID = '2.5.13.16'
    NAME = 'bitStringMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.6'


class booleanMatch(EqualityMatchingRule):
    OID = '2.5.13.13'
    NAME = 'booleanMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.7'


class caseExactIA5Match(EqualityMatchingRule):
    OID = '1.3.6.1.4.1.1466.109.114.1'
    NAME = 'caseExactIA5Match'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.26'
    prepMethods = caseExactPrepMethods


class caseExactMatch(EqualityMatchingRule):
    OID = '2.5.13.5'
    NAME = 'caseExactMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.15'
    prepMethods = caseExactPrepMethods


class caseIgnoreIA5Match(EqualityMatchingRule):
    OID = '1.3.6.1.4.1.1466.109.114.2'
    NAME = 'caseIgnoreIA5Match'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.26'
    prepMethods = caseIgnorePrepMethods


class caseIgnoreListMatch(EqualityMatchingRule):
    OID = '2.5.13.11'
    NAME = 'caseIgnoreListMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.4'
    prepMethods = caseIgnorePrepMethods


class caseIgnoreMatch(EqualityMatchingRule):
    OID = '2.5.13.2'
    NAME = 'caseIgnoreMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.15'
    prepMethods = caseIgnorePrepMethods


class directoryStringFirstComponentMatch(EqualityMatchingRule):
    OID = '2.5.13.31'
    NAME = 'directoryStringFirstComponentMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.15'


class distinguishedNameMatch(EqualityMatchingRule):
    OID = '2.5.13.1'
    NAME = 'distinguishedNameMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.12'

    def _parseDN(self, value):
        rdns = re.split(r'(?<!\\),', value)
        rdnDicts = []
        for rdn in rdns:
            rdnAVAs = re.split(r'(?<!\\)\+', rdn)
            rdnDict = {}
            for rdnAVA in rdnAVAs:
                attr, val = re.split(r'(?<!\\)=', rdnAVA)
                rdnDict[attr] = val
            rdnDicts.append(rdnDict)
        return rdnDicts

    def do_match(self, attributeValue, assertionValue):
        from .attributetype import getAttributeType
        attributeValue = self._parseDN(attributeValue)
        assertionValue = self._parseDN(assertionValue)
        if len(attributeValue) != len(assertionValue):
            return False
        try:
            for i in range(len(attributeValue)):
                attributeRDN = attributeValue[i]
                assertionRDN = assertionValue[i]
                for attr in attributeRDN:
                    attributeValue = attributeRDN[attr]
                    assertionValue = assertionRDN[attr]
                    if not getAttributeType(attr).match(attributeValue, assertionValue):
                        return False
            return True
        except Exception:
            return False


class generalizedTimeMatch(EqualityMatchingRule):
    OID = '2.5.13.27'
    NAME = 'generalizedTimeMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.24'

    def do_match(self, attributeValue, assertionValue):
        m = self.validate(assertionValue)
        # TODO
        return True


class integerFirstComponentMatch(EqualityMatchingRule):
    OID = '2.5.13.29'
    NAME = 'integerFirstComponentMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.27'


class integerMatch(EqualityMatchingRule):
    OID = '2.5.13.14'
    NAME = 'integerMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.27'


class numericStringMatch(EqualityMatchingRule):
    OID = '2.5.13.8'
    NAME = 'numericStringMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.36'
    prepMethods = (
        rfc4518.Transcode,
        rfc4518.Map.characters,
        rfc4518.Normalize,
        rfc4518.Prohibit,
        rfc4518.Insignificant.numericString,
    )


class objectIdentifierFirstComponentMatch(EqualityMatchingRule):
    OID = '2.5.13.30'
    NAME = 'objectIdentifierFirstComponentMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.38'


class objectIdentifierMatch(EqualityMatchingRule):
    OID = '2.5.13.0'
    NAME = 'objectIdentifierMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.38'


class octetStringMatch(EqualityMatchingRule):
    OID = '2.5.13.17'
    NAME = 'octetStringMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.40'


class telephoneNumberMatch(EqualityMatchingRule):
    OID = '2.5.13.20'
    NAME = 'telephoneNumberMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.50'
    prepMethods = (
        rfc4518.Transcode,
        rfc4518.Map.all,
        rfc4518.Normalize,
        rfc4518.Prohibit,
        rfc4518.Insignificant.telephoneNumber,
    )


class uniqueMemberMatch(EqualityMatchingRule):
    OID = '2.5.13.23'
    NAME = 'uniqueMemberMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.34'
