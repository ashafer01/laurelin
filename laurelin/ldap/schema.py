"""Schema specifications from various RFCs"""

from __future__ import absolute_import
from . import rfc4512
from . import rfc4514
from . import rfc4518
from . import utils
from .exceptions import LDAPValidationError, LDAPWarning, InvalidSyntaxError
from .rules import (
    SyntaxRule,
    RegexSyntaxRule,
    EqualityMatchingRule,
)
from .attributetype import get_attribute_type, AttributeType
from .objectclass import get_object_class, ObjectClass, ExtensibleObjectClass
from .validation import Validator

import re
import six
from six.moves import range
from warnings import warn


class SchemaValidator(Validator):
    """Ensures parameters conform to the available defined schema"""

    def validate_object(self, obj, write=True):
        """Validates an object when all attributes are present

         * Requires the objectClass attribute
         * Checks that all attributes required by the objectClass are defined
         * Checks that all attributes are allowed by the objectClass
         * Performs validation against the attribute type spec for all attributes
        """
        try:
            object_classes = obj['objectClass']
        except KeyError:
            raise LDAPValidationError('missing objectClass')
        required_attrs = set()
        allowed_attrs = set()
        for oc_name in object_classes:
            oc = get_object_class(oc_name)
            required_attrs.update(oc.must)
            allowed_attrs.update(oc.may)
        disallowed_attrs = []
        for attr in obj.keys():
            if attr in required_attrs:
                required_attrs.remove(attr)
            elif attr in allowed_attrs:
                pass
            else:
                disallowed_attrs.append(attr)
        if required_attrs:
            missing_required = ','.join(required_attrs)
            oc_names = ','.join(object_classes)
            raise LDAPValidationError('missing attributes {0} required by objectClasses {1}'.format(
                                      missing_required, oc_names))
        if disallowed_attrs:
            disallowed_attrs = ','.join(disallowed_attrs)
            oc_names = ','.join(object_classes)
            raise LDAPValidationError('attributes {0} are not permitted with objectClasses {1}'.format(
                                      disallowed_attrs, oc_names))
        Validator.validate_object(self, obj, write)

    def _validate_attribute(self, attr_name, values, write):
        attr = get_attribute_type(attr_name)
        if attr.obsolete:
            warn('Attribute {0} is obsolete'.format(attr_name), LDAPWarning)
        if attr.single_value and len(values) > 1:
            raise LDAPValidationError('Multiple values for single-value attribute {0}'.format(attr_name))
        if write and attr.no_user_mod:
            raise LDAPValidationError('Attribute {0} is not user modifiable'.format(attr_name))
        for value in values:
            attr.validate(value)

## RFC 2252 Syntaxes


class Binary(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.5'
    DESC = 'Binary'

    def validate(self, s):
        if not isinstance(s, six.binary_type):
            raise InvalidSyntaxError('Must be binary type')


class Certificate(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.8'
    DESC = 'Certificate'

    def validate(self, s):
        if not isinstance(s, six.binary_type):
            raise InvalidSyntaxError('Must be binary type')


## RFC 4517 Syntaxes and Matching Rules


PrintableCharacter = r"[A-Za-z0-9'()+,.=/:? -]"
_PrintableString = PrintableCharacter + r'+'

_IA5String = r"[\x00-\x7f]*"
_BitString = r"'[01]*'B"


## Syntax Rules


class AttributeTypeDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.3'
    DESC = 'Attribute Type Description'
    regex = utils.re_anchor(rfc4512.AttributeTypeDescription)


class BitString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.6'
    DESC = 'Bit String'
    regex = utils.re_anchor(_BitString)


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
    regex = utils.re_anchor(rfc4512.DITContentRuleDescription)


class DITStructureRuleDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.17'
    DESC = 'DIT Structure Rule Description'
    regex = utils.re_anchor(rfc4512.DITStructureRuleDescription)


class DistinguishedName(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.12'
    DESC = 'DN'
    regex = utils.re_anchor(rfc4514.distinguishedName)


class EnhancedGuide(SyntaxRule):
    # 3.3.10.  Enhanced Guide
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
                e = utils.find_closing_paren(criteria[i:])
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
        if not utils.validate_phone_number(params[0]):
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


class Guide(EnhancedGuide):
    OID = '1.3.6.1.4.1.1466.115.121.1.25'
    DESC = 'Guide'

    def validate(self, s):
        try:
            objectclass, criteria = s.split('#')
        except ValueError:
            raise InvalidSyntaxError('Not a valid {0}'.format(self.DESC))
        if not self._object_class.match(objectclass):
            raise InvalidSyntaxError('Not a valid {0} - invalid object class'.format(self.DESC))
        criteria = criteria.strip()
        self._validate_criteria(criteria)


class IA5String(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.26'
    DESC = 'IA5 String'
    regex = utils.re_anchor(_IA5String)


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
        if not isinstance(s, six.binary_type):
            raise InvalidSyntaxError('Must be binary')
        if s[6:10] != b'JFIF':  # adapted from imghdr source
            raise InvalidSyntaxError('not a JFIF-encoded image ')


class LDAPSyntaxDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.54'
    DESC = 'LDAP Syntax Description'
    regex = utils.re_anchor(rfc4512.SyntaxDescription)


class MatchingRuleDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.30'
    DESC = 'Matching Rule Description'
    regex = utils.re_anchor(rfc4512.MatchingRuleDescription)


class MatchingRuleUseDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.31'
    DESC = 'Matching Rule Use Description'
    regex = utils.re_anchor(rfc4512.MatchingRuleUseDescription)


class NameAndOptionalUID(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.34'
    DESC = 'Name And Optional UID'
    regex = r'^' + rfc4514.distinguishedName + r'(?:#' + _BitString + r')?'


class NameFormDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.35'
    DESC = 'Name Form Description'
    regex = utils.re_anchor(rfc4512.NameFormDescription)


class NumericString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.36'
    DESC = 'Numeric String'
    regex = r'^[0-9 ]+$'


class ObjectClassDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.37'
    DESC = 'Object Class Description'
    regex = utils.re_anchor(rfc4512.ObjectClassDescription)


class OctetString(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.40'
    DESC = 'Octet String'

    def validate(self, s):
        # Any arbitrary sequence of octets
        return


class OID(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.38'
    DESC = 'OID'
    regex = utils.re_anchor(rfc4512.oid)


class OtherMailbox(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.39'
    DESC = 'Other Mailbox'
    regex = r'^' + _PrintableString + r'\$' + _IA5String + r'$'


class PostalAddress(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.41'
    DESC = 'Postal Address'

    _line_char = utils.escaped_regex('\\$')
    _line = _line_char + r'+'
    regex = r'^' + _line + r'(\$' + _line + r')*$'


class PrintableString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.44'
    DESC = 'Printable String'
    regex = utils.re_anchor(_PrintableString)


class SubstringAssertion(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.58'
    DESC = 'Substring Assertion'

    _substring_character = utils.escaped_regex('\\*')
    _substring = _substring_character + r'+'
    regex = r'(?:' + _substring + r')?\*(?:' + _substring + r'\*)*(?:' + _substring + r')?'


class TelephoneNumber(SyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.50'
    DESC = 'Telephone Number'

    def validate(self, s):
        if not utils.validate_phone_number(s):
            raise InvalidSyntaxError('Not a valid {0}'.format(self.DESC))


class TeletextTerminalIdentifier(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.51'
    DESC = 'Teletex Terminal Identifier'

    _ttx_value = r'(?:[\x00-\x23]|\x5c24|\x5c5C)*'
    _ttx_key = r'(?:graphic|control|misc|page|private)'
    _ttx_param = _ttx_key + r':' + _ttx_value

    regex = utils.re_anchor(_PrintableString + r'(?:\$' + _ttx_param + r')*')


class TelexNumber(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.52'
    DESC = 'Telex Number'
    regex = r'^' + _PrintableString + r'\$' + _PrintableString + r'\$' + _PrintableString + r'$'


## Matching Rules


case_exact_prep_methods = (
    rfc4518.Transcode,
    rfc4518.Map.characters,
    rfc4518.Normalize,
    rfc4518.Prohibit,
    rfc4518.Insignificant.space,
)

case_ignore_prep_methods = (
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
    prep_methods = case_exact_prep_methods


class caseExactMatch(EqualityMatchingRule):
    OID = '2.5.13.5'
    NAME = 'caseExactMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.15'
    prep_methods = case_exact_prep_methods


class caseIgnoreIA5Match(EqualityMatchingRule):
    OID = '1.3.6.1.4.1.1466.109.114.2'
    NAME = 'caseIgnoreIA5Match'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.26'
    prep_methods = case_ignore_prep_methods


class caseIgnoreListMatch(EqualityMatchingRule):
    OID = '2.5.13.11'
    NAME = 'caseIgnoreListMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.41'
    prep_methods = case_ignore_prep_methods


class caseIgnoreMatch(EqualityMatchingRule):
    OID = '2.5.13.2'
    NAME = 'caseIgnoreMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.15'
    prep_methods = case_ignore_prep_methods


class directoryStringFirstComponentMatch(EqualityMatchingRule):
    OID = '2.5.13.31'
    NAME = 'directoryStringFirstComponentMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.15'


class distinguishedNameMatch(EqualityMatchingRule):
    OID = '2.5.13.1'
    NAME = 'distinguishedNameMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.12'

    def _parse_dn(self, value):
        rdns = re.split(r'(?<!\\),', value)
        rdn_dicts = []
        for rdn in rdns:
            rdn_avas = re.split(r'(?<!\\)\+', rdn)
            rdn_dict = {}
            for rdn_ava in rdn_avas:
                attr, val = re.split(r'(?<!\\)=', rdn_ava)
                rdn_dict[attr] = val
            rdn_dicts.append(rdn_dict)
        return rdn_dicts

    def do_match(self, attribute_value, assertion_value):
        from .attributetype import get_attribute_type
        attribute_value = self._parse_dn(attribute_value)
        assertion_value = self._parse_dn(assertion_value)
        if len(attribute_value) != len(assertion_value):
            return False
        try:
            for i in range(len(attribute_value)):
                attribute_rdn = attribute_value[i]
                assertion_rdn = assertion_value[i]
                for attr in attribute_rdn:
                    attribute_value = attribute_rdn[attr]
                    assertion_value = assertion_rdn[attr]
                    if not get_attribute_type(attr).match(attribute_value, assertion_value):
                        return False
            return True
        except Exception:
            return False


class generalizedTimeMatch(EqualityMatchingRule):
    OID = '2.5.13.27'
    NAME = 'generalizedTimeMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.24'

    def do_match(self, attribute_value, assertion_value):
        m = self.validate(assertion_value)
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
    prep_methods = (
        rfc4518.Transcode,
        rfc4518.Map.characters,
        rfc4518.Normalize,
        rfc4518.Prohibit,
        rfc4518.Insignificant.numeric_string,
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
    prep_methods = (
        rfc4518.Transcode,
        rfc4518.Map.all,
        rfc4518.Normalize,
        rfc4518.Prohibit,
        rfc4518.Insignificant.telephone_number,
    )


class uniqueMemberMatch(EqualityMatchingRule):
    OID = '2.5.13.23'
    NAME = 'uniqueMemberMatch'
    SYNTAX = '1.3.6.1.4.1.1466.115.121.1.34'


## RFC 4512 2.4.1 Abstract Object Classes


ObjectClass("""( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )""")


## RFC 4512 2.6 Alias Entries


ObjectClass("""
      ( 2.5.6.1 NAME 'alias'
        SUP top STRUCTURAL
        MUST aliasedObjectName )
""")

AttributeType("""
      ( 2.5.4.1 NAME 'aliasedObjectName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE )
""")


## RFC 4512 Section 3 - Administrative/Operational


AttributeType("""
      ( 2.5.4.0 NAME 'objectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
""")


AttributeType("""
      ( 2.5.18.3 NAME 'creatorsName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.18.1 NAME 'createTimestamp'
        EQUALITY generalizedTimeMatch
        ORDERING generalizedTimeOrderingMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.18.4 NAME 'modifiersName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.18.2 NAME 'modifyTimestamp'
        EQUALITY generalizedTimeMatch
        ORDERING generalizedTimeOrderingMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.9 NAME 'structuralObjectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.10 NAME 'governingStructureRule'
        EQUALITY integerMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")


## RFC 4512 4.2 Subschema Subentries


AttributeType("""
      ( 2.5.18.10 NAME 'subschemaSubentry'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

ObjectClass("""
      ( 2.5.20.1 NAME 'subschema' AUXILIARY
        MAY ( dITStructureRules $ nameForms $ ditContentRules $
          objectClasses $ attributeTypes $ matchingRules $
          matchingRuleUse ) )

""")

AttributeType("""
      ( 2.5.21.6 NAME 'objectClasses'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.37
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.5 NAME 'attributeTypes'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.3
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.4 NAME 'matchingRules'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.30
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.8 NAME 'matchingRuleUse'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.31
        USAGE directoryOperation )
""")

AttributeType("""
      ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.54
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.2 NAME 'dITContentRules'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.16
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.1 NAME 'dITStructureRules'
        EQUALITY integerFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.17
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.7 NAME 'nameForms'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.35
        USAGE directoryOperation )
""")


## RFC 4512 4.3 extensibleObject


ExtensibleObjectClass("""
      ( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject'
              SUP top AUXILIARY )
""")


## RFC 4512 5.1 Root DSE Attributes
## Note: equality rules in this section are NOT a part of the spec


AttributeType("""
      ( 1.3.6.1.4.1.1466.101.120.6 NAME 'altServer'
        EQUALITY caseExactMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
        USAGE dSAOperation )
""")

AttributeType("""
      ( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        USAGE dSAOperation )
""")

AttributeType("""
      ( 1.3.6.1.4.1.1466.101.120.13 NAME 'supportedControl'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
        USAGE dSAOperation )
""")

AttributeType("""
      ( 1.3.6.1.4.1.1466.101.120.7 NAME 'supportedExtension'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
        USAGE dSAOperation )
""")

AttributeType("""
      ( 1.3.6.1.4.1.4203.1.3.5 NAME 'supportedFeatures'
          EQUALITY objectIdentifierMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
          USAGE dSAOperation )
""")

AttributeType("""
      ( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion'
        EQUALITY integerMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
        USAGE dSAOperation )
""")

AttributeType("""
      ( 1.3.6.1.4.1.1466.101.120.14 NAME 'supportedSASLMechanisms'
        EQUALITY caseIgnoreMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
        USAGE dSAOperation )
""")


## RFC 4519 Attribute Types


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
      ( 2.5.4.14 NAME 'searchGuide'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.25 )
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
      ( 2.5.4.22 NAME 'teletexTerminalIdentifier'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.51 )
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


## RFC 4519 Object Classes


ObjectClass("""
      ( 2.5.6.11 NAME 'applicationProcess'
         SUP top
         STRUCTURAL
         MUST cn
         MAY ( seeAlso $
               ou $
               l $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.2 NAME 'country'
         SUP top
         STRUCTURAL
         MUST c
         MAY ( searchGuide $
               description ) )
""")

ObjectClass("""
      ( 1.3.6.1.4.1.1466.344 NAME 'dcObject'
         SUP top
         AUXILIARY
         MUST dc )
""")

ObjectClass("""
      ( 2.5.6.14 NAME 'device'
         SUP top
         STRUCTURAL
         MUST cn
         MAY ( serialNumber $
               seeAlso $
               owner $
               ou $
               o $
               l $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.9 NAME 'groupOfNames'
         SUP top
         STRUCTURAL
         MUST ( member $
               cn )
         MAY ( businessCategory $
               seeAlso $
               owner $
               ou $
               o $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.17 NAME 'groupOfUniqueNames'
         SUP top
         STRUCTURAL
         MUST ( uniqueMember $
               cn )
         MAY ( businessCategory $
               seeAlso $
               owner $
               ou $
               o $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.3 NAME 'locality'
         SUP top
         STRUCTURAL
         MAY ( street $
               seeAlso $
               searchGuide $
               st $
               l $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.4 NAME 'organization'
         SUP top
         STRUCTURAL
         MUST o
         MAY ( userPassword $ searchGuide $ seeAlso $
               businessCategory $ x121Address $ registeredAddress $
               destinationIndicator $ preferredDeliveryMethod $
               telexNumber $ teletexTerminalIdentifier $
               telephoneNumber $ internationalISDNNumber $
               facsimileTelephoneNumber $ street $ postOfficeBox $
               postalCode $ postalAddress $ physicalDeliveryOfficeName $
               st $ l $ description ) )
""")

ObjectClass("""
      ( 2.5.6.7 NAME 'organizationalPerson'
         SUP person
         STRUCTURAL
         MAY ( title $ x121Address $ registeredAddress $
               destinationIndicator $ preferredDeliveryMethod $
               telexNumber $ teletexTerminalIdentifier $
               telephoneNumber $ internationalISDNNumber $
               facsimileTelephoneNumber $ street $ postOfficeBox $
               postalCode $ postalAddress $ physicalDeliveryOfficeName $
               ou $ st $ l ) )
""")

ObjectClass("""
      ( 2.5.6.8 NAME 'organizationalRole'
         SUP top
         STRUCTURAL
         MUST cn
         MAY ( x121Address $ registeredAddress $ destinationIndicator $
               preferredDeliveryMethod $ telexNumber $
               teletexTerminalIdentifier $ telephoneNumber $
               internationalISDNNumber $ facsimileTelephoneNumber $
               seeAlso $ roleOccupant $ preferredDeliveryMethod $
               street $ postOfficeBox $ postalCode $ postalAddress $
               physicalDeliveryOfficeName $ ou $ st $ l $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.5 NAME 'organizationalUnit'
         SUP top
         STRUCTURAL
         MUST ou
         MAY ( businessCategory $ description $ destinationIndicator $
               facsimileTelephoneNumber $ internationalISDNNumber $ l $
               physicalDeliveryOfficeName $ postalAddress $ postalCode $
               postOfficeBox $ preferredDeliveryMethod $
               registeredAddress $ searchGuide $ seeAlso $ st $ street $
               telephoneNumber $ teletexTerminalIdentifier $
               telexNumber $ userPassword $ x121Address ) )
""")

ObjectClass("""
      ( 2.5.6.6 NAME 'person'
         SUP top
         STRUCTURAL
         MUST ( sn $
               cn )
         MAY ( userPassword $
               telephoneNumber $
               seeAlso $ description ) )
""")

ObjectClass("""
      ( 2.5.6.10 NAME 'residentialPerson'
         SUP person
         STRUCTURAL
         MUST l
         MAY ( businessCategory $ x121Address $ registeredAddress $
               destinationIndicator $ preferredDeliveryMethod $
               telexNumber $ teletexTerminalIdentifier $
               telephoneNumber $ internationalISDNNumber $
               facsimileTelephoneNumber $ preferredDeliveryMethod $
               street $ postOfficeBox $ postalCode $ postalAddress $
               physicalDeliveryOfficeName $ st $ l ) )
""")

ObjectClass("""
      ( 1.3.6.1.1.3.1 NAME 'uidObject'
         SUP top
         AUXILIARY
         MUST uid )
""")

## RFC 2798 inetOrgPerson - Attribute Types

AttributeType("""
    ( 2.16.840.1.113730.3.1.1 NAME 'carLicense'
      DESC 'vehicle license or registration plate'
      EQUALITY caseIgnoreMatch
      SUBSTR caseIgnoreSubstringsMatch
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
    ( 2.16.840.1.113730.3.1.2
      NAME 'departmentNumber'
      DESC 'identifies a department within an organization'
      EQUALITY caseIgnoreMatch
      SUBSTR caseIgnoreSubstringsMatch
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
  ( 2.16.840.1.113730.3.1.241
    NAME 'displayName'
    DESC 'preferred name of a person to be used when displaying entries'
    EQUALITY caseIgnoreMatch
    SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE )
""")

AttributeType("""
    ( 2.16.840.1.113730.3.1.3
      NAME 'employeeNumber'
      DESC 'numerically identifies an employee within an organization'
      EQUALITY caseIgnoreMatch
      SUBSTR caseIgnoreSubstringsMatch
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
      SINGLE-VALUE )
""")

AttributeType("""
    ( 2.16.840.1.113730.3.1.4
      NAME 'employeeType'
      DESC 'type of employment for a person'
      EQUALITY caseIgnoreMatch
      SUBSTR caseIgnoreSubstringsMatch
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
    ( 0.9.2342.19200300.100.1.60
      NAME 'jpegPhoto'
      DESC 'a JPEG image'
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.28 )
""")

AttributeType("""
    ( 2.16.840.1.113730.3.1.39
      NAME 'preferredLanguage'
      DESC 'preferred written or spoken language for a person'
      EQUALITY caseIgnoreMatch
      SUBSTR caseIgnoreSubstringsMatch
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
      SINGLE-VALUE )
""")

AttributeType("""
    ( 2.16.840.1.113730.3.1.40
      NAME 'userSMIMECertificate'
      DESC 'PKCS#7 SignedData used to support S/MIME'
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 )
""")

AttributeType("""
( 2.16.840.1.113730.3.1.216
  NAME 'userPKCS12'
  DESC 'PKCS #12 PFX PDU for exchange of personal identity information'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 )
""")

## RFC 2798 inetOrgPerson - Object Class

ObjectClass("""
( 2.16.840.1.113730.3.2.2
    NAME 'inetOrgPerson'
    SUP organizationalPerson
    STRUCTURAL
    MUST (
        cn $ objectClass $ sn
    )
    MAY (
        audio $ businessCategory $ carLicense $ departmentNumber $
        displayName $ employeeNumber $ employeeType $ givenName $
        homePhone $ homePostalAddress $ initials $ jpegPhoto $
        labeledURI $ mail $ manager $ mobile $ o $ pager $
        photo $ roomNumber $ secretary $ uid $ userCertificate $
        x500uniqueIdentifier $ preferredLanguage $
        userSMIMECertificate $ userPKCS12 $
        description $ destinationIndicator $ facsimileTelephoneNumber $
        internationaliSDNNumber $ l $ ou $ physicalDeliveryOfficeName $
        postalAddress $ postalCode $ postOfficeBox $
        preferredDeliveryMethod $ registeredAddress $ seeAlso $
        st $ street $ telephoneNumber $ teletexTerminalIdentifier $
        telexNumber $ title $ userPassword $ x121Address
    )
)
""")

## RFC 2256 Attribute Types via RFC 2798 sec 9.1.2

AttributeType("""
    ( 2.5.4.36
      NAME 'userCertificate'
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )
""")

## RFC 1274 Attribute Types via RFC 2798 sec 9.1.3

AttributeType("""
    ( 0.9.2342.19200300.100.1.55
      NAME 'audio'
      EQUALITY octetStringMatch
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{250000} )
""")

# Note: EQUALITY and SYNTAX in the photo spec are non-standard

AttributeType("""
    ( 0.9.2342.19200300.100.1.7
      NAME 'photo'
      EQUALITY octetStringMatch
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 )
""")

## RFC 2079 Attribute Types via RFC 2798 sec 9.1.4

AttributeType("""
    ( 1.3.6.1.4.1.250.1.57
      NAME 'labeledURI'
      EQUALITY caseExactMatch
      SUBSTR caseExactSubstringsMatch
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

## RFC 4524 Attribute Types

AttributeType("""
      ( 0.9.2342.19200300.100.1.37 NAME 'associatedDomain'
        EQUALITY caseIgnoreIA5Match
        SUBSTR caseIgnoreIA5SubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.38 NAME 'associatedName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.48 NAME 'buildingName'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.43 NAME 'co'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.14 NAME 'documentAuthor'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.11 NAME 'documentIdentifier'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.15 NAME 'documentLocation'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.56 NAME 'documentPublisher'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.12 NAME 'documentTitle'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.13 NAME 'documentVersion'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.5 NAME 'drink'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.20 NAME 'homePhone'
        EQUALITY telephoneNumberMatch
        SUBSTR telephoneNumberSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.39 NAME 'homePostalAddress'
        EQUALITY caseIgnoreListMatch
        SUBSTR caseIgnoreListSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.9 NAME 'host'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.4 NAME 'info'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{2048} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.3 NAME 'mail'
        EQUALITY caseIgnoreIA5Match
        SUBSTR caseIgnoreIA5SubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.10 NAME 'manager'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.41 NAME 'mobile'
        EQUALITY telephoneNumberMatch
        SUBSTR telephoneNumberSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.45 NAME 'organizationalStatus'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.42 NAME 'pager'
        EQUALITY telephoneNumberMatch
        SUBSTR telephoneNumberSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.40 NAME 'personalTitle'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.6 NAME 'roomNumber'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.21 NAME 'secretary'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.44 NAME 'uniqueIdentifier'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.8 NAME 'userClass'
        EQUALITY caseIgnoreMatch
        SUBSTR caseIgnoreSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
""")

## RFC 4524 Object Classes

ObjectClass("""
      ( 0.9.2342.19200300.100.4.5 NAME 'account'
        SUP top STRUCTURAL
        MUST uid
        MAY ( description $ seeAlso $ l $ o $ ou $ host ) )
""")

ObjectClass("""
      ( 0.9.2342.19200300.100.4.6 NAME 'document'
        SUP top STRUCTURAL
        MUST documentIdentifier
        MAY ( cn $ description $ seeAlso $ l $ o $ ou $
          documentTitle $ documentVersion $ documentAuthor $
          documentLocation $ documentPublisher ) )
""")

ObjectClass("""
      ( 0.9.2342.19200300.100.4.9 NAME 'documentSeries'
        SUP top STRUCTURAL
        MUST cn
        MAY ( description $ l $ o $ ou $ seeAlso $
          telephonenumber ) )
""")

ObjectClass("""
      ( 0.9.2342.19200300.100.4.13 NAME 'domain'
        SUP top STRUCTURAL
        MUST dc
        MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $
          x121Address $ registeredAddress $ destinationIndicator $
          preferredDeliveryMethod $ telexNumber $
          teletexTerminalIdentifier $ telephoneNumber $
          internationaliSDNNumber $ facsimileTelephoneNumber $ street $
          postOfficeBox $ postalCode $ postalAddress $
          physicalDeliveryOfficeName $ st $ l $ description $ o $
          associatedName ) )
""")

ObjectClass("""
      ( 0.9.2342.19200300.100.4.17 NAME 'domainRelatedObject'
        SUP top AUXILIARY
        MUST associatedDomain )
""")

ObjectClass("""
      ( 0.9.2342.19200300.100.4.18 NAME 'friendlyCountry'
        SUP country STRUCTURAL
        MUST co )
""")

ObjectClass("""
      ( 0.9.2342.19200300.100.4.14 NAME 'rFC822localPart'
        SUP domain STRUCTURAL
        MAY ( cn $ description $ destinationIndicator $
          facsimileTelephoneNumber $ internationaliSDNNumber $
          physicalDeliveryOfficeName $ postalAddress $ postalCode $
          postOfficeBox $ preferredDeliveryMethod $ registeredAddress $
          seeAlso $ sn $ street $ telephoneNumber $
          teletexTerminalIdentifier $ telexNumber $ x121Address ) )
""")

ObjectClass("""
      ( 0.9.2342.19200300.100.4.7 NAME 'room'
        SUP top STRUCTURAL
        MUST cn
        MAY ( roomNumber $ description $ seeAlso $ telephoneNumber ) )
""")

ObjectClass("""
      ( 0.9.2342.19200300.100.4.19 NAME 'simpleSecurityObject'
        SUP top AUXILIARY
        MUST userPassword )
""")
