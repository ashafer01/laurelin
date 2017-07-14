"""Implementations of RFC 4517: Syntaxes and Matching Rules

https://tools.ietf.org/html/rfc4517
"""

from __future__ import absolute_import

from . import rfc4512
from .utils import reAnchor
import re
import six

PrintableCharacter = r"[A-Za-z0-9'()+,.=/:? -]"
PrintableString = PrintableCharacter + r'+'
IA5String = r"[\x00-\x7f]*"

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

    def validate(self, s):
        return bool(self.compiled_re.validate(s))


class BitString(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.6'
    DESC = 'Bit String'
    regex = r"^'[01]*'B$"


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
        return (len(s) > 0)

class DITContentRuleDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.16'
    DESC = 'DIT Content Rule Description'
    regex = reAnchor(rfc4512.DITContentRuleDescription)


class DITStructureRuleDescription(RegexSyntaxRule):
    OID = '1.3.6.1.4.1.1466.115.121.1.17'
    DESC = 'DIT Structure Rule Description'
    regex = reAnchor(rfc4512.DITStructureRuleDescription)
