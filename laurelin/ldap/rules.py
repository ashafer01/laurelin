"""Base classes for syntax rules and matching rules"""

from __future__ import absolute_import
import re
import six


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
        m = self.compiled_re.match(s)
        if m:
            return m
        else:
            raise InvalidSyntaxError('Not a valid {0}'.format(self.DESC))


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
        for name in names:
            _nameMatchingRuleObjects[name] = self

    def validate(self, value):
        return getSyntaxRule(self.SYNTAX).validate(value)

    def prepare(self, value):
        for method in getattr(self, 'prepMethods', ()):
            value = method(value)
        return value


# Note: currently only implementing equality matching rules since there is no
# use for ordering or substring matching rules for correct functioning of the
# current codebase. Any forseeable use for other types of rules would be in
# support of new features not currently planned.

class EqualityMatchingRule(MatchingRule):
    def match(self, attributeValue, assertionValue):
        self.validate(assertionValue)
        attributeValue = self.prepare(attributeValue)
        assertionValue = self.prepare(assertionValue)
        return (attributeValue == assertionValue)
