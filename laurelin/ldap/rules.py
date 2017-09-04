"""Base classes for syntax rules and matching rules"""

from __future__ import absolute_import
from .exceptions import InvalidSyntaxError, LDAPSchemaError
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
            if oid in _oidSyntaxRules:
                raise LDAPSchemaError('Duplicate OID in syntax rule declaration')
            _oidSyntaxRules[oid] = cls
        return cls


@six.add_metaclass(MetaSyntaxRule)
class SyntaxRule(object):
    """Base class for all syntax rules"""
    def __init__(self):
        oid = getattr(self, 'OID', None)
        if oid:
            if oid in _oidSyntaxRuleObjects:
                raise LDAPSchemaError('Multiple instantiations of syntax rule with OID {0}'.format(oid))
            _oidSyntaxRuleObjects[oid] = self

    def validate(self, s):
        raise NotImplementedError()


class RegexSyntaxRule(SyntaxRule):
    """For validating rules based on a regular expression
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
            if oid in _oidMatchingRules:
                raise LDAPSchemaError('Duplicate OID {0} in matching rule declaration'.format(oid))
            _oidMatchingRules[oid] = cls
        for name in names:
            if name in _nameMatchingRules:
                raise LDAPSchemaError('Duplicate name {0} in matching rule declaration'.format(name))
            _nameMatchingRules[name] = cls
        return cls


@six.add_metaclass(MetaMatchingRule)
class MatchingRule(object):
    """Base class for all matching rules"""

    def __init__(self):
        oid = getattr(self, 'OID', None)
        if oid:
            if oid in _oidMatchingRuleObjects:
                raise LDAPSchemaError('Multiple instantiations of matching rule with OID {0}'.format(oid))
            _oidMatchingRuleObjects[oid] = self
        names = getattr(self, 'NAME', ())
        for name in names:
            if name in _nameMatchingRuleObjects:
                raise LDAPSchemaError('Multiple instantiations of matching rule with name {0}'.format(name))
            _nameMatchingRuleObjects[name] = self

    def validate(self, value):
        """Perform validation according to the matching rule's syntax"""
        return getSyntaxRule(self.SYNTAX).validate(value)

    def prepare(self, value):
        """Prepare a string for matching"""
        for method in getattr(self, 'prepMethods', ()):
            value = method(value)
        return value

    def do_match(self, attributeValue, assertionValue):
        """Perform the match operation"""
        raise NotImplementedError()

    def match(self, attributeValue, assertionValue):
        """Prepare values and perform the match operation. Assumes values have
         already been validated.
        """
        attributeValue = self.prepare(attributeValue)
        assertionValue = self.prepare(assertionValue)
        return self.do_match(attributeValue, assertionValue)


# Note: currently only implementing equality matching rules since there is no
# use for ordering or substring matching rules for correct functioning of the
# current codebase. Any forseeable use for other types of rules would be in
# support of new features not currently planned.

class EqualityMatchingRule(MatchingRule):
    """Base class for all EQUALITY matching rules"""

    def do_match(self, attributeValue, assertionValue):
        """Perform equality matching"""
        return (attributeValue == assertionValue)
