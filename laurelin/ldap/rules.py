"""Base classes for syntax rules and matching rules"""

from __future__ import absolute_import
from .exceptions import InvalidSyntaxError, LDAPSchemaError
from .utils import CaseIgnoreDict, get_obj_module
import re

## Syntax Rules

_oid_syntax_rules = {}
_oid_syntax_rule_objects = {}


def get_syntax_rule(oid):
    obj = _oid_syntax_rule_objects.get(oid)
    if not obj:
        obj = _oid_syntax_rules[oid]()
    return obj


class SyntaxRule(object):
    """Base class for all syntax rules"""

    OID = ''
    """The globally unique numeric OID of the syntax rule. Referenced in attribute type and matching rule specs. Must be
    defined by subclasses."""

    DESC = ''
    """Short text description of the rule. Must be defined by subclasses."""

    def __init__(self):
        if self.OID:
            if self.OID in _oid_syntax_rule_objects:
                raise LDAPSchemaError('Multiple instantiations of syntax rule with OID {0}'.format(self.OID))
            _oid_syntax_rule_objects[self.OID] = self

    @classmethod
    def register(cls):
        if cls.OID in _oid_syntax_rules:
            cur_class = _oid_syntax_rules[cls.OID].__name__
            cur_mod = get_obj_module(cur_class)
            new_class = cls.__name__
            new_mod = get_obj_module(new_class)
            raise LDAPSchemaError('Duplicate OID {0} in syntax rule declaration (original class {1}.{2}, '
                                  'new class {3}.{4})'.format(cls.OID, cur_mod, cur_class, new_mod, new_class))
        _oid_syntax_rules[cls.OID] = cls

    def validate(self, s):
        """Validate a string. Must be implemented by subclasses.

        :param s: Candidate string
        :return: Any useful value for the rule
        :raises InvalidSyntaxError: if the string is invalid
        """
        raise NotImplementedError()


class RegexSyntaxRule(SyntaxRule):
    """For validating rules based on a regular expression. Most syntax rules can inherit from this."""

    regex = r''
    """The regular expression defining the rule. Subclasses must define this attribute."""

    def __init__(self):
        self.compiled_re = re.compile(self.regex)
        SyntaxRule.__init__(self)

    def validate(self, s):
        """Validate a string against the regular expression.

        :param s: Candidate string
        :return: The regex match object
        :rtype: MatchObject
        :raises InvalidSyntaxError: if the string does not match
        """
        m = self.compiled_re.match(s)
        if m:
            return m
        else:
            raise InvalidSyntaxError('Not a valid {0}: {1}'.format(self.DESC, s))


## Matching Rules


_oid_matching_rules = {}
_name_matching_rules = CaseIgnoreDict()
_oid_matching_rule_objects = {}
_name_matching_rule_objects = CaseIgnoreDict()


def get_matching_rule(ident):
    """Obtains matching rule instance for name or OID"""
    if ident[0].isdigit():
        cls_dict = _oid_matching_rules
        obj_dict = _oid_matching_rule_objects
    else:
        cls_dict = _name_matching_rules
        obj_dict = _name_matching_rule_objects
    obj = obj_dict.get(ident)
    if not obj:
        obj = cls_dict[ident]()
    return obj


class MatchingRule(object):
    """Base class for all matching rules"""

    OID = ''
    """Globally unique numeric OID for the matching rule. This must be defined by subclasses."""

    NAME = ''
    """Globally unique name for the matching rule. Most attribute type specs will reference rules using the name, but
    they can also use the OID. This must be defined by subclasses."""

    SYNTAX = ''
    """The numeric OID for the syntax rule that assertion values must comply with. Subclasses must define this."""

    prep_methods = ()
    """A tuple of callables used to prepare attribute and asserion values. Subclasses may optionally define this."""

    def __init__(self):
        if self.OID:
            if self.OID in _oid_matching_rule_objects:
                raise LDAPSchemaError('Multiple instantiations of matching rule with OID {0}'.format(self.OID))
            _oid_matching_rule_objects[self.OID] = self
        if self.NAME:
            if self.NAME in _name_matching_rule_objects:
                raise LDAPSchemaError('Multiple instantiations of matching rule with name {0}'.format(self.NAME))
            _name_matching_rule_objects[self.NAME] = self

    @classmethod
    def register(cls):
        if cls.OID:
            if cls.OID in _oid_matching_rules:
                raise LDAPSchemaError('Duplicate OID {0} in matching rule declaration'.format(cls.OID))
            _oid_matching_rules[cls.OID] = cls
        if cls.NAME:
            if cls.NAME in _name_matching_rules:
                raise LDAPSchemaError('Duplicate name {0} in matching rule declaration'.format(cls.NAME))
            _name_matching_rules[cls.NAME] = cls

    def validate(self, value):
        """Perform validation according to the matching rule's syntax"""
        return get_syntax_rule(self.SYNTAX).validate(value)

    def prepare(self, value):
        """Prepare a string for matching"""
        for method in getattr(self, 'prep_methods', ()):
            value = method(value)
        return value

    def do_match(self, attribute_value, assertion_value):
        """Perform the match operation"""
        raise NotImplementedError()

    def match(self, attribute_value, assertion_value):
        """Prepare values and perform the match operation. Assumes values have
        already been validated.
        """
        attribute_value = self.prepare(attribute_value)
        assertion_value = self.prepare(assertion_value)
        return self.do_match(attribute_value, assertion_value)


# Note: currently only implementing equality matching rules since there is no
# use for ordering or substring matching rules for correct functioning of the
# current codebase. Any forseeable use for other types of rules would be in
# support of new features not currently planned.

class EqualityMatchingRule(MatchingRule):
    """Base class for all EQUALITY matching rules"""

    def do_match(self, attribute_value, assertion_value):
        """Perform equality matching"""
        return (attribute_value == assertion_value)
