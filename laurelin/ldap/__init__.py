"""Imports and defines the core of the public API"""

from __future__ import absolute_import
from .attributetype import get_attribute_type, AttributeType
from .base import LDAP, LDAPURI
from .constants import Scope, DerefAliases, DELETE_ALL, FilterSyntax
from .controls import Control, critical, optional
from .exceptions import LDAPError, NoSearchResults, Abandon
from .extensible import (
    extensions,
    add_extension,
    BaseLaurelinExtension,
    BaseLaurelinSchema,
    BaseLaurelinControls,
    BaseLaurelinLDAPExtension,
    BaseLaurelinLDAPObjectExtension,
    LaurelinTransiter,
    LaurelinRegistrar,
)
from .filter import escape as filter_escape
from .ldapobject import LDAPObject
from .modify import Mod
from .objectclass import get_object_class, ObjectClass, ExtensibleObjectClass
from .rules import SyntaxRule, RegexSyntaxRule, MatchingRule, EqualityMatchingRule
from .schema import SchemaValidator
from .validation import Validator

import pyasn1.type.univ


def dc(domain):
    """Convert a DNS dotted domain name to a DN with domain components"""
    return ','.join(['dc={0}'.format(dc) for dc in domain.split('.')])


def domain(dc):
    """Convert a DN with domain components to a DNS dotted domain name"""
    return '.'.join([i.split('=')[1] for i in dc.split(',')])


__all__ = [
    'get_attribute_type',
    'AttributeType',
    'LDAP',
    'LDAPURI',
    'Scope',
    'DerefAliases',
    'DELETE_ALL',
    'FilterSyntax',
    'Control',
    'critical',
    'optional',
    'LDAPError',
    'NoSearchResults',
    'Abandon',
    'extensions',
    'add_extension',
    'BaseLaurelinExtension',
    'BaseLaurelinSchema',
    'BaseLaurelinControls',
    'BaseLaurelinLDAPExtension',
    'BaseLaurelinLDAPObjectExtension',
    'LaurelinTransiter',
    'LaurelinRegistrar',
    'filter_escape',
    'LDAPObject',
    'Mod',
    'get_object_class',
    'ObjectClass',
    'ExtensibleObjectClass',
    'SyntaxRule',
    'RegexSyntaxRule',
    'MatchingRule',
    'EqualityMatchingRule',
    'Validator',
    'SchemaValidator',
    'dc',
    'domain',
]


# make pyasn1 enumerated repr() consistant

def _enum_repr(enum_obj):
    try:
        intval = int(enum_obj)
        name = enum_obj.namedValues.getName(intval)
        namerepr = repr(name)
    except Exception:
        namerepr = '<schema object>'
    return '{0}({1})'.format(enum_obj.__class__.__name__, namerepr)


pyasn1.type.univ.Enumerated.__repr__ = _enum_repr
