"""Global constant classes."""

from __future__ import absolute_import
from .rfc4511 import (
    Scope as _Scope,
    DerefAliases as _DerefAliases,
)

_const_filter_syntax_standard = '__rfc4515_standard_filter_syntax__'
_const_filter_syntax_simple = '__laurelin_simplified_filter_syntax__'
_const_filter_syntax_unified = '__laurelin_unified_filter_syntax__'


class _FilterSyntaxSelection(object):
    def __init__(self, const):
        self.const = const

    def __repr__(self):
        if self.const == _const_filter_syntax_simple:
            return 'FilterSyntax.SIMPLE'
        elif self.const == _const_filter_syntax_standard:
            return 'FilterSyntax.STANDARD'
        elif self.const == _const_filter_syntax_unified:
            return 'FilterSyntax.UNIFIED'
        else:
            return repr(self.const)


class FilterSyntax:
    """Filter syntax selection constants. Used to determine which filter syntax to use when parsing a search filter."""
    STANDARD = _FilterSyntaxSelection(_const_filter_syntax_standard)
    SIMPLE = _FilterSyntaxSelection(_const_filter_syntax_simple)
    UNIFIED = _FilterSyntaxSelection(_const_filter_syntax_unified)

    @staticmethod
    def string(str):
        """Convert filter syntax string to constant"""
        str = str.upper()
        return getattr(FilterSyntax, str)


class _DeleteAllAttrs(object):
    """Sentinel object used to delete all attributes in replace or delete"""
    def __bool__(self):
        return False

    def __nonzero__(self):
        return False

    def __len__(self):
        return 0

    def __repr__(self):
        return '<delete all values>'


DELETE_ALL = _DeleteAllAttrs()


class Scope:
    """Scope constants. These instruct the server how far to take a search, relative to the base object"""

    BASE = _Scope('baseObject')
    """Only search the base object"""

    ONELEVEL = _Scope('singleLevel')
    ONE = ONELEVEL
    """Search the base object and its immediate children"""

    SUBTREE = _Scope('wholeSubtree')
    SUB = SUBTREE
    """Search the base object and all of its dscendants"""

    @staticmethod
    def string(str):
        """translate RFC4516 URL scope strings to constant"""
        str = str.lower()
        if str == 'base':
            return Scope.BASE
        elif str == 'one':
            return Scope.ONELEVEL
        elif str == 'sub':
            return Scope.SUBTREE
        else:
            raise ValueError()

    @staticmethod
    def constant(c):
        """translate constants to RFC4516 URL scope string"""
        if c == Scope.BASE:
            return 'base'
        elif c == Scope.ONE:
            return 'one'
        elif c == Scope.SUB:
            return 'sub'
        else:
            raise ValueError()


def _scope_repr(scope_obj):
    """Uses laurelin constant name representation for scope"""
    try:
        intval = int(scope_obj)
        name = scope_obj.namedValues.getName(intval)
        if name == 'wholeSubtree':
            return 'Scope.SUB'
        elif name == 'singleLevel':
            return 'Scope.ONE'
        elif name == 'baseObject':
            return 'Scope.BASE'
        else:
            return '{0}({1})'.format(scope_obj.__class__.__name__, repr(name))
    except Exception:
        return '{0}(<schema object>)'.format(scope_obj.__class__.__name__)


_Scope.__repr__ = _scope_repr


class DerefAliases:
    """DerefAliases constants. These instruct the server when to automatically resolve an alias object, rather than
       return the alias object itself
    """

    NEVER = _DerefAliases('neverDerefAliases')
    """always return the alias object"""

    SEARCH = _DerefAliases('derefInSearching')
    """dereferences search results, but not the base object itself"""

    BASE = _DerefAliases('derefFindingBaseObj')
    """dereferences the search base object, but not search results"""

    ALWAYS = _DerefAliases('derefAlways')
    """dereferences both the search base object and results"""


def _deref_repr(deref_obj):
    """Uses laurelin constant name representation for deref aliases"""
    try:
        intval = int(deref_obj)
        name = deref_obj.namedValues.getName(intval)
        if name == 'neverDerefAliases':
            return 'DerefAliases.NEVER'
        elif name == 'derefInSearching':
            return 'DerefAliases.SEARCH'
        elif name == 'derefFindingBaseObj':
            return 'DerefAliases.BASE'
        elif name == 'derefAlways':
            return 'DerefAliases.ALWAYS'
        else:
            return '{0}({1})'.format(deref_obj.__class__.__name__, repr(name))
    except Exception:
        return '{0}(<schema object>)'.format(deref_obj.__class__.__name__)


_DerefAliases.__repr__ = _deref_repr
