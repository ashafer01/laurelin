from __future__ import absolute_import
from .rfc4511 import (
    Scope as _Scope,
    DerefAliases as _DerefAliases,
)

class Scope:
    """Scope constants

     These instruct the server how far to take a search, relative to the base object
     * Scope.BASE - only search the base object
     * Scope.ONE  - search the base object and its immediate children
     * Scope.SUB  - search the base object and all of its descendants
    """

    BASE = _Scope('baseObject')
    ONELEVEL = _Scope('singleLevel')
    ONE = ONELEVEL
    SUBTREE = _Scope('wholeSubtree')
    SUB = SUBTREE

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


class DerefAliases:
    """DerefAliases constants

     These instruct the server when to automatically resolve an alias object, rather than return the
     alias object itself
     * DerefAliases.NEVER  - always return the alias object
     * DerefAliases.SEARCH - dereferences search results, but not the base object itself
     * DerefAliases.BASE   - dereferences the search base object, but not search results
     * DerefAliases.ALWAYS - dereferences both the search base object and results
    """

    NEVER = _DerefAliases('neverDerefAliases')
    SEARCH = _DerefAliases('derefInSearching')
    BASE = _DerefAliases('derefFindingBaseObj')
    ALWAYS = _DerefAliases('derefAlways')
