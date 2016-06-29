from rfc4511 import Scope as _Scope, DerefAliases as _DerefAliases

class Scope:
    BASE = _Scope('baseObject')
    ONELEVEL = _Scope('singleLevel')
    SUBTREE = _Scope('wholeSubtree')

    # translate RFC4516 URL scope strings to constant
    @staticmethod
    def string(str):
        if str == 'base':
            return Scope.BASE
        elif str == 'one':
            return Scope.ONELEVEL
        elif str == 'sub':
            return Scope.SUBTREE
        else:
            raise ValueError()

class DerefAliases:
    NEVER = _DerefAliases('neverDerefAliases')
    SEARCH = _DerefAliases('derefInSearching')
    BASE = _DerefAliases('derefFindingBaseObj')
    ALWAYS = _DerefAliases('derefAlways')

class LDAPError(Exception):
    pass
