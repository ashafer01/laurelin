from rfc4511 import Scope as _Scope, DerefAliases as _DerefAliases

class Scope:
    BASE = _Scope('baseObject')
    ONELEVEL = _Scope('singleLevel')
    SUBTREE = _Scope('wholeSubtree')

class DerefAliases:
    NEVER = _DerefAliases('neverDerefAliases')
    SEARCH = _DerefAliases('derefInSearching')
    BASE = _DerefAliases('derefFindingBaseObj')
    ALWAYS = _DerefAliases('derefAlways')
