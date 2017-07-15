"""Implementations of various constructs defined on RFC 4512

https://tools.ietf.org/html/rfc4512
"""

from __future__ import absolute_import

## Translations from spec ABNF to regex

ALPHA = r'[A-Za-z]'
DIGIT = r'[0-9]'
HEX = r'[0-9A-Fa-f]'

SP = r' +'
WSP = r' *'

keychar = r'[A-Za-z0-9-]' # ALPHA / DIGIT / HYPHEN
keystring = ALPHA + keychar + r'*'

numericoid = DIGIT + r'+(\.' + DIGIT + r'+)+'
descr = keystring
oid = r'(' + descr + r'|' + numericoid + r')'

qdescr = r"'" + descr + r"'"
qdescrlist = qdescr + r'(' + SP + qdescr + r')*'
qdescrs = r'(' + qdescr + r'|\(' + WSP + qdescrlist + WSP + r'\))'

QQ = r'\\27'
QS = r'\\5[Cc]'
QUTF8 = r"[^'\\]"

dstring = r'(' + QS + r'|' + QQ + r'|' + QUTF8 + r')+'
qdstring = r"'" + dstring + r"'"
qdstringlist = qdstring + r'(' + SP + qdstring + r')*'
qdstrings = r'(' + qdstring + r'|\(' + WSP + qdstringlist + WSP + r'\))'

oidlist = oid + r'(' + WSP + r'\$' + WSP + oid + r')*'
oids = r'(' + oid + r'|\(' + WSP + oidlist + WSP + r'\))'

noidlen = numericoid + r'(\{[0-9]+\})?'

AttributeTypeDescription = (
    r'\(' + WSP +
    r'(' + numericoid + r')' +
    r'(' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(' + SP + r'OBSOLETE)?' +
    r'(' + SP + r'SUP' + SP + oid + r')?' +
    r'(' + SP + r'EQUALITY' + SP + oid + r')?' +
    r'(' + SP + r'ORDERING' + SP + oid + r')?' +
    r'(' + SP + r'SUBSTR' + SP + oid + r')?' +
    r'(' + SP + r'SYNTAX' + SP + noidlen + r')?' +
    r'(' + SP + r'SINGLE-VALUE)?' +
    r'(' + SP + r'COLLECTIVE)?' +
    r'(' + SP + r'NO-USER-MODIFICATION)?' +
    r'(' + SP + r'USAGE' + SP + r'(userApplications|directoryOperation|distributedOperation|dSAOperation))?' +
    WSP + r'\)' # TODO extensions
)

MatchingRuleDescription = (
    r'\(' + WSP +
    r'(' + numericoid + r')' +
    r'(' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(' + SP + r'OBSOLETE)?' +
    r'(' + SP + r'SYNTAX' + SP + oids + r')' +
    WSP + r'\)' # TODO extensions
)

MatchingRuleUseDescription = (
    r'\(' + WSP +
    r'(' + numericoid + r')' +
    r'(' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(' + SP + r'OBSOLETE)?' +
    r'(' + SP + r'APPLIES' + SP + oids + r')' +
    WSP + r'\)' # TODO extensions
)

SyntaxDescription = (
    r'\(' + WSP +
    r'(' + numericoid + r')' +
    r'(' + SP + r'DESC' + SP + qdstring + r')?' +
    WSP + r'\)' # TODO extensions
)

DITContentRuleDescription = (
    r'\(' + WSP +
    r'(' + numericoid + r')' +
    r'(' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(' + SP + r'OBSOLETE' + SP + r')?' +
    r'(' + SP + r'AUX' + SP + oids + r')?' +
    r'(' + SP + r'MUST' + SP + oids + r')?' +
    r'(' + SP + r'NOT' + SP + oids + r')?' +
    WSP + r'\)' # TODO extensions
)

ruleid = r'[0-9]+'
ruleidlist = ruleid + r'(' + SP + ruleid + r')*'
ruleids = r'(' + ruleid + r'|\(' + WSP + ruleidlist + WSP + r'\))'

DITStructureRuleDescription = (
    r'\(' + WSP +
    r'(' + ruleid +  r')' +
    r'(' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(' + SP + r'OBSOLETE' + SP + r')?' +
    r'(' + SP + r'FORM' + SP + oid + r')' +
    r'(' + SP + r'SUP' + SP + ruleids + r')?' +
    WSP + r'\)' # TODO extensions
)

NameFormDescription = (
    r'\(' +  WSP +
    r'(' + numericoid + r')' +
    r'(' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(' + SP + r'OBSOLETE)?' +
    r'(' + SP + r'OC' + SP + oid + r')' +
    r'(' + SP + r'MUST' + SP + oids + r')' +
    r'(' + SP + 'MAY' + SP + oids + r')?' +
    WSP + r'\)' # TODO extensions
)

ObjectClassDescription = (
    r'\(' + WSP +
    r'(' + numericoid + r')' +
    r'(' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(' + SP + r'OBSOLETE)?' +
    r'(' + SP + r'SUP' + SP + oids + r')?' +
    r'(' + SP + r'(ABSTRACT|STRUCTURAL|AUXILIARY))?' +
    r'(' + SP + r'MUST' + SP + oids + r')?' +
    r'(' + SP + r'MAY' + SP + oids + r')?' +
    WSP + r'\)' # TODO extensions
)
