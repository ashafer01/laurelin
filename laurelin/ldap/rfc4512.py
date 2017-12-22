"""Translations of ABNF specs to regex from RFC 4512

https://tools.ietf.org/html/rfc4512
"""

from __future__ import absolute_import

ALPHA = r'[A-Za-z]'
DIGIT = r'[0-9]'
HEX = r'[0-9A-Fa-f]'

SP = r' +'
WSP = r' *'

keychar = r'[A-Za-z0-9-]' # ALPHA / DIGIT / HYPHEN
keystring = ALPHA + keychar + r'*'

numericoid = DIGIT + r'+(?:\.' + DIGIT + r'+)+'
descr = keystring
oid = r'(?:' + descr + r'|' + numericoid + r')'

qdescr = r"'" + descr + r"'"
qdescrlist = qdescr + r'(?:' + SP + qdescr + r')*'
qdescrs = r'(?:' + qdescr + r'|\(' + WSP + qdescrlist + WSP + r'\))'

QQ = r'\\27'
QS = r'\\5[Cc]'
QUTF8 = r"[^'\\]"

dstring = r'(?:' + QS + r'|' + QQ + r'|' + QUTF8 + r')+'
qdstring = r"'" + dstring + r"'"
qdstringlist = qdstring + r'(?:' + SP + qdstring + r')*'
qdstrings = r'(?:' + qdstring + r'|\(' + WSP + qdstringlist + WSP + r'\))'

oidlist = oid + r'(?:' + WSP + r'\$' + WSP + oid + r')*'
oids = r'(?:' + oid + r'|\(' + WSP + oidlist + WSP + r'\))'

noidlen = numericoid + r'(\{[0-9]+\})?'

xstring = r'(?:X-[A-Za-z_-]+)'
extensions = r'(?P<extensions> ' + xstring + r' ' + qdstrings + r')?'

ObjectClassDescription = (
    r'\(' + WSP +
    r'(?P<oid>' + numericoid + r')' +
    r'(?:' + SP + r'NAME' + SP + r'(?P<name>' + qdescrs + r'))?' +
    r'(?:' + SP + r'DESC' + SP + r'(?P<desc>' + qdstring + r'))?' +
    r'(?P<obsolete>' + SP + r'OBSOLETE)?' +
    r'(?:' + SP + r'SUP' + SP + r'(?P<superclass>' + oids + r'))?' +
    r'(?:' + SP + r'(?P<kind>ABSTRACT|STRUCTURAL|AUXILIARY))?' +
    r'(?:' + SP + r'MUST' + SP + r'(?P<must>' + oids + r'))?' +
    r'(?:' + SP + r'MAY' + SP + r'(?P<may>' + oids + r'))?' +
    extensions + WSP + r'\)'
)

AttributeTypeDescription = (
    r'\(' + WSP +
    r'(?P<oid>' + numericoid + r')' +
    r'(?:' + SP + r'NAME' + SP + r'(?P<name>' + qdescrs + r'))?' +
    r'(?:' + SP + r'DESC' + SP + r'(?P<desc>' + qdstring + r'))?' +
    r'(?P<obsolete>' + SP + r'OBSOLETE)?' +
    r'(?:' + SP + r'SUP' + SP + r'(?P<supertype>' + oid + r'))?' +
    r'(?:' + SP + r'EQUALITY' + SP + r'(?P<equality>' + oid + r'))?' +
    r'(?:' + SP + r'ORDERING' + SP + r'(?P<ordering>' + oid + r'))?' +
    r'(?:' + SP + r'SUBSTR' + SP + r'(?P<substr>' + oid + r'))?' +
    r'(?:' + SP + r'SYNTAX' + SP + r'(?P<syntax>' + noidlen + r'))?' +
    r'(?P<single_value>' + SP + r'SINGLE-VALUE)?' +
    r'(?P<collective>' + SP + r'COLLECTIVE)?' +
    r'(?P<no_user_mod>' + SP + r'NO-USER-MODIFICATION)?' +
    r'(?:' + SP + r'USAGE' + SP + r'(?P<usage>userApplications|directoryOperation|distributedOperation|dSAOperation))?' +
    extensions + WSP + r'\)'
)

MatchingRuleDescription = (
    r'\(' + WSP +
    r'(?P<oid>' + numericoid + r')' +
    r'(?:' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(?:' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(?:' + SP + r'OBSOLETE)?' +
    r'(?:' + SP + r'SYNTAX' + SP + oids + r')' +
    extensions + WSP + r'\)'
)

MatchingRuleUseDescription = (
    r'\(' + WSP +
    r'(?P<oid>' + numericoid + r')' +
    r'(?:' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(?:' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(?:' + SP + r'OBSOLETE)?' +
    r'(?:' + SP + r'APPLIES' + SP + oids + r')' +
    extensions + WSP + r'\)'
)

SyntaxDescription = (
    r'\(' + WSP +
    r'(?P<oid>' + numericoid + r')' +
    r'(?:' + SP + r'DESC' + SP + qdstring + r')?' +
    extensions + WSP + r'\)'
)

DITContentRuleDescription = (
    r'\(' + WSP +
    r'(?P<oid>' + numericoid + r')' +
    r'(?:' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(?:' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(?:' + SP + r'OBSOLETE' + SP + r')?' +
    r'(?:' + SP + r'AUX' + SP + oids + r')?' +
    r'(?:' + SP + r'MUST' + SP + oids + r')?' +
    r'(?:' + SP + r'NOT' + SP + oids + r')?' +
    extensions + WSP + r'\)'
)

ruleid = r'[0-9]+'
ruleidlist = ruleid + r'(?:' + SP + ruleid + r')*'
ruleids = r'(?:' + ruleid + r'|\(' + WSP + ruleidlist + WSP + r'\))'

DITStructureRuleDescription = (
    r'\(' + WSP +
    r'(?:' + ruleid +  r')' +
    r'(?:' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(?:' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(?:' + SP + r'OBSOLETE' + SP + r')?' +
    r'(?:' + SP + r'FORM' + SP + oid + r')' +
    r'(?:' + SP + r'SUP' + SP + ruleids + r')?' +
    extensions + WSP + r'\)'
)

NameFormDescription = (
    r'\(' +  WSP +
    r'(?:' + numericoid + r')' +
    r'(?:' + SP + r'NAME' + SP + qdescrs + r')?' +
    r'(?:' + SP + r'DESC' + SP + qdstring + r')?' +
    r'(?:' + SP + r'OBSOLETE)?' +
    r'(?:' + SP + r'OC' + SP + oid + r')' +
    r'(?:' + SP + r'MUST' + SP + oids + r')' +
    r'(?:' + SP + r'MAY' + SP + oids + r')?' +
    extensions + WSP + r'\)'
)
