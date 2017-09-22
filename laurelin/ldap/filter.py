"""Contains utilities for handling filters"""

from __future__ import absolute_import
from .rfc4511 import (
    Filter,
    And,
    Or,
    Not,
    EqualityMatch,
    SubstringFilter,
    GreaterOrEqual,
    LessOrEqual,
    Present,
    ApproxMatch,
    AttributeValue,
    AttributeDescription,
    Substrings,
    Substring,
    AssertionValue,
    Initial,
    Any,
    Final,
    ExtensibleMatch,
    MatchValue,
    MatchingRuleId,
    DnAttributes,
)
from .exceptions import LDAPError
from .utils import findClosingParen

escapeMap = [
    ('(', '\\28'),
    (')', '\\29'),
    ('&', '\\26'),
    ('|', '\\7c'),
    ('!', '\\21'),
    ('=', '\\3d'),
    ('<', '\\3c'),
    ('>', '\\3e'),
    ('~', '\\7e'),
    ('*', '\\2a'),
    ('/', '\\2f')
]
def escape(text):
    """Escape special characters"""
    for rep in escapeMap:
        text = text.replace(*rep)
    return text

def parse(filterStr):
    """Parse a filter string to a protocol-level object"""

    fil = Filter()
    chunk = filterStr[1:findClosingParen(filterStr)]
    if chunk[0] == '&':
        fil.setComponentByName('and', _parseSet(chunk[1:], And))
    elif chunk[0] == '|':
        fil.setComponentByName('or', _parseSet(chunk[1:], Or))
    elif chunk[0] == '!':
        notFilter = Not()
        notFilter.setComponentByName('innerNotFilter', parse(chunk[1:]))
        fil.setComponentByName('not', notFilter)
    else:
        attr, val = chunk.split('=', 1)
        if attr[-1] == '>':
            ava = GreaterOrEqual()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr[0:-1].strip()))
            ava.setComponentByName('assertionValue', AssertionValue(val))
            fil.setComponentByName('greaterOrEqual', ava)
        elif attr[-1] == '<':
            ava = LessOrEqual()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr[0:-1].strip()))
            ava.setComponentByName('assertionValue', AssertionValue(val))
            fil.setComponentByName('lessOrEqual', ava)
        elif attr[-1] == '~':
            ava = ApproxMatch()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr[0:-1].strip()))
            ava.setComponentByName('assertionValue', AssertionValue(val))
            fil.setComponentByName('approxMatch', ava)
        elif attr[-1] == ':':
            # 1
            # attr:=value
            # 2
            # attr:dn:=value
            # attr:rule:=value
            # :rule:=value
            # 3
            # attr:dn:rule:=value
            # :dn:rule:=value

            params = attr[0:-1].split(':')
            n = len(params)

            attr = None
            dnattrs = False
            rule = None

            if n == 1:
                attr = params[0]
            elif n == 2:
                attr = params[0]
                if params[1] == 'dn':
                    dnattrs = True
                else:
                    rule = params[1]
            elif n == 3:
                if params[1] != 'dn':
                    raise LDAPError('invalid extensible filter')
                dnattrs = True
                attr = params[0]
                rule = params[2]
            else:
                raise LDAPError('invalid extensible filter')

            xm = ExtensibleMatch()
            xm.setComponentByName('matchValue', MatchValue(val))
            xm.setComponentByName('dnAttributes', DnAttributes(dnattrs))
            if attr:
                xm.setComponentByName('type', AttributeDescription(attr))
            if rule:
                xm.setComponentByName('matchingRule', MatchingRuleId(rule))
            fil.setComponentByName('extensibleMatch', xm)
        elif val.strip() == '*':
            fil.setComponentByName('present', Present(attr))
        elif '*' in val:
            subf = SubstringFilter()
            subf.setComponentByName('type', AttributeDescription(attr.strip()))
            subs = Substrings()
            sublist = val.split('*')
            p = 0
            i = 0
            if sublist[0] != '':
                # do initial substring
                c = Substring()
                c.setComponentByName('initial', Initial(sublist[0]))
                subs.setComponentByPosition(p, c)
                i += 1
                p += 1
            else:
                i += 1
            # do middle substrings
            while i < len(sublist)-1:
                if sublist[i] != '':
                    c = Substring()
                    c.setComponentByName('any', Any(sublist[i]))
                    subs.setComponentByPosition(p, c)
                    p += 1
                i += 1
            if sublist[i] != '':
                # do final substring
                c = Substring()
                c.setComponentByName('final', Final(sublist[i]))
                subs.setComponentByPosition(p, c)
            subf.setComponentByName('substrings', subs)
            fil.setComponentByName('substrings', subf)
        else:
            ava = EqualityMatch()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr.strip()))
            ava.setComponentByName('assertionValue', AttributeValue(val))
            fil.setComponentByName('equalityMatch', ava)
    return fil

def _parseSet(filterStr, cls):
    fset = cls()
    i = 0
    while len(filterStr) > 0:
        end = findClosingParen(filterStr)+1
        fset.setComponentByPosition(i, parse(filterStr[0:end]))
        filterStr = filterStr[end:]
        i += 1
    return fset
