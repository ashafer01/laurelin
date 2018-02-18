"""Contains utilities for handling filters.

See RFC4515 String Representation of Search Filters
"""

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
    MatchingRule,
    DnAttributes,
    Type,
)
from .exceptions import LDAPError
from .utils import find_closing_paren

escape_map = [
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
    for rep in escape_map:
        text = text.replace(*rep)
    return text


def parse(filter_str):
    """Parse a filter string to a protocol-level object"""

    fil = Filter()
    try:
        chunk = filter_str[1:find_closing_paren(filter_str)]
    except ValueError as e:
        raise LDAPError('invalid filter - {0}'.format(str(e)))
    if chunk[0] == '&':
        fil.setComponentByName('and', _parse_set(chunk[1:], And))
    elif chunk[0] == '|':
        fil.setComponentByName('or', _parse_set(chunk[1:], Or))
    elif chunk[0] == '!':
        not_filter = Not()
        not_filter.setComponentByName('innerNotFilter', parse(chunk[1:]))
        fil.setComponentByName('not', not_filter)
    else:
        try:
            attr, val = chunk.split('=', 1)
        except ValueError:
            raise LDAPError('Invalid filter - missing =')
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
                xm.setComponentByName('type', Type(attr))
            if rule:
                xm.setComponentByName('matchingRule', MatchingRule(rule))
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


def _parse_set(filter_str, cls):
    fset = cls()
    i = 0
    while len(filter_str) > 0:
        end = find_closing_paren(filter_str) + 1
        fset.setComponentByPosition(i, parse(filter_str[0:end]))
        filter_str = filter_str[end:]
        i += 1
    return fset
