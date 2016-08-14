##
## ldap.filter
## 
## Filter parser

from rfc4511 import (
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
    ExtensibleMatch,
    AttributeValue,
    AttributeDescription,
    Substrings,
    Substring,
    AssertionValue,
    Initial,
    Any,
    Final,
)

def findClosingParen(text):
    if text[0] != '(':
        raise ValueError()
    parens = 1
    i = 0
    while parens > 0:
        i += 1
        if text[i] == '(':
            parens += 1
        elif text[i] == ')':
            parens -= 1
    return i

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
    for rep in escapeMap:
        text = text.replace(*rep)
    return text

def parseSet(filterStr, cls):
    fset = cls()
    i = 0
    while len(filterStr) > 0:
        end = findClosingParen(filterStr)+1
        fset.setComponentByPosition(i, parse(filterStr[0:end]))
        filterStr = filterStr[end:]
        i += 1
    return fset

def parse(filterStr):
    fil = Filter()
    chunk = filterStr[1:findClosingParen(filterStr)]
    if chunk[0] == '&':
        fil.setComponentByName('and', parseSet(chunk[1:], And))
    elif chunk[0] == '|':
        fil.setComponentByName('or', parseSet(chunk[1:], Or))
    elif chunk[0] == '!':
        notFilter = Not()
        notFilter.setComponentByName('innerNotFilter', parse(chunk[1:]))
        fil.setComponentByName('not', notFilter)
    else:
        attr, val = chunk.split('=', 1)
        if attr[-1] == '>':
            ava = GreaterOrEqual()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr[0:-1]))
            ava.setComponentByName('assertionValue', AssertionValue(val))
            fil.setComponentByName('greaterOrEqual', ava)
        elif attr[-1] == '<':
            ava = LessOrEqual()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr[0:-1]))
            ava.setComponentByName('assertionValue', AssertionValue(val))
            fil.setComponentByName('lessOrEqual', ava)
        elif attr[-1] == '~':
            ava = ApproxMatch()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr[0:-1]))
            ava.setComponentByName('assertionValue', AssertionValue(val))
            fil.setComponentByName('approxMatch', ava)
        elif val == '*':
            fil.setComponentByName('present', Present(attr))
        elif '*' in val:
            subf = SubstringFilter()
            subf.setComponentByName('type', AttributeDescription(attr))
            subs = Substrings()
            sublist = val.split('*')
            if sublist[0] != '':
                c = Substring()
                c.setComponentByName('initial', Initial(sublist[0]))
                subs.setComponentByPosition(0, c)
            if sublist[-1] != '':
                c = Substring()
                c.setComponentByName('final', Final(sublist[-1]))
                subs.setComponentByPosition(len(sublist)-1, c)
            i = 1
            while i < len(sublist)-1:
                c = Substring()
                c.setComponentByName('any', Any(sublist[i]))
                subs.setComponentByPosition(i, c)
                i += 1
            subf.setComponentByName('substrings', subs)
            fil.setComponentByName('substrings', subf)
        else:
            ava = EqualityMatch()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr))
            ava.setComponentByName('assertionValue', AttributeValue(val))
            fil.setComponentByName('equalityMatch', ava)
    return fil
