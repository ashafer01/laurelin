##
## ldap.filter
## 
## Filter parser

from rfc4511 import Filter, FilterSet, AttributeValueAssertion, AttributeDescription, AssertionValue, SubstringFilter, AttributeDescription

def findClosingParen(text):
    if text[0] != '(':
        raise ValueError()
    parens = 1
    i = 0
    while parens > 0:
        i+= 1
        if text[i] == '(':
            parens += 1
        elif text[i] == ')':
            parens -= 1
    return i

def parseFilterSet(filterStr):
    fset = FilterSet()
    i = 0
    while len(filterStr) > 0:
        end = findClosingParen(filterStr)+1
        fset.setComponentByPosition(i, parseFilter(filterStr[0:end]))
        filterStr = filterStr[end:]
        i += 1
    return fset

def parseFilter(filterStr):
    fil = Filter()
    chunk = filterStr[1:findClosingParen(filterStr)]
    if chunk[0] == '&':
        fil.setComponentByName('and', parseFilterSet(chunk[1:]))
    elif chunk[0] == '|':
        fil.setComponentByName('or', parseFilterSet(chunk[1:]))
    elif chunk[0] == '!':
        fil.setComponentByName('not', parseFilter(chunk[1:]))
    else:
        attr, val = chunk.split('=', 1)
        if attr[-1] == '>':
            ava = AttributeValueAssertion()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr[0:-1]))
            ava.setComponentByName('assertionValue', AttributeValue(val))
            fil.setComponentByName('greaterOrEqual', ava)
        elif attr[-1] == '<':
            ava = AttributeValueAssertion()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr[0:-1]))
            ava.setComponentByName('assertionValue', AttributeValue(val))
            fil.setComponentByName('lessOrEqual', ava)
        elif attr[-1] == '~':
            ava = AttributeValueAssertion()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr[0:-1]))
            ava.setComponentByName('assertionValue', AttributeValue(val))
            fil.setComponentByName('approxMatch', ava)
        elif val == '*':
            fil.setComponentByName('present', AttributeDescription(attr))
        elif '*' in val:
            # substrings
            pass
        else:
            ava = AttributeValueAssertion()
            ava.setComponentByName('attributeDesc', AttributeDescription(attr))
            ava.setComponentByName('assertionValue', AttributeValue(val))
            fil.setComponentByName('equalityMatch', ava)
    return fil
