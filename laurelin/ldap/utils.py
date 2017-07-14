import re

def reAnchor(r):
    return r'^' + r + r'$'

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

def validatePhoneNumber(s):
    """Perform simplistic phone number validation"""

    # strip out non-digit and non-plus characters
    s = re.sub('[^0-9+]', s)

    # remove leading +
    if s.startswith('+'):
        s = s[1:]

    # Should only have numbers now
    if not s.isdigit():
        return False

    # Check length
    l = len(s)
    return (l >= 7 and l <= 15)
