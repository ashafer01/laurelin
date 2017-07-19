import re

try:
    str.casefold
    def casefold(value):
        return value.casefold()
except AttributeError:
    from py2casefold import casefold

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
    s = re.sub('[^0-9+]', '', s)

    # remove leading +
    if s.startswith('+'):
        s = s[1:]

    # Should only have numbers now
    if not s.isdigit():
        return False

    # Check length
    l = len(s)
    return (l >= 7 and l <= 15)

def collapseWhitespace(s):
    """Collapse all whitespace sequences down to a single space"""
    return re.sub('\s+', ' ', s).strip()

def _anyCase(m):
    """For use with re.sub

     Convert a single-character lower-cased regex match to a character class
     with both cases
    """
    return '[{0}{1}]'.format(m.group(0), m.group(0).upper())

def escapedRegex(escapeChars):
    """
     Convert a series of characters to a regular expression that requires LDAP
     hex escapes or any single character excluding escapeChars

     Result will be a parenthesized subpattern that can be repeated to form a
     larger string.
    """

    # ensure no duplicate characters
    escapeChars = ''.join(set(escapeChars))

    try:
        # move dash to end for use in character class
        di = escapeChars.index('-')
        escapeChars = escapeChars[0:di] + escapeChars[di+1:] + '-'
    except ValueError:
        # no dash
        pass

    # build hex-escape subpatterns
    subpatterns = []
    for c in escapeChars:
        code = hex(ord(c))
        if len(code) > 4:
            # only single-byte characters will ever need escaping in LDAP
            # multi-byte escapes probably not even supported
            raise ValueError('Character "{0}" does not need escaping'.format(c))

        # strip leading 0x
        code = code[2:]

        # zero-pad if necessary
        if len(code) == 1:
            code = '0' + code

        # make it an LDAP hex escape
        code = r'\\' + code

        # allow upper/lower cased alpha characters - hex() produces in lower
        code = re.sub('[a-f]', _anyCase, code)

        subpatterns.append(code)

    # add final character class excluding escapeChars
    try:
        # double any backslash present
        bi = escapeChars.index('\\')
        escapeChars = escapeChars[0:bi] + '\\' + escapeChars[bi:]
    except ValueError:
        # no backslash
        pass
    subpatterns.append('[^{0}]'.format(escapeChars))

    return '({0})'.format('|'.join(subpatterns))


def parseQdescrs(spec):
    """Parse an rfc4512.qdescrs to a tuple"""
    if spec is None:
        return ()
    return tuple(qdescr.strip("'") for qdescr in spec.strip('( )').split(' '))
