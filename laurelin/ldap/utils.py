import re

try:
    str.casefold

    def casefold(value):
        return value.casefold()
except AttributeError:
    from py2casefold import casefold


def re_anchor(r):
    return r'^' + r + r'$'


def find_closing_paren(text):
    if text[0] != '(':
        raise ValueError('missing opening paren')
    parens = 1
    i = 0
    try:
        while parens > 0:
            i += 1
            if text[i] == '(':
                parens += 1
            elif text[i] == ')':
                parens -= 1
    except IndexError:
        raise ValueError('missing closing paren')
    return i


def validate_phone_number(s):
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


def collapse_whitespace(s):
    """Collapse all whitespace sequences down to a single space"""
    return re.sub('\s+', ' ', s).strip()


def _any_case(m):
    """For use with re.sub

     Convert a single-character lower-cased regex match to a character class
     with both cases
    """
    return '[{0}{1}]'.format(m.group(0), m.group(0).upper())


def escaped_regex(escape_chars):
    """
     Convert a series of characters to a regular expression that requires LDAP
     hex escapes or any single character excluding escape_chars

     Result will be a parenthesized subpattern that can be repeated to form a
     larger string.
    """

    # ensure no duplicate characters
    escape_chars = ''.join(set(escape_chars))

    try:
        # move dash to end for use in character class
        di = escape_chars.index('-')
        escape_chars = escape_chars[0:di] + escape_chars[di + 1:] + '-'
    except ValueError:
        # no dash
        pass

    # build hex-escape subpatterns
    subpatterns = []
    for c in escape_chars:
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
        code = re.sub('[a-f]', _any_case, code)

        subpatterns.append(code)

    # add final character class excluding escape_chars
    try:
        # double any backslash present
        bi = escape_chars.index('\\')
        escape_chars = escape_chars[0:bi] + '\\' + escape_chars[bi:]
    except ValueError:
        # no backslash
        pass
    subpatterns.append('[^{0}]'.format(escape_chars))

    return '({0})'.format('|'.join(subpatterns))
