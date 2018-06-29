from . import exceptions
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


class CaseIgnoreDict(dict):
    """A dictionary with case-insensitive keys and storage of last actual key casing"""
    def __init__(self, plaindict=None):
        self._keys = {}
        if plaindict is not None:
            self.update(plaindict)

    def __setitem__(self, key, value):
        self._keys[key.lower()] = key
        dict.__setitem__(self, key, value)

    def setdefault(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            self[key] = default
            return default

    def __getitem__(self, key):
        key = self._keys[key.lower()]
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    def update(self, other):
        for key in other:
            self[key] = other[key]

    def __delitem__(self, key):
        lkey = key.lower()
        key = self._keys[lkey]
        dict.__delitem__(self, key)
        del self._keys[lkey]

    def clear(self):
        dict.clear(self)
        self._keys.clear()


def get_one_result(results):
    n = len(results)
    if n == 0:
        raise exceptions.NoSearchResults()
    elif n > 1:
        raise exceptions.MultipleSearchResults()
    else:
        return results[0]


_get_class_module_err_msg = ('Could not identify the source module for object {0}. This may indicate an incompatability'
                             ' between your Python version or implementation and laurelin.')


def get_obj_module(obj):
    """Identify the name of the module where the given object was defined.

    This uses the __module__ attribute with some error handling since there is some suggestion around the internet
    that this attribute may not be 100% reliable. But, the consensus seems to be that it is at least "pretty reliable"
    so this function performs a little bit of error handling just in case. It could probably do more, but the actual
    presentation of lack of support for this is unknown.
    """
    try:
        modname = obj.__module__
        if not modname:
            raise exceptions.LDAPError(_get_class_module_err_msg.format(obj.__name__))
        return modname
    except AttributeError:
        raise exceptions.LDAPError(_get_class_module_err_msg.format(obj.__name__))
