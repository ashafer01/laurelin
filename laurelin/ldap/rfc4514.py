"""RFC 4514: String Representation of Distinguished Names

https://tools.ietf.org/html/rfc4514
"""

from __future__ import absolute_import

from . import rfc4512
from .errors import LDAPError

import re
from six.moves import range

class InvalidDN(LDAPError):
    pass

## Section 3

hexpair = rfc4512.HEX + r'{2}'

hexstring = re.compile(r'^#(' + hexpair + r')+$')
attributeType = re.compile(r'^(' + rfc4512.descr + r'|' + rfc4512.numericoid + r')$')

escaped_chars = '"+,;<>'
escaped_leaders = '# '
escaped_trailers = ' \0'

def validateValueString(s):
    """Ensure requisite characters are escaped

     The following characters are to be escaped when they appear
     in the value to be encoded: ESC, one of <escaped>, leading
     SHARP or SPACE, trailing SPACE, and NULL.
    """
    l = len(s)
    end = l-1
    for i in range(l):
        cc = s[i]
        if i == 0:
            # first character cannot be one of escaped_leaders (must be \ instead)
            if cc in escaped_leaders:
                raise InvalidDN('Missing leading escape')
        else:
            # ensure \ comes before anything that needs it
            lc = s[i-1]
            if i == end:
                if cc in escaped_trailers and lc != '\\':
                    raise InvalidDN('Missing trailing escape')
            else:
                nc = s[i+1]
                if cc == '\\' and nc in escaped_chars:
                    continue
                if cc in escaped_chars and lc != '\\':
                    raise InvalidDN('Missing escape before "{0}"'.format(cc))

def validateDistinguishedName(s):
    """Ensure validity of a DN"""

    # split on unescaped commas
    rdns = re.split(r'(?<!\\),', s)
    for rdn in rdns:
        # split on unescaped plus signs
        rdn_parts = re.split(r'(?<!\\)\+', rdn)
        for rdn_part in rdn_parts:
            # split on unescaped equals signs
            av = re.split(r'(?<!\\)=', rdn_part, 2)

            # ensure exactly 2 parts, attr=value
            if len(av) != 2:
                raise InvalidDN('Invalid RDN part "{0}" (unescaped equals sign?)'.format(rdn_part))
            attr, value = av

            # validate attr
            if not attributeType.match(attr):
                raise InvalidDN('Invalid attribute type "{0}"'.format(attr))

            # validate value is hex string or normal string
            if not hexstring.match(value):
                validateValueString(value)
