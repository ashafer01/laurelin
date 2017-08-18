"""RFC 4514: String Representation of Distinguished Names

https://tools.ietf.org/html/rfc4514
"""

from __future__ import absolute_import
from . import rfc4512

## Section 3


hexpair = rfc4512.HEX + r'{2}'
hexstring = r'#(?:' + hexpair + r')+'

escaped = r'"+,;<>\0\\'
special = escaped + ' #='

pair = r'\\([' + special + r']|' + hexpair + r')'

stringchar = r'[^' + escaped + r']'
leadchar = r'[^' + special + r']'
trailchar = r'[^' + escaped + r' ]'

string = (
    r'(?:' + leadchar + r'|' + pair + r')' +
    r'(?:' + stringchar + r'|' + pair + r')*' +
    r'(?:' + trailchar + r'|' + pair + r')?'
)

attributeValue = r'(?:' + string + r'|' + hexstring + r')'
attributeType = r'(?:' + rfc4512.descr + r'|' + rfc4512.numericoid + r')'
attributeTypeAndValue = attributeType + r'=' + attributeValue

relativeDistinguishedName = attributeTypeAndValue + r'(?:\+' + attributeTypeAndValue + r')*'
distinguishedName = relativeDistinguishedName + r'(?:,' + relativeDistinguishedName + r')*'
