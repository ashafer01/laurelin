from __future__ import absolute_import
import re
from laurelin.ldap import LDAP, LDAPObject, LDAPError
from laurelin.ldap.attributetype import AttributeType
from laurelin.ldap.objectclass import ObjectClass
from laurelin.ldap.rules import RegexSyntaxRule
import six

TAG = 'netgroup_base'
OBJECT_CLASS = 'nisNetgroup'
NETGROUP_ATTRS = ['cn', 'nisNetgroupTriple', 'memberNisNetgroup', 'objectClass']

_TRIPLE_RE = '^\(([^,]*),([^,]*),([^)]*)\)$'


## Schema definitions from RFC 2307


ObjectClass('''
( 1.3.6.1.1.1.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
  MUST cn
  MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
''')

AttributeType('''
( 1.3.6.1.1.1.1.13 NAME 'memberNisNetgroup'
  EQUALITY caseExactIA5Match
  SUBSTR caseExactIA5SubstringsMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
''')

AttributeType('''
( 1.3.6.1.1.1.1.14 NAME 'nisNetgroupTriple'
  DESC 'Netgroup triple'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.1.1.0.0 )
''')


class nisNetgroupTripleSytnax(RegexSyntaxRule)
    OID = '1.3.6.1.1.1.0.0'
    DESC = 'NIS netgroup triple'
    regex = _TRIPLE_RE


## LDAP extension methods


@LDAP.EXTEND()
def getNetgroup(self, cn, attrs=NETGROUP_ATTRS):
    return self.tag(TAG).get(cn, attrs)

@LDAP.EXTEND()
def netgroupSearch(self, filter, attrs=NETGROUP_ATTRS):
    return self.tag(TAG).search(_netgroupFilter(filter), attrs)

@LDAP.EXTEND()
def getNetgroupUsers(self, cn, recursive=True):
    ng = self.getNetgroup(cn)
    users = _extractTripleField(ng, 2)
    if recursive and ('memberNisNetgroup' in ng):
        for member in ng['memberNisNetgroup']:
            users += self.getNetgroupUsers(member, True)
    return users

@LDAP.EXTEND()
def getNetgroupHosts(self, cn, recursive=True):
    ng = self.getNetgroup(cn)
    users = _extractTripleField(ng, 1)
    if recursive and ('memberNisNetgroup' in ng):
        for member in ng['memberNisNetgroup']:
            users += self.getNetgroupHosts(member, True)
    return users

@LDAP.EXTEND()
def addNetgroupUsers(self, DN, members, domain=''):
    if not isinstance(members, list):
        members = [members]
    self.add_attrs(DN, _memberUserListToAttrs(members, domain))

@LDAP.EXTEND()
def addNetgroupHosts(self, DN, members, domain=''):
    if not isinstance(members, list):
        members = [members]
    self.add_attrs(DN, _memberHostListToAttrs(members, domain))


## LDAPObject extension methods


@LDAPObject.EXTEND()
def _requireNetgroup(self):
    if not self.has_object_class(OBJECT_CLASS):
        raise RuntimeError('objectClass {0} is required'.format(OBJECT_CLASS))

@LDAPObject.EXTEND('getNetgroupUsers')
def obj_getNetgroupUsers(self):
    self._requireNetgroup()

@LDAPObject.EXTEND('addNetgroupUsers')
def obj_addNetgroupUsers(self, members, domain=''):
    self._requireNetgroup()
    self.ldapConn.addNetgroupUsers(self.dn, members, domain)

@LDAPObject.EXTEND('addNetgroupHosts')
def obj_addNetgroupHosts(self, members, domain=''):
    self._requireNetgroup()
    self.ldapConn.addNetgroupHosts(self.dn, members, domain)


## private functions


TRIPLE_RE = re.compile(_TRIPLE_RE)

def _netgroupFilter(filter):
    return '(&(objectClass={0}){1})'.format(OBJECT_CLASS, filter)

def _isTriple(val):
    return (TRIPLE_RE.match(val) is not None)

def _nisNetgroupTriple(host, user, domain):
    return '({0},{1},{2})'.format(host, user, domain)

def _extractTripleField(ngObj, index):
    ret = []
    for triple in ngObj.get('nisNetgroupTriple', []):
        m = TRIPLE_RE.match(triple)
        if m is None:
            raise LDAPError('Invalid nisNetgroupTriple: {0}'.format(triple))
        else:
            ret.append(m.group(index))
    return users

def _memberUserListToAttrs(memberList, domain=''):
    attrs = {}
    for member in memberList:
        attr = 'nisNetgroupTriple'
        if isinstance(member, six.string_types):
            if member[0] == '+':
                attr = 'memberNisNetgroup'
                member = member[1:]
            else:
                if not _isTriple(member):
                    member = _nisNetgroupTriple('', member, domain)
        elif isinstance(member, tuple):
            if len(member) == 1:
                raise ValueError('At least first 2 triple values (host,user) must be '
                    'specified for users')
            elif len(member) == 2:
                member = _nisNetgroupTriple(member[0], member[1], domain)
            elif len(member) == 3:
                member = _nisNetgroupTriple(*member)
            else:
                raise ValueError('tuple must have 2 or 3 elements')
        else:
            raise TypeError('memberList elements must be string or tuple')
        if attr not in attrs:
            attrs[attr] = []
        attrs[attr].append(member)
    return attrs

def _memberHostListToAttrs(memberList, domain=''):
    attrs = {}
    for member in memberList:
        attr = 'nisNetgroupTriple'
        if isinstance(member, six.string_types):
            if member[0] == '+':
                attr = 'memberNisNetgroup'
                member = member[1:]
            else:
                if not _isTriple(member):
                    member = _nisNetgroupTriple(member, '', domain)
        elif isinstance(member, tuple):
            if len(member) == 1:
                member = _nisNetgroupTriple(member[0], '', domain)
            elif len(member) == 2:
                member = _nisNetgroupTriple(member[0], member[1], domain)
            elif len(member) == 3:
                member = _nisNetgroupTriple(*member)
            else:
                raise ValueError('tuple must have 1-3 elements')
        else:
            raise TypeError('memberList elements must be string or tuple')
        if attr not in attrs:
            attrs[attr] = []
        attrs[attr].append(member)
    return attrs
