from __future__ import absolute_import
import re
from laurelin.ldap import LDAP, LDAPObject, LDAPError
import six

TAG = 'netgroup_base'
OBJECT_CLASS = 'nisNetgroup'
NETGROUP_ATTRS = ['nisNetgroupTriple', 'memberNisNetgroup', 'objectClass', 'description']

## LDAP extension methods

def getNetgroup(self, cn, attrs=NETGROUP_ATTRS):
    return self.tag(TAG).get(cn, attrs)

def netgroupSearch(self, filter, attrs=NETGROUP_ATTRS):
    return self.tag(TAG).search(_netgroupFilter(filter), attrs)

def getNetgroupUsers(self, cn, recursive=True):
    ng = self.getNetgroup(cn)
    users = _extractTripleField(ng, 2)
    if recursive and ('memberNisNetgroup' in ng):
        for member in ng['memberNisNetgroup']:
            users += self.getNetgroupUsers(member, True)
    return users

def getNetgroupHosts(self, cn, recursive=True):
    ng = self.getNetgroup(cn)
    users = _extractTripleField(ng, 1)
    if recursive and ('memberNisNetgroup' in ng):
        for member in ng['memberNisNetgroup']:
            users += self.getNetgroupHosts(member, True)
    return users

def addNetgroupUsers(self, DN, members, domain=''):
    if not isinstance(members, list):
        members = [members]
    self.addAttrs(DN, _memberUserListToAttrs(members, domain))

def addNetgroupHosts(self, DN, members, domain=''):
    if not isinstance(members, list):
        members = [members]
    self.addAttrs(DN, _memberHostListToAttrs(members, domain))

LDAP.EXTEND([
    getNetgroup,
    netgroupSearch,
    getNetgroupUsers,
    getNetgroupHosts,
    addNetgroupUsers,
    ('addNetgroupUser', addNetgroupUsers),
    addNetgroupHosts,
    ('addNetgroupHost', addNetgroupHosts),
])

## LDAPObject extension methods

def _obj_getNetgroupUsers(self):
    if not self.hasObjectClass(OBJECT_CLASS):
        raise RuntimeError('Invalid objectClass for addNetgroupUsers '
            '(must have {0})'.format(OBJECT_CLASS))

def _obj_addNetgroupUsers(self, members, domain=''):
    if not self.hasObjectClass(OBJECT_CLASS):
        raise RuntimeError('Invalid objectClass for addNetgroupUsers '
            '(must have {0})'.format(OBJECT_CLASS))
    self.ldapConn.addNetgroupUsers(self.dn, members, domain)

def _obj_addNetgroupHosts(self, members, domain=''):
    if not self.hasObjectClass(OBJECT_CLASS):
        raise RuntimeError('Invalid objectClass for addNetgroupHosts '
            '(must have {0})'.format(OBJECT_CLASS))
    self.ldapConn.addNetgroupHosts(self.dn, members, domain)

LDAPObject.EXTEND([
    ('addNetgroupUsers', _obj_addNetgroupUsers),
    ('addNetgroupUser', _obj_addNetgroupUsers),
    ('addNetgroupHosts', _obj_addNetgroupHosts),
    ('addNetgroupHost', _obj_addNetgroupHosts),
])

## private functions

TRIPLE_RE = re.compile('^\(([^,]*),([^,]*),([^)]*)\)$')

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
