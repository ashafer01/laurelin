import re
from laurelin.ldap import LDAP, LDAP_rw, LDAPObject

TAG = 'netgroup_base'
OBJECT_CLASS = 'nisNetgroup'

## LDAP extension methods

def getNetgroup(self, cn, attrs=None):
    return self.tag(TAG).get(cn, attrs)

def netgroupSearch(self, filter, attrs=None):
    return self.tag(TAG).search(filter, attrs)

LDAP.EXTEND([
    getNetgroup,
    netgroupSearch,
])

## LDAP_rw extension methods

def addNetgroupUsers(self, DN, members):
    self.addAttrs(DN, _memberUserListToAttrs(members))

LDAP_rw.EXTEND([
    addNetgroupUsers,
])

## LDAPObject extension methods

def _obj_addNetgroupUsers(self, members):
    if not self.hasObjectClass(OBJECT_CLASS):
        raise RuntimeError('Invalid objectClass for addNetgroupUsers '
            '(must have {0})'.format(OBJECT_CLASS))
    self.addAttrs(_memberUserListToAttrs(members))

LDAPObject.EXTEND([
    ('addNetgroupUsers', _obj_addNetgroupUsers),
])

## private functions

def _isTriple(val):
    return re.match('^\([^,]*,[^,]*,[^)]*\)$', val)

def _nisNetgroupTriple(host, user, domain):
    return '({0},{1},{2})'.format(host, user, domain)

def _memberUserListToAttrs(memberList, domain=''):
    attrs = {}
    for member in memberList:
        attr = 'nisNetgroupTriple'
        if isinstance(member, basestring):
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
        if isinstance(member, basestring):
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
