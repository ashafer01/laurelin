from getpass import getpass
from laurelin.ldap import LDAP_rw, Scope
import laurelin.extensions.async

l = LDAP_rw('ldap://127.0.0.1')
l.simpleBind('cn=admin,dc=example,dc=org', getpass())

for o in l.base.search('(objectClass=*)'):
    print o.formatLDIF()

o = l.add('ou=test3,ou=test2,dc=example,dc=org', {
    'objectClass': ['organizationalUnit'],
    'ou':['test3'],
    'description':['another test ou']
})
print '========'
print o.formatLDIF()
print '========'

for o in l.searchAsync(l.base.dn, Scope.SUBTREE, '(objectClass=*)').iter():
    print o.formatLDIF()
