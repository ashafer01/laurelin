from getpass import getpass
from laurelin.ldap import LDAP, Scope
import laurelin.extensions.async

l = LDAP('ldap://127.0.0.1')
#l.simpleBind()
#l.simpleBind(username='cn=admin,dc=example,dc=org', password=getpass())
l.saslBind(mech='DIGEST-MD5', username='admin', password=getpass())

#for o in l.base.search('(objectClass=*)'):
#    print(o.formatLDIF())
#
#o = l.add('ou=test3,ou=test2,dc=example,dc=org', {
#    'objectClass': ['organizationalUnit'],
#    'ou':['test3'],
#    'description':['another test ou']
#})
#print('========')
#print(o.formatLDIF())
#print('========')

for o in l.search(l.base.dn, Scope.SUBTREE, '(objectClass=*)'):
    print(o.formatLDIF())
