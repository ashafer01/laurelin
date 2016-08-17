from getpass import getpass
from laurelin.ldap import LDAP_rw, Scope

l = LDAP_rw('ldap://127.0.0.1')
l.simpleBind('cn=admin,dc=example,dc=org', getpass())

o = l.addIfNotExists('ou=test,dc=example,dc=org', {
    'objectClass': ['organizationalUnit'],
    'ou': ['test'],
})
l.addIfNotExists('ou=test2,dc=example,dc=org', {
    'objectClass': ['organizationalUnit'],
    'ou': ['test2'],
    'description': ['test object'],
})
