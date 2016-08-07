from getpass import getpass
from ldap import LDAP_rw

l = LDAP_rw('ldap://127.0.0.1:389', baseDC='dc=example,dc=org')
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

o.addAttrs({
    'description':['desc1', 'desc2']
})
