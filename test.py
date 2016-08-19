from getpass import getpass
from laurelin.ldap import LDAP_rw, Scope

l = LDAP_rw('ldap://127.0.0.1')
l.simpleBind('cn=admin,dc=example,dc=org', getpass())

for o in l.base.search('(description=*foo)'):
    print o.formatLDIF()
