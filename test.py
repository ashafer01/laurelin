from getpass import getpass
from laurelin.ldap import LDAP, Scope

LDAP.enableLogging()
with LDAP('ldap://127.0.0.1') as l:
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

    #for o in l.search(l.base.dn, Scope.SUBTREE, '(objectClass=*)'):
    #    print(o.formatLDIF())

    with l.search(l.base.dn, Scope.SUBTREE, '(objectClass=*)') as r:
        n = 0
        for o in r:
            print(o.formatLDIF())
            n += 1
            if n > 2:
                break

    r = list(l.search(l.base.dn, Scope.SUBTREE, '(objectClass=*)'))
    for o in r:
        print(o.dn)

    for o in l.search(l.base.dn, Scope.SUBTREE, '(objectClass=*)'):
        print(o.dn)
