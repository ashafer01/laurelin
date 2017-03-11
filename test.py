from getpass import getpass
from laurelin.ldap import LDAP, Scope

LDAP.enableLogging()
with LDAP('ldap://127.0.0.1') as l:
    #l.simpleBind()
    #l.simpleBind(username='cn=admin,dc=example,dc=org', password=getpass())
    l.saslBind(mech='DIGEST-MD5', username='admin', password=getpass())

    with l.search(l.base.dn) as r:
        n = 0
        for o in r:
            print(o.formatLDIF())
            n += 1
            if n > 2:
                break

    r = list(l.search(l.base.dn))
    for o in r:
        print(o.dn)

    for o in l.search(l.base.dn):
        print(o.dn)

    print(l.compare('cn=admin,'+l.base.dn, 'cn', 'admin'))
    print(l.compare('cn=admin,'+l.base.dn, 'cn', 'admxxin'))

    #l.add('ou=test4,ou=test,dc=example,dc=org', {
    #    'objectClass': ['organizationalUnit'],
    #    'ou': ['test4'],
    #    'description': ['YATOU']
    #})

    #l.obj('ou=test4,ou=test,dc=example,dc=org').addAttrs({
    #    'description': ['YATOUDFT'],
    #})

    print(l.get('ou=test4,ou=test,dc=example,dc=org').formatLDIF())
