#!/usr/bin/env python
from getpass import getpass
from laurelin.ldap import LDAP
import laurelin.ldap.schema

LDAP.enable_logging()
with LDAP('ldap://localhost:10389') as ldap:
    ldap.startTLS(verify=False)
    ldap.simpleBind(username='cn=admin,dc=example,dc=org', password=getpass())

    print(ldap.rootDSE.formatLDIF())

    print('WHO AM I? {0}'.format(ldap.whoAmI()))

    for obj in ldap.base.search():
        print(obj.formatLDIF())
