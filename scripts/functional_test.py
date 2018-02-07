#!/usr/bin/env python
from getpass import getpass
from laurelin.ldap import LDAP
import laurelin.ldap.schema

LDAP.enable_logging()
with LDAP('ldap://localhost:10389') as ldap:
    ldap.start_tls(verify=False)
    ldap.simple_bind(username='cn=admin,dc=example,dc=org', password=getpass())

    print(ldap.root_dse.formatLDIF())

    print('WHO AM I? {0}'.format(ldap.who_am_i()))

    for obj in ldap.base.search():
        print(obj.formatLDIF())
