#!/usr/bin/env python
from getpass import getpass
from laurelin.ldap import LDAP
from laurelin.ldap.schema import SchemaValidator

LDAP.enable_logging()
LDAP.activate_extension('laurelin.extensions.descattrs')
with LDAP('ldap://localhost:10389',
          validators=[SchemaValidator()],
          ) as ldap:
    ldap.start_tls(verify=False)
    ldap.simple_bind(username='cn=admin,dc=example,dc=org', password=getpass())

    print(ldap.root_dse.format_ldif())

    print('WHO AM I? {0}'.format(ldap.who_am_i()))

    for obj in ldap.base.search():
        print(obj.format_ldif())
