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

    # test descattrs extension
    testobj = ldap.base.add_child('ou=functest', {
        'objectClass': ['organizationalUnit'],
        'ou': ['functest'],
        'description': ['unstructured desc'],
    })
    testobj.add_desc_attrs({'foo': ['one', 'two']})
    print(testobj.desc_attrs())
    testobj.replace_desc_attrs({'foo': ['three', 'four']})
    testobj.delete_desc_attrs({'foo': ['three']})
    assert testobj.desc_attrs().get_attr('foo') == ['four']
    assert set(testobj.get_attr('description')) == set(('unstructured desc', 'foo=four'))
    print(testobj.format_ldif())
    testobj.delete()
