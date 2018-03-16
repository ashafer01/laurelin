#!/usr/bin/env python
from laurelin.ldap import LDAP, LDAPObject
from laurelin.ldap.schema import SchemaValidator

test_servers = [
    {'name': 'OpenLDAP',
     'uri': 'ldap://localhost:10389',
     'bind_dn': 'cn=admin,dc=example,dc=org',
     'pw': 'admin'},
    {'name': 'OpenLDAP ldaps',
     'uri': 'ldaps://localhost:10636',
     'start_tls': False,
     'bind_dn': 'cn=admin,dc=example,dc=org',
     'pw': 'admin'},
    {'name': '389 Directory Server',
     'uri': 'ldap://localhost:11389',
     'start_tls': False,
     'bind_dn': 'cn=Directory Manager',
     'pw': 'password'},
]

LDAP.enable_logging()
LDAP.activate_extension('laurelin.extensions.descattrs')
for info in test_servers:
    print('Testing {0}'.format(info['name']))
    try:
        with LDAP(info['uri'], validators=[SchemaValidator()], ssl_verify=False) as ldap:
            if info.get('start_tls', True):
                ldap.start_tls()
            ldap.simple_bind(username=info['bind_dn'], password=info['pw'])

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

            # test mod_transaction and format_mod_ldif
            testobj = ldap.base.add_child('ou=functest', {
                'objectClass': ['organizationalUnit'],
                'ou': ['functest'],
            })
            with testobj.mod_transaction() as trans:
                trans.add_attrs({'description': ['foo', 'bar']})
                trans.delete_attrs({'description': ['bar']})
                trans.replace_attrs({
                    'postalAddress': ['1234 Main, San Mateo, CA'],
                })
                print(trans.format_mod_ldif())
                trans.commit()
            print(testobj.format_ldif())
            testobj.delete()

            # test format_ldif
            o = LDAPObject('o=foo ', {
                'binaryAndNormal': [b'\xff\xab\xcd\xef', 'abc'],
                'encodeBadLeading': [
                    ':leading colon must be encoded',
                    ' leading space must be encoded',
                    '<leading left angle must be encoded',
                ],
                'encodeBadChar': [
                    'newlines\nmust be encoded',
                    'cr\rmust be encoded',
                    'null\0must be encoded',
                ],
                'lineFold': ['abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk'
                             'lmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv'
                             'wxyzab'],
            })
            print(o.format_ldif())

            # test DELETE_ALL
            test_rdn = 'ou=foo'
            test_attr = 'description'
            obj1 = ldap.base.add_child(test_rdn, {
                'objectClass': ['organizationalUnit'],
                'ou': ['foo'],
                test_attr: ['foo']
            })
            assert test_attr in obj1
            obj1.delete_attrs({test_attr: LDAP.DELETE_ALL})
            assert test_attr not in obj1
            obj2 = ldap.base.get_child(test_rdn)
            assert test_attr not in obj2
            obj2.delete()
    except Exception as e:
        raise Exception('Functional test failed on {0}: {1}'.format(info['name'], str(e)))
