from laurelin.ldap import (
    LDAP,
    LDAPObject,
    rfc4511,
    protoutils,
    exceptions,
    Mod,
    controls,
)
import laurelin.ldap.base
import inspect
import six
import unittest
from .mock_ldapsocket import MockLDAPSocket
from types import ModuleType
from base64 import b64encode
from laurelin.ldap.validation import Validator


class TestLDAP(unittest.TestCase):
    def test_global_default_presence(self):
        """Ensure that all parameters of LDAP.__init__ have a global default defined"""
        init_params = inspect.getargspec(LDAP.__init__).args
        init_params.remove('self')
        for param in init_params:
            gdefault = param.upper()
            if not gdefault.startswith('DEFAULT'):
                gdefault = 'DEFAULT_'+gdefault
            assert hasattr(LDAP, gdefault) is True

    def test_init_base_dn(self):
        """Test paths for base_dn"""
        # This also exercises the search method.

        # this should get the only namingContext
        expected_base_dn = 'o=testing'
        mock_sock = MockLDAPSocket()
        mock_sock.add_search_res_entry('', {
            'namingContexts': [expected_base_dn]
        }),
        mock_sock.add_search_res_done('')

        ldap = LDAP(mock_sock)
        self.assertEqual(ldap.base_dn, expected_base_dn)

        # this should complain about insufficient namingContexts
        mock_sock = MockLDAPSocket()
        mock_sock.add_search_res_entry('', {}),
        mock_sock.add_search_res_done('')

        with self.assertRaises(exceptions.LDAPError):
            LDAP(mock_sock)

        # this should complain about too many namingContexts
        mock_sock = MockLDAPSocket()
        mock_sock.add_search_res_entry('', {
            'namingContexts': [
                'o=test1',
                'o=test2',
            ]
        }),
        mock_sock.add_search_res_done('')

        with self.assertRaises(exceptions.LDAPError):
            LDAP(mock_sock)

        # this should get the defaultNamingContext and ignore namingContexts
        expected_base_dn = 'o=defaultnc'
        mock_sock = MockLDAPSocket()
        mock_sock.add_search_res_entry('', {
            'defaultNamingContext': [expected_base_dn],
            'namingContexts': [
                'o=foo',
                'o=bar',
            ]
        }),
        mock_sock.add_search_res_done('')

        ldap = LDAP(mock_sock)
        self.assertEqual(ldap.base_dn, expected_base_dn)

        # this should get the passed-in base_dn and ignore others
        mock_sock = MockLDAPSocket()
        mock_sock.add_search_res_entry('', {
            'defaultNamingContext': ['o=foobar'],
            'namingContexts': [
                'o=foo',
                'o=bar',
            ]
        }),
        mock_sock.add_search_res_done('')

        expected_base_dn = 'o=passedin'
        ldap = LDAP(mock_sock, base_dn=expected_base_dn)
        self.assertEqual(ldap.base_dn, expected_base_dn)

    def test_get(self):
        """Ensure the get function handles various result numbers properly"""

        # Test no results
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        mock_sock.add_search_res_done('o=foo')
        with self.assertRaises(exceptions.NoSearchResults):
            ldap.get('o=foo')

        # Test multiple results
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        mock_sock.add_search_res_entry('o=foo', {})
        mock_sock.add_search_res_entry('o=foo', {})
        mock_sock.add_search_res_done('o=foo')
        ldap = LDAP(mock_sock)

        with self.assertRaises(exceptions.MultipleSearchResults):
            ldap.get('o=foo')

        # Note: exactly 1 result is already exercised by test_init_base_dn

    def test_exists(self):
        """Ensure the exists function handles various result numbers properly"""

        # Test no results
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        mock_sock.add_search_res_done('o=foo')
        ldap = LDAP(mock_sock)

        self.assertFalse(ldap.exists('o=foo'))

        # Test multiple results
        mock_sock.add_search_res_entry('o=foo', {})
        mock_sock.add_search_res_entry('o=foo', {})
        mock_sock.add_search_res_done('o=foo')

        self.assertTrue(ldap.exists('o=foo'))

        # Test exactly one result
        mock_sock.add_search_res_entry('o=foo', {})
        mock_sock.add_search_res_done('o=foo')

        self.assertTrue(ldap.exists('o=foo'))

    def test_get_sasl_mechs(self):
        """Ensure get_sasl_mechs works correctly"""
        mechs = [
            'DIGEST-MD5',
            'GSSAPI'
        ]
        root_dse = {
            'namingContexts': ['o=testing'],
            'supportedSASLMechanisms': mechs,
        }
        mock_sock = MockLDAPSocket()

        # add root DSE
        mock_sock.add_search_res_entry('', root_dse)
        mock_sock.add_search_res_done('')
        # the constructor performs the initial root dse query
        ldap = LDAP(mock_sock)

        m1 = ldap.get_sasl_mechs()
        m2 = ldap.get_sasl_mechs()

        self.assertEqual(m1, mechs)
        self.assertIs(m1, m2)

    def test_recheck_sasl_mechs(self):
        """Ensure a downgrade attack is properly identified"""
        root_dse = {
            'namingContexts': ['o=testing'],
            'supportedSASLMechanisms': [
                'DIGEST-MD5',
                'GSSAPI'
            ]
        }
        mock_sock = MockLDAPSocket()

        # add root DSE
        mock_sock.add_search_res_entry('', root_dse)
        mock_sock.add_search_res_done('')
        # the constructor performs the initial root dse query
        ldap = LDAP(mock_sock)

        # the first recheck is identical and should work fine
        mock_sock.add_search_res_entry('', root_dse)
        mock_sock.add_search_res_done('')
        ldap.recheck_sasl_mechs()

        # the second recheck eliminates some of the previous mechs and should raise an error
        root_dse['supportedSASLMechanisms'] = ['DIGEST-MD5']
        mock_sock.add_search_res_entry('', root_dse)
        mock_sock.add_search_res_done('')
        with self.assertRaises(exceptions.LDAPError):
            ldap.recheck_sasl_mechs()

    def test_duplicate_tag(self):
        """Ensure trying to define a duplicate tag is an error"""
        tag = 'foobar'
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        ldap.obj('o=foo', tag=tag)
        with self.assertRaises(exceptions.TagError):
            ldap.obj('o=bar', tag=tag)

    def test_tagging(self):
        """Ensure setting and retreiving tags works"""
        tag = 'foobar'
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        expected_obj = ldap.obj('o=foo', tag=tag)
        actual_obj = ldap.tag(tag)
        self.assertIs(expected_obj, actual_obj)

        with self.assertRaises(exceptions.TagError):
            ldap.tag('not_a_defined_tag')

    def test_search_result_ref(self):
        """Ensure searchResRef is handled correctly"""
        # Note: searchResEntry and searchResDone paths have already been exercised

        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        base_dn = 'ou=foo,o=testing'
        uri = 'ldap://test.net/ou=foo,o=testing'

        mock_sock.add_search_res_ref([uri])
        mock_sock.add_search_res_done(base_dn)

        with ldap.search(base_dn, fetch_result_refs=False) as search:
            results = list(search)
            self.assertEqual(len(results), 1)
            srh = results[0]
            self.assertIsInstance(srh, laurelin.ldap.base.SearchReferenceHandle)
            self.assertEqual(len(srh.uris), 1)

        # TODO: verify we get a warning when response controls are returned with a searchResultRef
        # TODO: test with fetch_result_refs set True, will need to mock SearchReferenceHandle

    def test_search_error_response(self):
        """Ensure non-success results for search are handled correctly"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        mock_sock.add_search_res_done('', result_code=protoutils.RESULT_compareTrue)

        with self.assertRaises(exceptions.LDAPError):
            list(ldap.search(''))

    def test_search_nosuchobject_response(self):
        """Ensure noSuchObject response is treated as no results"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        mock_sock.add_search_res_done('', result_code=rfc4511.ResultCode('noSuchObject'))

        self.assertEqual(len(list(ldap.search(''))), 0)

    def test_search_referral(self):
        """Ensure a referral response is handled correctly for search"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        uri = 'ldap://test.net/ou=foo,o=testing'
        mock_sock.add_search_res_done(2, '', referral=[uri])

        with ldap.search('', follow_referrals=False) as search:
            results = list(search)
            self.assertEqual(len(results), 0)

        # TODO: test with follow_referrals set True, will need to mock SearchReferenceHandle

    def test_compare(self):
        """Ensure compare returns correct boolean results"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        mock_sock.add_ldap_result(rfc4511.CompareResponse, 'compareResponse', dn='',
                                  result_code=protoutils.RESULT_compareTrue)
        actual = ldap.compare('', 'foo', 'bar')
        self.assertTrue(actual)

        mock_sock.add_ldap_result(rfc4511.CompareResponse, 'compareResponse', dn='',
                                  result_code=protoutils.RESULT_compareFalse)
        actual = ldap.compare('', 'foo', 'bar')
        self.assertFalse(actual)

    def test_add_bad_response(self):
        """Ensure non-success results for add are handled correctly"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        mock_sock.add_ldap_result(rfc4511.AddResponse, 'addResponse', dn='', result_code=protoutils.RESULT_compareTrue)

        with self.assertRaises(exceptions.LDAPError):
            ldap.add('o=foo', {})

    def test_modify_zero_length(self):
        """Ensure zero-length modlists are ignored"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()
        ldap.modify('', [])
        self.assertEqual(mock_sock.num_sent(), 0)

    def test_modify(self):
        """Ensure protocol-level modlist is contructed without error"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        ldap.modify('', [
            Mod(Mod.ADD, 'foo', ['bar', 'baz']),
            Mod(Mod.REPLACE, 'foo', []),
            Mod(Mod.REPLACE, 'foo', ['foo']),
            Mod(Mod.DELETE, 'foo', []),
            Mod(Mod.DELETE, 'foo', ['foo'])
        ])

    def test_modify_bad_response(self):
        """Ensure modify complains when receiving a bad response from the server"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse', result_code=protoutils.RESULT_compareFalse)
        with self.assertRaises(exceptions.LDAPError):
            ldap.modify('', [
                Mod(Mod.ADD, 'foo', ['bar', 'baz']),
            ])

    def test_add_attrs(self):
        """Ensure add_attrs behaves correctly"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()

        # current is not None
        # should NOT perform a search
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        ldap.add_attrs('', {'foo': ['bar']}, current=LDAPObject('', {}))
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # current is None and not strict_modify
        # should perform a search before modify
        mock_sock.add_search_res_entry('', {'abc': ['def']})
        mock_sock.add_search_res_done('')
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        ldap.strict_modify = False
        ldap.add_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 2)
        protoutils.unpack('searchRequest', mock_sock.read_sent())
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # current is None and strict_modify
        # should NOT perform a search
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        ldap.strict_modify = True
        ldap.add_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

    def test_delete_attrs(self):
        """Ensure delete_attrs behaves correctly"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()

        # current is not None
        # should NOT perform a search
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        ldap.delete_attrs('', {'foo': ['bar']}, current=LDAPObject('', {'foo': ['bar']}))
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # current is None and not strict_modify
        # should perform a search before modify
        mock_sock.add_search_res_entry('', {'foo': ['bar']})
        mock_sock.add_search_res_done('')
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        ldap.strict_modify = False
        ldap.delete_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 2)
        protoutils.unpack('searchRequest', mock_sock.read_sent())
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # current is None and strict_modify
        # should NOT perform a search
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        ldap.strict_modify = True
        ldap.delete_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

    def test_replace_attrs(self):
        """Ensure replace_attrs behaves correctly"""
        class MockValidator(Validator):
            def validate_object(self, obj, write=True):
                pass

            def validate_modify(self, dn, modlist, current):
                pass

            def _validate_attribute(self, attr_name, values, write):
                pass

        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()

        # current is None and have validators and not strict_modify
        # SHOULD perform a search before modify
        ldap.validators = [MockValidator()]
        ldap.strict_modify = False
        mock_sock.add_search_res_entry('', {'foo': ['bar']})
        mock_sock.add_search_res_done('')
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        ldap.strict_modify = False
        ldap.replace_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 2)
        protoutils.unpack('searchRequest', mock_sock.read_sent())
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # else
        # SHOULD NOT perform a search, only modify
        ldap.validators = []
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        ldap.replace_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

    def test_who_am_i(self):
        """Exercise the extension subsystem"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        # ensure unsupported extensions raise an exceptions
        with self.assertRaises(exceptions.LDAPSupportError):
            ldap.who_am_i()

        # make the who am i operation supported
        root_dse = {
            'namingContexts': ['o=testing'],
            'supportedExtension': [LDAP.OID_WHOAMI],
        }
        mock_sock.add_search_res_entry('', root_dse)
        mock_sock.add_search_res_done('')
        mock_sock.add_ldap_result(rfc4511.ExtendedResponse, 'extendedResp')
        ldap.refresh_root_dse()
        ldap.who_am_i()

        # test failure result
        mock_sock.add_ldap_result(rfc4511.ExtendedResponse, 'extendedResp', result_code=protoutils.RESULT_compareFalse)
        with self.assertRaises(exceptions.LDAPError):
            ldap.who_am_i()

    def test_activate_extension(self):
        """Ensure extension activation/loading works"""
        ext = 'laurelin.extensions.netgroups'
        netgroups = LDAP.activate_extension(ext)
        self.assertIsInstance(netgroups, ModuleType)
        self.assertTrue(hasattr(LDAP, 'get_netgroup'))
        self.assertTrue(hasattr(netgroups, 'LAURELIN_ACTIVATED'))

        # ensure activating again does not cause an error
        LDAP.activate_extension(ext)

        with self.assertRaises(ImportError):
            LDAP.activate_extension('i.am.not.a.module')

    def test_unbind(self):
        """Test unbind/unbound behavior"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()

        ldap.unbind()

        # ensure we sent the actual unbindRequest
        self.assertEqual(mock_sock.num_sent(), 1)

        unbound_fail_methods = [
            (ldap.simple_bind,),
            (ldap.sasl_bind,),
            (ldap.unbind,),
            (ldap.get, ''),
            (ldap.exists, ''),
            (ldap.search, ''),
            (ldap.compare, '', '', ''),
            (ldap.add, '', None),
            (ldap.delete, ''),
            (ldap.mod_dn, '', ''),
            (ldap.modify, '', [None]),
        ]

        for args in unbound_fail_methods:
            with self.assertRaises(exceptions.ConnectionUnbound):
                args[0](*args[1:])

    def test_bound(self):
        """Ensure bind methods complain that the connection is already bound"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        mock_sock.bound = True

        bound_fail_methods = [
            ldap.simple_bind,
            ldap.sasl_bind
        ]

        for method in bound_fail_methods:
            with self.assertRaises(exceptions.ConnectionAlreadyBound):
                method()

    def test_search_kwds(self):
        """Ensure all valid forms of search keywords work and that invalid keywords are detected early"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        # create a valid control keyword
        class MockControl(controls.Control):
            method = ('search',)
            keyword = 'mock_control'
            REQUEST_OID = '9.999.999.999.999.9999999'

        test_dn = 'o=foo'
        mock_sock.add_search_res_entry(test_dn, {'description': ['foo']})
        mock_sock.add_search_res_done(test_dn)

        # test with valid search keyword, control keyword, and object keyword
        list(ldap.search(test_dn, limit=7, mock_control='foo', rdn_attr='ou'))

        mock_sock.clear_sent()

        # test with bad keyword
        with self.assertRaises(TypeError):
            ldap.search(test_dn, bad_keyword='foo')
        self.assertEqual(mock_sock.num_sent(), 0)

    def test_process_ldif(self):
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        dn = 'ou=modify,o=bar'
        b64dn = b64encode(dn.encode()).decode('ascii')

        add_dn = 'ou=foo,o=bar'
        add_desc = 'hello world'
        b64desc = b64encode(add_desc.encode()).decode('ascii')
        expected_add_object = LDAPObject(dn=add_dn, attrs_dict={
            'objectClass': ['top', 'organizationalUnit'],
            'description': [add_desc],
            'ou': ['foo'],
        })

        ldif = ('dn: {add_dn}\n'
                'changetype: add\n'
                'objectClass: top\n'
                'objectClass: organizationalUnit\n'
                'description:: {b64desc}\n'
                'ou: foo\n'
                '\n'
                'dn: ou=delete,o=bar\n'
                'changetype: delete\n'
                '\n'
                'dn: ou=modify,o=bar\n'
                'changetype: modify\n'
                'add: description\n'
                'description: foo\n'
                '-\n'
                'replace: description\n'
                'description: bar\n'
                '-\n'
                'delete: description\n'
                'description: bar\n'
                '-\n'
                '\n'
                'dn:: {b64dn}\n'
                'changetype: moddn\n'
                'newrdn: ou=modified\n'
                'deleteoldrdn: 1\n'
                'newsuperior: o=foo\n'
                '\n'.format(b64desc=b64desc, b64dn=b64dn, add_dn=add_dn))

        mock_sock.add_ldap_result(rfc4511.AddResponse, 'addResponse')
        mock_sock.add_ldap_result(rfc4511.DelResponse, 'delResponse')
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        mock_sock.add_ldap_result(rfc4511.ModifyDNResponse, 'modDNResponse')

        results = ldap.process_ldif(ldif)

        self.assertEqual(expected_add_object, results[0])

    def test_error_empty_list(self):
        """Ensure the error_empty_list option is respected with all invocations"""

        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock, error_empty_list=True)

        with self.assertRaises(exceptions.LDAPError):
            ldap.modify('o=foo', [Mod(Mod.REPLACE, 'foo', [])])

        with self.assertRaises(exceptions.LDAPError):
            ldap.replace_attrs('o=foo', {'foo': []})

        with self.assertRaises(exceptions.LDAPError):
            ldap.delete_attrs('o=foo', {'foo': []}, current={'foo': ['bar']})

        with self.assertRaises(exceptions.LDAPError):
            ldap.obj('o=foo').modify([Mod(Mod.REPLACE, 'foo', [])])

        with self.assertRaises(exceptions.LDAPError):
            ldap.obj('o=foo').replace_attrs({'foo': []})

        with self.assertRaises(exceptions.LDAPError):
            ldap.obj('o=foo', attrs_dict={'foo': ['bar']}).delete_attrs({'foo': []})

    def test_ignore_empty_list(self):
        """Ensure emtpy value lists are ignored"""

        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock, ignore_empty_list=True)

        mock_sock.clear_sent()

        # this should succeed without sending a request to the server or expecting a response
        ldap.modify('o=foo', [Mod(Mod.REPLACE, 'foo', [])])
        self.assertEqual(mock_sock.num_sent(), 0)

    def test_disable_validation(self):
        """Exercise disable_validation()"""
        class MockValidator(Validator):
            def validate_object(self, obj, write=True):
                raise exceptions.LDAPValidationError()

            def validate_modify(self, dn, modlist, current):
                raise exceptions.LDAPValidationError()

            def _validate_attribute(self, attr_name, values, write):
                raise exceptions.LDAPValidationError()

        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock, validators=[MockValidator()], strict_modify=True)

        # ensure validation gets run
        with self.assertRaises(exceptions.LDAPValidationError):
            ldap.base.add_child('cn=foo', {})

        # ensure validation does not get run
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        with ldap.disable_validation():
            ldap.base.add_attrs({'foo': 'bar'})

        # ensure validation has been restored
        with self.assertRaises(exceptions.LDAPValidationError):
            ldap.base.add_child('cn=foo', {})

        # test disabling specific validator by class
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        with ldap.disable_validation([MockValidator]):
            ldap.base.add_attrs({'foo': 'bar'})

        # test disabling specific validator by class name
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        with ldap.disable_validation(['MockValidator']):
            ldap.base.add_attrs({'foo': 'bar'})

    def test_sasl_bind(self):
        """Verify sasl_bind functions correctly"""
        mech = 'DIGEST-MD5'
        root_dse = {
            'supportedSASLMechanisms': [mech],
            'namingContexts': ['o=testing'],
        }
        mock_sock = MockLDAPSocket()
        mock_sock.add_search_res_entry('', root_dse),
        mock_sock.add_search_res_done('')
        ldap = LDAP(mock_sock)

        mock_sock.clear_sent()

        challenge1 = b'foo'
        challenge2 = b'bar'

        mock_sock.add_sasl_bind_in_progress(challenge1)
        mock_sock.add_sasl_bind_in_progress(challenge2)
        mock_sock.add_bind_success()
        mock_sock.add_search_res_entry('', root_dse),
        mock_sock.add_search_res_done('')

        ldap.sasl_bind(mech, username='foo', password='foo')

        # initial bind request + 2 challenge responses + root DSE refresh
        self.assertEqual(mock_sock.num_sent(), 4)

        def get_sasl_cred(br):
            ac = br.getComponentByName('authentication')
            sasl = ac.getComponentByName('sasl')
            return sasl.getComponentByName('credentials')

        mock_sock.read_sent()  # initial bind request
        lm = mock_sock.read_sent()  # first challenge response
        mid, br, ctrls = protoutils.unpack('bindRequest', lm)
        self.assertEqual(get_sasl_cred(br), challenge1)
        lm = mock_sock.read_sent()  # second challenge response
        mid, br, ctrls = protoutils.unpack('bindRequest', lm)
        self.assertEqual(get_sasl_cred(br), challenge2)

    def test_sasl_bind_fail(self):
        """Verify sasl_bind fails correctly"""
        mech = 'DIGEST-MD5'
        root_dse = {
            'supportedSASLMechanisms': [mech],
            'namingContexts': ['o=testing'],
        }
        mock_sock = MockLDAPSocket()
        mock_sock.add_search_res_entry('', root_dse),
        mock_sock.add_search_res_done('')
        ldap = LDAP(mock_sock)

        mock_sock.add_ldap_result(rfc4511.BindResponse, 'bindResponse', result_code=protoutils.RESULT_compareFalse)
        with self.assertRaises(exceptions.LDAPError):
            ldap.sasl_bind(mech, username='foo', password='foo')


if __name__ == '__main__':
    unittest.main()
