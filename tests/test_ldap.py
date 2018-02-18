from laurelin.ldap import (
    LDAP,
    LDAPObject,
    rfc4511,
    protoutils,
    exceptions,
    Mod,
)
import laurelin.ldap.base
import inspect
import unittest
from .mock_ldapsocket import MockLDAPSocket
from types import ModuleType
from laurelin.ldap.validation import Validator


def obj_to_lm(mid, dn, attrs_dict, controls=None):
    """Create a searchResEntry LDAPMessage"""
    sre = rfc4511.SearchResultEntry()
    sre.setComponentByName('objectName', rfc4511.LDAPDN(dn))

    attrs = rfc4511.PartialAttributeList()
    i = 0
    for attr, values in attrs_dict.items():
        _attr = rfc4511.PartialAttribute()
        _attr.setComponentByName('type', rfc4511.AttributeDescription(attr))
        _vals = rfc4511.Vals()
        for j, val in enumerate(values):
            _vals.setComponentByPosition(j, rfc4511.AttributeValue(val))
        _attr.setComponentByName('vals', _vals)
        attrs.setComponentByPosition(i, _attr)
        i += 1

    sre.setComponentByName('attributes', attrs, controls)

    return protoutils.pack(mid, 'searchResEntry', sre)


def search_res_done(mid, dn, result_code=protoutils.RESULT_success, controls=None, referral=None):
    """Create a searchResDone LDAPMessage"""
    return ldap_result(rfc4511.SearchResultDone,
                       mid,
                       'searchResDone',
                       dn=dn,
                       result_code=result_code,
                       msg='THIS IS A TEST OBJECT',
                       controls=controls,
                       referral=referral)


def search_res_ref(mid, uris, controls=None):
    """Generate a searchResultRef LDAPMessage"""
    srr = rfc4511.SearchResultReference()
    for i, uri in enumerate(uris):
        srr.setComponentByPosition(i, uri)
    return protoutils.pack(mid, 'searchResRef', srr, controls)


def add_root_dse(mock_sock, mid=1):
    """Add a response to the mock socket for root DSE query"""
    mock_sock.add_messages([
        obj_to_lm(mid, '', {
            'namingContexts': ['o=testing']
        }),
        search_res_done(mid, ''),
    ])


def ldap_result(cls, mid, op, result_code=protoutils.RESULT_success, dn='', msg='', controls=None, referral=None):
    res = cls()
    if referral:
        result_code = protoutils.RESULT_referral
        _referral = rfc4511.Referral()
        for i, uri in enumerate(referral):
            _referral.setComponentByPosition(i, rfc4511.URI(uri))
        res.setComponentByName('referral', _referral)
    res.setComponentByName('resultCode', result_code)
    res.setComponentByName('matchedDN', rfc4511.LDAPDN(dn))
    res.setComponentByName('diagnosticMessage', rfc4511.LDAPString(msg))
    return protoutils.pack(mid, op, res, controls)


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
        mock_sock.add_messages([
            obj_to_lm(1, '', {
                'namingContexts': [expected_base_dn]
            }),
            search_res_done(1, '')
        ])

        ldap = LDAP(mock_sock)
        self.assertEqual(ldap.base_dn, expected_base_dn)

        # this should complain about insufficient namingContexts
        mock_sock = MockLDAPSocket()
        mock_sock.add_messages([
            obj_to_lm(1, '', {}),
            search_res_done(1, '')
        ])

        with self.assertRaises(exceptions.LDAPError):
            LDAP(mock_sock)

        # this should complain about too many namingContexts
        mock_sock = MockLDAPSocket()
        mock_sock.add_messages([
            obj_to_lm(1, '', {
                'namingContexts': [
                    'o=test1',
                    'o=test2',
                ]
            }),
            search_res_done(1, '')
        ])

        with self.assertRaises(exceptions.LDAPError):
            LDAP(mock_sock)

        # this should get the defaultNamingContext and ignore namingContexts
        expected_base_dn = 'o=defaultnc'
        mock_sock = MockLDAPSocket()
        mock_sock.add_messages([
            obj_to_lm(1, '', {
                'defaultNamingContext': [expected_base_dn],
                'namingContexts': [
                    'o=foo',
                    'o=bar',
                ]
            }),
            search_res_done(1, '')
        ])

        ldap = LDAP(mock_sock)
        self.assertEqual(ldap.base_dn, expected_base_dn)

        # this should get the passed-in base_dn and ignore others
        mock_sock = MockLDAPSocket()
        mock_sock.add_messages([
            obj_to_lm(1, '', {
                'defaultNamingContext': ['o=foobar'],
                'namingContexts': [
                    'o=foo',
                    'o=bar',
                ]
            }),
            search_res_done(1, '')
        ])

        expected_base_dn = 'o=passedin'
        ldap = LDAP(mock_sock, base_dn=expected_base_dn)
        self.assertEqual(ldap.base_dn, expected_base_dn)

    def test_get(self):
        """Ensure the get function handles various result numbers properly"""

        # Test no results
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        mock_sock.add_messages([search_res_done(2, 'o=foo')])
        ldap = LDAP(mock_sock)

        with self.assertRaises(exceptions.NoSearchResults):
            ldap.get('o=foo')

        # Test multiple results
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        mock_sock.add_messages([
            obj_to_lm(2, 'o=foo', {}),
            obj_to_lm(2, 'o=foo', {}),
            search_res_done(2, 'o=foo'),
        ])
        ldap = LDAP(mock_sock)

        with self.assertRaises(exceptions.MultipleSearchResults):
            ldap.get('o=foo')

        # Note: exactly 1 result is already exercised by test_init_base_dn

    def test_exists(self):
        """Ensure the exists function handles various result numbers properly"""

        # Test no results
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        mock_sock.add_messages([search_res_done(2, 'o=foo')])
        ldap = LDAP(mock_sock)

        self.assertFalse(ldap.exists('o=foo'))

        # Test multiple results
        mock_sock.add_messages([
            obj_to_lm(3, 'o=foo', {}),
            obj_to_lm(3, 'o=foo', {}),
            search_res_done(3, 'o=foo'),
        ])

        self.assertTrue(ldap.exists('o=foo'))

        # Test exactly one result
        mock_sock.add_messages([
            obj_to_lm(4, 'o=foo', {}),
            search_res_done(4, 'o=foo'),
        ])

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
        mock_sock.add_messages([
            obj_to_lm(1, '', root_dse),
            search_res_done(1, ''),
        ])
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
        mock_sock.add_messages([
            obj_to_lm(1, '', root_dse),
            search_res_done(1, ''),
        ])
        # the constructor performs the initial root dse query
        ldap = LDAP(mock_sock)

        # the first recheck is identical and should work fine
        mock_sock.add_messages([
            obj_to_lm(2, '', root_dse),
            search_res_done(2, ''),
        ])
        ldap.recheck_sasl_mechs()

        # the second recheck eliminates some of the previous mechs and should raise an error
        root_dse['supportedSASLMechanisms'] = ['DIGEST-MD5']
        mock_sock.add_messages([
            obj_to_lm(3, '', root_dse),
            search_res_done(3, ''),
        ])
        with self.assertRaises(exceptions.LDAPError):
            ldap.recheck_sasl_mechs()

    def test_duplicate_tag(self):
        """Ensure trying to define a duplicate tag is an error"""
        tag = 'foobar'
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)
        ldap.obj('o=foo', tag=tag)
        with self.assertRaises(exceptions.TagError):
            ldap.obj('o=bar', tag=tag)

    def test_tagging(self):
        """Ensure setting and retreiving tags works"""
        tag = 'foobar'
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
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
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)

        base_dn = 'ou=foo,o=testing'
        uri = 'ldap://test.net/ou=foo,o=testing'

        mock_sock.add_messages([
            search_res_ref(2, [uri]),
            search_res_done(2, base_dn)
        ])

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
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)

        mock_sock.add_messages([
            search_res_done(2, '', result_code=protoutils.RESULT_compareTrue)
        ])

        with self.assertRaises(exceptions.LDAPError):
            list(ldap.search(''))

    def test_search_nosuchobject_response(self):
        """Ensure noSuchObject response is treated as no results"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)

        mock_sock.add_messages([
            search_res_done(2, '', result_code=rfc4511.ResultCode('noSuchObject'))
        ])

        self.assertEqual(len(list(ldap.search(''))), 0)

    def test_search_referral(self):
        """Ensure a referral response is handled correctly for search"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)

        uri = 'ldap://test.net/ou=foo,o=testing'
        mock_sock.add_messages([search_res_done(2, '', referral=[uri])])

        with ldap.search('', follow_referrals=False) as search:
            results = list(search)
            self.assertEqual(len(results), 0)

        # TODO: test with follow_referrals set True, will need to mock SearchReferenceHandle

    def test_compare(self):
        """Ensure compare returns correct boolean results"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)

        mock_sock.add_messages([
            ldap_result(rfc4511.CompareResponse, 2, 'compareResponse', dn='',
                        result_code=protoutils.RESULT_compareTrue)
        ])
        actual = ldap.compare('', 'foo', 'bar')
        self.assertTrue(actual)

        mock_sock.add_messages([
            ldap_result(rfc4511.CompareResponse, 3, 'compareResponse', dn='',
                        result_code=protoutils.RESULT_compareFalse)
        ])
        actual = ldap.compare('', 'foo', 'bar')
        self.assertFalse(actual)

    def test_add_bad_response(self):
        """Ensure non-success results for add are handled correctly"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)

        mock_sock.add_messages([
            ldap_result(rfc4511.AddResponse, 2, 'addResponse', dn='', result_code=protoutils.RESULT_compareTrue)
        ])

        with self.assertRaises(exceptions.LDAPError):
            ldap.add('o=foo', {})

    def test_modify_zero_length(self):
        """Ensure zero-length modlists are ignored"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()
        ldap.modify('', [])
        self.assertEqual(mock_sock.num_sent(), 0)

    def test_modify(self):
        """Ensure protocol-level modlist is contructed without error"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)

        mock_sock.add_messages([
            ldap_result(rfc4511.ModifyResponse, 2, 'modifyResponse')
        ])
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
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)

        mock_sock.add_messages([
            ldap_result(rfc4511.ModifyResponse, 2, 'modifyResponse', result_code=protoutils.RESULT_compareFalse)
        ])
        with self.assertRaises(exceptions.LDAPError):
            ldap.modify('', [
                Mod(Mod.ADD, 'foo', ['bar', 'baz']),
            ])

    def test_add_attrs(self):
        """Ensure add_attrs behaves correctly"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()

        # current is not None
        # should NOT perform a search
        mock_sock.add_messages([
            ldap_result(rfc4511.ModifyResponse, 2, 'modifyResponse'),
        ])
        ldap.add_attrs('', {'foo': ['bar']}, current=LDAPObject('', {}))
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # current is None and not strict_modify
        # should perform a search before modify
        mock_sock.add_messages([
            obj_to_lm(3, '', {'abc': ['def']}),
            search_res_done(3, ''),
            ldap_result(rfc4511.ModifyResponse, 4, 'modifyResponse'),
        ])
        ldap.strict_modify = False
        ldap.add_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 2)
        protoutils.unpack('searchRequest', mock_sock.read_sent())
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # current is None and strict_modify
        # should NOT perform a search
        mock_sock.add_messages([
            ldap_result(rfc4511.ModifyResponse, 5, 'modifyResponse'),
        ])
        ldap.strict_modify = True
        ldap.add_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

    def test_delete_attrs(self):
        """Ensure delete_attrs behaves correctly"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()

        # current is not None
        # should NOT perform a search
        mock_sock.add_messages([
            ldap_result(rfc4511.ModifyResponse, 2, 'modifyResponse'),
        ])
        ldap.delete_attrs('', {'foo': ['bar']}, current=LDAPObject('', {'foo': ['bar']}))
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # current is None and not strict_modify
        # should perform a search before modify
        mock_sock.add_messages([
            obj_to_lm(3, '', {'foo': ['bar']}),
            search_res_done(3, ''),
            ldap_result(rfc4511.ModifyResponse, 4, 'modifyResponse'),
        ])
        ldap.strict_modify = False
        ldap.delete_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 2)
        protoutils.unpack('searchRequest', mock_sock.read_sent())
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # current is None and strict_modify
        # should NOT perform a search
        mock_sock.add_messages([
            ldap_result(rfc4511.ModifyResponse, 5, 'modifyResponse'),
        ])
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
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()

        # current is None and have validators and not strict_modify
        # SHOULD perform a search before modify
        ldap.validators = [MockValidator()]
        ldap.strict_modify = False
        mock_sock.add_messages([
            obj_to_lm(2, '', {'foo': ['bar']}),
            search_res_done(2, ''),
            ldap_result(rfc4511.ModifyResponse, 3, 'modifyResponse'),
        ])
        ldap.strict_modify = False
        ldap.replace_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 2)
        protoutils.unpack('searchRequest', mock_sock.read_sent())
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # else
        # SHOULD NOT perform a search, only modify
        ldap.validators = []
        mock_sock.add_messages([
            ldap_result(rfc4511.ModifyResponse, 4, 'modifyResponse'),
        ])
        ldap.replace_attrs('', {'foo': ['bar']})
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

    def test_who_am_i(self):
        """Exercise the extension subsystem"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)

        # ensure unsupported extensions raise an exceptions
        with self.assertRaises(exceptions.LDAPSupportError):
            ldap.who_am_i()

        # make the who am i operation supported
        root_dse = {
            'namingContexts': ['o=testing'],
            'supportedExtension': [LDAP.OID_WHOAMI],
        }
        mock_sock.add_messages([
            obj_to_lm(2, '', root_dse),
            search_res_done(2, ''),
            ldap_result(rfc4511.ExtendedResponse, 3, 'extendedResp'),
        ])
        ldap.refresh_root_dse()
        ldap.who_am_i()

        # test failure result
        mock_sock.add_messages([
            ldap_result(rfc4511.ExtendedResponse, 4, 'extendedResp', result_code=protoutils.RESULT_compareFalse),
        ])
        with self.assertRaises(exceptions.LDAPError):
            ldap.who_am_i()

    def test_activate_extension(self):
        """Ensure extension activation/loading works"""
        netgroups = LDAP.activate_extension('laurelin.extensions.netgroups')
        self.assertIsInstance(netgroups, ModuleType)
        self.assertTrue(hasattr(LDAP, 'get_netgroup'))

        with self.assertRaises(ImportError):
            LDAP.activate_extension('i.am.not.a.module')

    def test_unbind(self):
        """Test unbind/unbound behavior"""
        mock_sock = MockLDAPSocket()
        add_root_dse(mock_sock)
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
        add_root_dse(mock_sock)
        ldap = LDAP(mock_sock)
        mock_sock.bound = True

        bound_fail_methods = [
            ldap.simple_bind,
            ldap.sasl_bind
        ]

        for method in bound_fail_methods:
            with self.assertRaises(exceptions.ConnectionAlreadyBound):
                method()


if __name__ == '__main__':
    unittest.main()