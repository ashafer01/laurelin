from laurelin.ldap import (
    LDAP,
    rfc4511,
    protoutils,
    exceptions,
)
import inspect
import unittest
from .mock_ldapsocket import MockLDAPSocket


def obj_to_lm(mid, dn, attrs_dict):
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

    sre.setComponentByName('attributes', attrs)

    return protoutils.pack(mid, 'searchResEntry', sre)


def search_res_done(mid, dn, result_code=protoutils.RESULT_success):
    """Create a searchResDone LDAPMessage"""
    srd = rfc4511.SearchResultDone()
    srd.setComponentByName('resultCode', result_code)
    srd.setComponentByName('matchedDN', rfc4511.LDAPDN(dn))
    srd.setComponentByName('diagnosticMessage', rfc4511.LDAPString('THIS IS A TEST OBJECT'))
    return protoutils.pack(mid, 'searchResDone', srd)


def add_root_dse(mock_sock, mid=1):
    """Add a response to the mock socket for root DSE query"""
    mock_sock.add_messages([
        obj_to_lm(mid, '', {
            'namingContexts': ['o=testing']
        }),
        search_res_done(mid, ''),
    ])


class TestLDAP(unittest.TestCase):
    def setUp(self):
        self.init_params = inspect.getargspec(LDAP.__init__).args
        self.init_params.remove('self')

    def test_global_default_presence(self):
        """Ensure that all parameters of LDAP.__init__ have a global default defined"""
        for param in self.init_params:
            gdefault = param.upper()
            if not gdefault.startswith('DEFAULT'):
                gdefault = 'DEFAULT_'+gdefault
            assert hasattr(LDAP, gdefault) is True

    def test_init_base_dn(self):
        """Test paths for base_dn. This also exercises the search method."""
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


if __name__ == '__main__':
    unittest.main()
