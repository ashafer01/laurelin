from laurelin.ldap import LDAPURI, Scope, exceptions
import unittest


class TestLDAPURI(unittest.TestCase):
    def test_parsing(self):
        """Ensure an LDAPURI gets parsed correctly"""
        scheme = 'ldaps'
        netloc = 'dir.example.org:123'
        dn = 'cn=foo,dc=example,dc=org'
        attrs = ['a', 'b', 'c']
        scope = Scope.ONELEVEL
        filter = '(b=foo)'
        uri = LDAPURI('{0}://{1}/{2}?{3}?{4}?{5}'.format(scheme, netloc, dn, ','.join(attrs), Scope.constant(scope),
                                                         filter))
        self.assertEqual(scheme, uri.scheme)
        self.assertEqual(netloc, uri.netloc)
        self.assertEqual(dn, uri.dn)
        self.assertEqual(attrs, uri.attrs)
        self.assertEqual(scope, uri.scope)
        self.assertEqual(filter, uri.filter)

    def test_bad_crit_extension(self):
        """Ensure an unsupported critical extension raises an error"""
        with self.assertRaises(exceptions.LDAPError):
            LDAPURI('ldaps://foo/o=bar????!NotAURIExtension')

    def test_defaults(self):
        """Ensure missing URI parameters are handled correctly"""
        scheme = 'ldaps'
        netloc = 'foo'
        dn = 'o=bar'

        # test with entirely missing query
        uri = LDAPURI('{0}://{1}/{2}'.format(scheme, netloc, dn))
        self.assertEqual(scheme, uri.scheme)
        self.assertEqual(netloc, uri.netloc)
        self.assertEqual(dn, uri.dn)
        self.assertEqual(LDAPURI.DEFAULT_ATTRS, uri.attrs)
        self.assertEqual(LDAPURI.DEFAULT_SCOPE, uri.scope)
        self.assertEqual(LDAPURI.DEFAULT_FILTER, uri.filter)
        self.assertEqual(LDAPURI.DEFAULT_STARTTLS, uri.starttls)

        # test with unpopulated query
        uri = LDAPURI('{0}://{1}/{2}????'.format(scheme, netloc, dn))
        self.assertEqual(scheme, uri.scheme)
        self.assertEqual(netloc, uri.netloc)
        self.assertEqual(dn, uri.dn)
        self.assertEqual(LDAPURI.DEFAULT_ATTRS, uri.attrs)
        self.assertEqual(LDAPURI.DEFAULT_SCOPE, uri.scope)
        self.assertEqual(LDAPURI.DEFAULT_FILTER, uri.filter)
        self.assertEqual(LDAPURI.DEFAULT_STARTTLS, uri.starttls)


if __name__ == '__main__':
    unittest.main()