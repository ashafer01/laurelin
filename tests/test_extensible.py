import six
import unittest
from laurelin.ldap import add_extension, LDAP, extensible
from laurelin.ldap.exceptions import LDAPExtensionError
from .mock_ldapsocket import MockSockRootDSE


class TestAddExtension(unittest.TestCase):
    def test_add_extension_already_defined(self):
        """Ensure add_extension works when adding an extension already defined in AVAILABLE_EXTENSIONS"""
        add_extension('laurelin.extensions.pagedresults')

    def test_add_extension(self):
        """Test adding an extension works"""
        add_extension('tests.mock_extension')
        ldap = LDAP(MockSockRootDSE())
        self.assertEqual(ldap.mock_ext.foo(), 'foo')
        self.assertEqual(ldap.base.mock_ext.bar(), 'bar')

    def test_add_extension_again(self):
        """Ensure adding an extension multiple times does not generate an error"""
        add_extension('tests.mock_extension')
        add_extension('tests.mock_extension')
        add_extension('tests.mock_extension')
        ldap = LDAP(MockSockRootDSE())
        self.assertEqual(ldap.mock_ext.foo(), 'foo')
        self.assertEqual(ldap.base.mock_ext.bar(), 'bar')

    def test_instance_per_instance(self):
        """Ensure there is only one extension instance per extended instance"""
        add_extension('tests.mock_extension')
        ldap = LDAP(MockSockRootDSE())
        self.assertIs(ldap.mock_ext, ldap.mock_ext)

        ldap2 = LDAP(MockSockRootDSE())
        self.assertIs(ldap2.mock_ext, ldap2.mock_ext)
        self.assertIsNot(ldap2.mock_ext, ldap.mock_ext)

        ldapobj = ldap.base
        self.assertIs(ldapobj.mock_ext, ldapobj.mock_ext)
        self.assertIsNot(ldap.mock_ext, ldapobj.mock_ext)

        ldapobj2 = ldap2.base
        self.assertIs(ldapobj2.mock_ext, ldapobj2.mock_ext)
        self.assertIsNot(ldapobj2.mock_ext, ldapobj.mock_ext)


class TestAvailableExtensions(unittest.TestCase):
    def test_instance_per_instance(self):
        """Ensure only one instance is created for a defined extension"""
        ldap = LDAP(MockSockRootDSE())
        self.assertIs(ldap.netgroups, ldap.netgroups)

        ldap2 = LDAP(MockSockRootDSE())
        self.assertIs(ldap2.netgroups, ldap2.netgroups)
        self.assertIsNot(ldap2.netgroups, ldap.netgroups)

        ldapobj = ldap.base
        self.assertIs(ldapobj.netgroups, ldapobj.netgroups)
        self.assertIsNot(ldap.netgroups, ldapobj.netgroups)

        ldapobj2 = ldap2.base
        self.assertIs(ldapobj2.netgroups, ldapobj2.netgroups)
        self.assertIsNot(ldapobj2.netgroups, ldapobj.netgroups)

    def test_import_error(self):
        test_key = 'test_ext'
        test_pip_package = 'not_a_real_pip_package'
        extensible.Extensible.AVAILABLE_EXTENSIONS[test_key] = {
            'module': 'does.not.exist',
            'pip_package': test_pip_package,
            'docstring': 'foo',
        }
        try:
            ldap = LDAP(MockSockRootDSE())
            with six.assertRaisesRegex(self, LDAPExtensionError, test_pip_package):
                ldap._get_extension_instance(test_key)
        finally:
            del extensible.Extensible.AVAILABLE_EXTENSIONS[test_key]
