import laurelin.ldap
import unittest


class TestMisc(unittest.TestCase):
    def test_dc(self):
        expected = 'dc=foo,dc=example,dc=org'
        actual = laurelin.ldap.dc('foo.example.org')
        self.assertEqual(expected, actual)

    def test_domain(self):
        expected = 'foo.example.org'
        actual = laurelin.ldap.domain('dc=foo,dc=example,dc=org')
        self.assertEqual(expected, actual)
