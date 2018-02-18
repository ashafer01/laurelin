from laurelin.ldap.extensible import Extensible
from laurelin.ldap import exceptions
import unittest


class MockExtensible(Extensible):
    def foo(self):
        pass


class TestExtensible(unittest.TestCase):
    def test_extend(self):
        # test function
        def bar(self):
            pass
        MockExtensible.EXTEND([bar])
        self.assertTrue(hasattr(MockExtensible, 'bar'))

        # test dupe
        def foo(self):
            pass
        with self.assertRaises(exceptions.LDAPExtensionError):
            MockExtensible.EXTEND([foo])
