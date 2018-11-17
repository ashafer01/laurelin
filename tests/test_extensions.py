from laurelin.ldap import extensions
from laurelin.ldap.extensible import Extensible
import unittest


class TestExtensions(unittest.TestCase):
    def test_require_all_extensions(self):
        for name in Extensible.AVAILABLE_EXTENSIONS.keys():
            getattr(extensions, name).require()
