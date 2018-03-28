from . import utils
from .mock_ldapsocket import MockSockRootDSE
from laurelin.ldap import config, LDAP, LDAPObject
from laurelin.ldap.base import LDAPResponse
import laurelin.ldap.base
import six
import unittest

mock = utils.import_install_mock()


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.schema = utils.load_schema()

    def test_normalize_global_config_param(self):
        """Ensure normalize_global_config_param functions correctly"""
        tests = [
            ('foo', 'DEFAULT_FOO'),
            ('DEFAULT_FOO', 'DEFAULT_FOO'),
            ('default_foo', 'DEFAULT_FOO'),
        ]

        for test, expected in tests:
            actual = config.normalize_global_config_param(test)
            self.assertEqual(expected, actual)

    def test_set_global_config(self):
        """Ensure set_global_config functions correctly"""
        with self.assertRaises(KeyError):
            config.set_global_config({'foo': 'bar'})

        with self.assertRaises(KeyError):
            config.set_global_config({'global': {
                'not_a_global_config_param': 'foo'
            }})

        reset_config = {'global': {
            'DEFAULT_CRITICALITY': LDAP.DEFAULT_CRITICALITY,
            'DEFAULT_SSL_CA_PATH': LDAP.DEFAULT_SSL_CA_PATH,
        }}

        try:
            working_config = {'global': {
                'DEFAULT_CRITICALITY': True,
                'ssl_ca_path': '/etc/ldap/cacerts',
            }}

            config.set_global_config(working_config)

            for key, val in six.iteritems(working_config['global']):
                key = config.normalize_global_config_param(key)
                self.assertEqual(getattr(LDAP, key), val)
        finally:
            config.set_global_config(reset_config)

    @mock.patch.object(laurelin.ldap.base, 'LDAPSocket', MockSockRootDSE)
    @mock.patch('laurelin.ldap.LDAP.simple_bind', return_value=LDAPResponse())
    @mock.patch('laurelin.ldap.LDAP.sasl_bind', return_value=LDAPResponse())
    @mock.patch('laurelin.ldap.LDAP.start_tls', return_value=None)
    def test_create_connection(self, *args):
        """Ensure create_connection functions properly"""

        with self.assertRaises(KeyError):
            config.create_connection({'foo': 'bar'})

        with self.assertRaises(TypeError):
            config.create_connection({'connection': {
                'simple_bind': {'a': 'b'},
                'sasl_bind': {'a': 'b'},
            }})

        with self.assertRaises(TypeError):
            config.create_connection({'connection': {
                'not_a_contructor_keyword_arg': True,
            }})

        conn = {
            'server': 'ldap://dir01.example.org',
            'reuse_connection': False,
            'start_tls': True,
            'simple_bind': {
                'username': 'testuser',
                'password': 'testpass',
            }
        }

        config.create_connection({'connection': conn})

        with self.assertRaises(TypeError):
            config.create_connection({'connection': conn, 'objects': [{
                'dn': 'foo',
                'rdn': 'foo',
            }]})

        with self.assertRaises(TypeError):
            config.create_connection({'connection': conn, 'objects': [{
                'rdn': 'foo',
            }]})

        with self.assertRaises(TypeError):
            config.create_connection({'connection': conn, 'objects': [{
                'tag': 'foo',
            }]})

        tag = 'foo'
        ldap = config.create_connection({'connection': conn, 'objects': [{
            'rdn': 'o=foo',
            'tag': tag,
            'relative_search_scope': 'one',
        }]})
        self.assertIsInstance(ldap.tag(tag), LDAPObject)

        conn['validators'] = ['laurelin.ldap.schema.SchemaValidator']
        ldap = config.create_connection({'connection': conn})
        self.assertIsInstance(ldap.validators[0], self.schema.SchemaValidator)

        validator = self.schema.SchemaValidator()
        conn['validators'] = [validator]
        ldap = config.create_connection({'connection': conn})
        self.assertIs(ldap.validators[0], validator)

        conn['validators'] = [('foo',)]
        with self.assertRaises(TypeError):
            config.create_connection({'connection': conn})
        del conn['validators']
