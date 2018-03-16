from .mock_ldapsocket import MockLDAPSocket
from laurelin.ldap.exceptions import LDAPConnectionError
import unittest


class TestNet(unittest.TestCase):
    def test_check_hostname(self):
        """Ensure check_hostname behaves correctly"""

        mock_sock = MockLDAPSocket()
        mock_sock.host = 'dns-test.example.org'

        bad_cn = 'bad.test.com'

        # test when matching the cert commonName
        mock_sock.check_hostname(mock_sock.host, {})

        # test when matching a subjectAltName
        mock_sock.check_hostname(bad_cn, {
            'subjectAltName': [
                ('DNS', mock_sock.host)
            ]
        })

        # test when matching a wildcard
        mock_sock.check_hostname(bad_cn, {
            'subjectAltName': [
                ('DNS', '*.example.org')
            ]
        })

        # test with no match
        with self.assertRaises(LDAPConnectionError):
            mock_sock.check_hostname(bad_cn, {
                'subjectAltName': [
                    ('DNS', bad_cn)
                ]
            })