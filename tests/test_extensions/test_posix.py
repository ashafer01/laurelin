import unittest
from laurelin.ldap import LDAP, Scope
from laurelin.ldap import rfc4511
from ..utils import load_schema
from ..mock_ldapsocket import MockSockRootDSE


class TestPosixExtension(unittest.TestCase):
    def setUp(self):
        load_schema()
        self.posix = LDAP.activate_extension('laurelin.extensions.posix')

    def test__find_available_idnumber(self):
        """Test the _find_available_idnumber function"""

        min = 100
        expected = str(min)
        actual = self.posix._find_available_idnumber([], min, True)
        self.assertEqual(expected, actual, msg='Empty id_number list handling')

        actual = self.posix._find_available_idnumber([103], min, True)
        self.assertEqual(expected, actual, msg='Single id_number list entry with fill_gaps')

        expected = '104'
        actual = self.posix._find_available_idnumber([103], min, False)
        self.assertEqual(expected, actual, msg='Single id_number list entry without fill_gaps')

        with self.assertRaises(self.posix.LDAPPOSIXError, msg='Detect duplicate id numbers'):
            self.posix._find_available_idnumber([107, 105, 106, 105], min, False)

        expected = str(min)
        actual = self.posix._find_available_idnumber([105, 103, 104], min, True)
        self.assertEqual(expected, actual, msg='Detect that min is available')

        expected = '106'
        actual = self.posix._find_available_idnumber([105, 103, 104], min, False)
        self.assertEqual(expected, actual, msg='No fill_gaps on arbitrary sequence')

        expected = str(min+4)
        actual = self.posix._find_available_idnumber([min, min+3, min+1, min+2], min, True)
        self.assertEqual(expected, actual, msg='Ensure going off the end of the sequence increments the highest id')

        expected = str(min+2)
        actual = self.posix._find_available_idnumber([min, min+3, min+1], min, True)
        self.assertEqual(expected, actual, msg='Find gap')

    def test_add_user(self):
        mock_sock = MockSockRootDSE()
        ldap = LDAP(mock_sock)

        ldap.base.obj('ou=people',
                      tag=self.posix.USERS_BASE_TAG,
                      rdn_attr='uid',
                      relative_search_scope=Scope.ONE)

        test_uid = 'foo'
        test_homedir_format = '/x/{uid}'
        self.posix.HOMEDIR_FORMAT = test_homedir_format

        expected_homedir = test_homedir_format.format(uid=test_uid)
        expected_ocs = set(['posixAccount', 'organizationalPerson'])

        mock_sock.add_ldap_result(rfc4511.AddResponse, 'addResponse')
        user = ldap.add_user(uid=test_uid, uidNumber='742', postalAddress='foo', userPassword='foo')

        self.assertEqual(user['homeDirectory'][0], expected_homedir,
                         'home directory not correctly formatted')
        self.assertEqual(set(user['objectClass']), expected_ocs,
                         'incorrect auto objectClass selection')
        self.assertEqual(user['gidNumber'][0], self.posix.DEFAULT_GIDNUMBER,
                         'default gidNumber not set')
        self.assertEqual(user['cn'][0], test_uid,
                         'cn not set to username')

        mock_sock.add_ldap_result(rfc4511.AddResponse, 'addResponse')
        user = ldap.add_user(uid=test_uid, uidNumber='742', carLicense='foo', userPassword='foo')

        expected_ocs = set(['posixAccount', 'inetOrgPerson'])
        self.assertEqual(set(user['objectClass']), expected_ocs,
                         'incorrect auto objectClass selection')

        mock_sock.add_search_res_entry('a=b,x=y', {'uidNumber': ['1000']})
        mock_sock.add_search_res_entry('a=c,x=y', {'uidNumber': ['1003']})
        mock_sock.add_search_res_done('x=y')
        mock_sock.add_ldap_result(rfc4511.AddResponse, 'addResponse')

        user = ldap.add_user(uid=test_uid, fill_gaps=True)
        self.assertEqual(user['uidNumber'][0], '1001',
                         'incorrect auto uidNumber selection with fill_gaps enabled')

        mock_sock.add_search_res_entry('a=b,x=y', {'uidNumber': ['1001']})
        mock_sock.add_search_res_entry('a=c,x=y', {'uidNumber': ['1003']})
        mock_sock.add_search_res_done('x=y')
        mock_sock.add_ldap_result(rfc4511.AddResponse, 'addResponse')

        user = ldap.add_user(uid=test_uid, fill_gaps=False)
        self.assertEqual(user['uidNumber'][0], '1004',
                         'incorrect auto uidNumber selection with fill_gaps disabled')

    def test_add_group(self):
        mock_sock = MockSockRootDSE()
        ldap = LDAP(mock_sock)

        ldap.base.obj('ou=groups',
                      tag=self.posix.GROUPS_BASE_TAG,
                      rdn_attr='cn',
                      relative_search_scope=Scope.ONE)

        test_cn = 'testgroup'

        mock_sock.add_search_res_entry('a=b,x=y', {'gidNumber': ['1000']})
        mock_sock.add_search_res_entry('a=c,x=y', {'gidNumber': ['1003']})
        mock_sock.add_search_res_done('x=y')
        mock_sock.add_ldap_result(rfc4511.AddResponse, 'addResponse')

        user = ldap.add_group(cn=test_cn, fill_gaps=True)
        self.assertEqual(user['gidNumber'][0], '1001',
                         'incorrect auto gidNumber selection with fill_gaps enabled')

        mock_sock.add_search_res_entry('a=b,x=y', {'gidNumber': ['1001']})
        mock_sock.add_search_res_entry('a=c,x=y', {'gidNumber': ['1003']})
        mock_sock.add_search_res_done('x=y')
        mock_sock.add_ldap_result(rfc4511.AddResponse, 'addResponse')

        user = ldap.add_group(cn=test_cn, fill_gaps=False)
        self.assertEqual(user['gidNumber'][0], '1004',
                         'incorrect auto gidNumber selection with fill_gaps disabled')
