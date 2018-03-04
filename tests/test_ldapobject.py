from laurelin.ldap import LDAP, rfc4511, protoutils, LDAPObject
from .mock_ldapsocket import MockLDAPSocket
import unittest


class TestLDAPObject(unittest.TestCase):
    def test_refresh_missing(self):
        """Ensure refresh_missing behaves correctly"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()

        # ensure we do not send any request if all listed attributes are present
        obj = ldap.obj('o=test', {
            'foo': ['bar'],
            'abc': ['def'],
        })
        obj.refresh_missing(['foo', 'abc'])
        self.assertEqual(mock_sock.num_sent(), 0)

        # ensure new attributes get filled when we do search
        mock_sock.add_search_res_entry('o=test', {
            'new': ['attr']
        })
        mock_sock.add_search_res_done('o=test')
        obj.refresh_missing(['new'])
        self.assertIn('new', obj)
        self.assertEqual(obj['new'], ['attr'])

    def test_add_attrs(self):
        """Ensure LDAPObject.add_attrs behaves correctly."""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()
        test_add_attr = 'foo'
        test_add_vals = ['bar']

        # should perform a search and then a modify if strict_modify is False and attrs in attrs_dict are not present
        # on the object
        obj = ldap.obj('o=test', {
            'test': ['abc', 'def']
        })
        ldap.strict_modify = False
        mock_sock.add_search_res_entry('o=test', {
            test_add_attr: ['baz']
        })
        mock_sock.add_search_res_done('o=test')
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        obj.add_attrs({
            test_add_attr: test_add_vals
        })
        self.assertEqual(mock_sock.num_sent(), 2)
        protoutils.unpack('searchRequest', mock_sock.read_sent())
        protoutils.unpack('modifyRequest', mock_sock.read_sent())
        self.assertIn(test_add_attr, obj)
        self.assertIn(test_add_vals[0], obj[test_add_attr])

        # should only perform a modify regardless of missing attrs if strict_modify is True
        obj = ldap.obj('o=test', {
            'test': ['abc', 'def']
        })
        ldap.strict_modify = True
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        obj.add_attrs({
            test_add_attr: test_add_vals
        })
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())
        self.assertIn(test_add_attr, obj)
        self.assertEqual(obj[test_add_attr], test_add_vals)

        # should never perform an extra search if all attrs in attrs_dict are present
        test_add_attr = 'test'
        test_add_vals = ['foo']

        ldap.strict_modify = False
        obj = ldap.obj('o=test', {
            'test': ['abc', 'def']
        })
        ldap.strict_modify = True
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        obj.add_attrs({
            test_add_attr: test_add_vals
        })
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())
        self.assertIn(test_add_attr, obj)
        self.assertIn(test_add_vals[0], obj[test_add_attr])

        ldap.strict_modify = True
        obj = ldap.obj('o=test', {
            'test': ['abc', 'def']
        })
        ldap.strict_modify = True
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        obj.add_attrs({
            test_add_attr: test_add_vals
        })
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())
        self.assertIn(test_add_attr, obj)
        self.assertIn(test_add_vals[0], obj[test_add_attr])

    def test_delete_attrs(self):
        """Ensure LDAPObject.delete_attrs behaves correctly."""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)
        mock_sock.clear_sent()

        # should perform a search and then a modify if strict_modify is False and attrs in attrs_dict are not present
        # on the object
        obj = ldap.obj('o=test', {
            'test': ['abc', 'def']
        })
        ldap.strict_modify = False
        mock_sock.add_search_res_entry('o=test', {
            'foo': ['bar']
        })
        mock_sock.add_search_res_done('o=test')
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        obj.delete_attrs({
            'foo': ['bar']
        })
        self.assertEqual(mock_sock.num_sent(), 2)
        protoutils.unpack('searchRequest', mock_sock.read_sent())
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        # should never perform an extra search if all attrs in attrs_dict are present
        # strict_modify False and strict_modify True
        ldap.strict_modify = False
        obj = ldap.obj('o=test', {
            'test': ['abc', 'def']
        })
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        obj.delete_attrs({
            'test': ['abc']
        })
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

        ldap.strict_modify = True
        obj = ldap.obj('o=test', {
            'test': ['abc', 'def']
        })
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        obj.delete_attrs({
            'test': ['abc']
        })
        self.assertEqual(mock_sock.num_sent(), 1)
        protoutils.unpack('modifyRequest', mock_sock.read_sent())

    def test_replace_attrs(self):
        """Excercise replace_attrs"""
        mock_sock = MockLDAPSocket()
        mock_sock.add_root_dse()
        ldap = LDAP(mock_sock)

        obj = ldap.obj('o=test', {
            'test': ['abc'],
            'deleteme': ['foo'],
        })
        mock_sock.add_ldap_result(rfc4511.ModifyResponse, 'modifyResponse')
        obj.replace_attrs({
            'test': ['def'],
            'foo': ['bar'],
            'deleteme': [],
        })
        self.assertIn('test', obj)
        self.assertIn('foo', obj)
        self.assertNotIn('deleteme', obj)
        self.assertEqual(obj['test'], ['def'])
        self.assertEqual(obj['foo'], ['bar'])

    def test_format_ldif(self):
        """Exercise format_ldif"""
        o = LDAPObject('o=foo ', {
            'binaryAndNormal': [b'\xff\xab\xcd\xef', 'abc'],
            'encodeBadLeading': [
                ':leading colon must be encoded',
                ' leading space must be encoded',
                '<leading left angle must be encoded',
            ],
            'encodeBadChar': [
                'newlines\nmust be encoded',
                'cr\rmust be encoded',
                'null\0must be encoded',
            ],
            'lineFold': ['abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmno'
                         'pqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzab'],
        })
        o.format_ldif()
