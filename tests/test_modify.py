from laurelin.ldap.modify import Mod, AddModlist, DeleteModlist
import unittest


class TestModify(unittest.TestCase):
    def test_empty_attrs(self):
        """Verify that empty attribute lists work"""
        with self.assertRaises(ValueError):
            Mod(Mod.ADD, 'foo', [])
        Mod(Mod.DELETE, 'foo', [])
        Mod(Mod.REPLACE, 'foo', [])

    def test_mod_string(self):
        """Ensure Mod.string identifies invalid values"""
        with self.assertRaises(ValueError):
            Mod.string('foo')

    def test_mod_op_to_string(self):
        """Ensure Mod.op_to_string identifies invalid values"""
        with self.assertRaises(ValueError):
            Mod.op_to_string(None)

    def test_add_modlist(self):
        """Verify that duplicate attributes are not added"""
        cur_attrs = {
            'foo': ['abc', 'def'],
            'bar': ['ghi'],
        }
        baz = ['whole', 'new', 'attr']
        add_attrs = {
            'foo': ['abc', 'def', 'ghi'],
            'bar': ['jkl'],
            'baz': baz,
        }
        modlist = AddModlist(cur_attrs, add_attrs)
        found_foo = False
        found_bar = False
        found_baz = False
        for mod in modlist:
            if mod.attr == 'foo':
                found_foo = True
                self.assertEqual(mod.vals, ['ghi'])
            elif mod.attr == 'bar':
                found_bar = True
                self.assertEqual(mod.vals, ['jkl'])
            elif mod.attr == 'baz':
                found_baz = True
                self.assertEqual(mod.vals, baz)
            else:
                self.fail('Unexpected attribute modified')
        if not found_foo or not found_bar or not found_baz:
            self.fail('Did not find expected attribute modification')

    def test_delete_modlist(self):
        """Verify that unknown values are not removed"""
        cur_attrs = {
            'foo': ['abc'],
            'bar': ['def'],
        }
        del_attrs = {
            'foo': ['abc', 'def'],
            'bar': ['ghi'],
        }
        modlist = DeleteModlist(cur_attrs, del_attrs)
        found_foo = False
        for mod in modlist:
            if mod.attr == 'foo':
                found_foo = True
                self.assertEqual(mod.vals, ['abc'])
            else:
                self.fail('Unexpected attribute modified')
        if not found_foo:
            self.fail('Did not find expected attribute modification')
