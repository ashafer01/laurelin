from laurelin.ldap.attrsdict import AttrsDict
import unittest


class TestAttrsDict(unittest.TestCase):
    def test_init_update(self):
        """Test that types are properly checked at init"""

        test_ok = {'abc': ['def', 'ghi']}
        AttrsDict(test_ok)

        test_bad_key = {('abc',): ['def']}
        with self.assertRaises(TypeError):
            AttrsDict(test_bad_key)

        test_bad_value = {'abc': 'def'}
        with self.assertRaises(TypeError):
            AttrsDict(test_bad_value)


class TestContains(unittest.TestCase):
    """Test __contains__"""

    def setUp(self):
        self.k1 = 'abCdef'
        self.k2 = 'abc'
        self.testobj = AttrsDict({
            self.k1: ['ghi', 'jkl'],
            self.k2: [],
        })

    def test_case_exact(self):
        self.assertIn(self.k1, self.testobj)

    def test_case_insensitive(self):
        self.assertIn(self.k1.upper(), self.testobj)

    def test_empty_list(self):
        self.assertNotIn(self.k2, self.testobj)

    def test_empty_list_insensitive(self):
        self.assertNotIn(self.k2.upper(), self.testobj)

    def test_non_existant_key(self):
        self.assertNotIn('foo', self.testobj)


class TestGets(unittest.TestCase):
    """Tests get, getAttr, and __getitem__"""

    def setUp(self):
        self.k = 'abcDef'
        self.v = ['foo', 'bar']
        self.testobj = AttrsDict({
            self.k: self.v
        })

    def test_get(self):
        self.assertIs(self.testobj.get(self.k), self.v)

    def test_get_insensitive(self):
        self.assertIs(self.testobj[self.k.upper()], self.v)

    def test_get_attr_notexists(self):
        v = self.testobj.get_attr('foo')
        self.assertIsInstance(v, list)
        self.assertEqual(len(v), 0)

    def test_get_attr_exists(self):
        self.assertIs(self.testobj.get_attr(self.k), self.v)

    def test_get_default(self):
        expect = 'foobar'
        actual = self.testobj.get('foo', expect)
        self.assertIs(expect, actual)


class TestSetsDeletes(unittest.TestCase):
    """Tests setting and deleting individual items"""

    def setUp(self):
        self.testobj = AttrsDict()

    def test_set_retreive_delete(self):
        k = 'abcdEf'
        v = ['foo', 'bar']
        self.testobj[k] = v
        self.assertEqual(self.testobj[k.upper()], v)
        del self.testobj[k]
        self.assertNotIn(k, self.testobj)

    def test_invalid_key(self):
        k = ('foo',)
        v = ['bar']
        with self.assertRaises(TypeError):
            self.testobj[k] = v

    def test_invalid_value(self):
        k = 'foo'
        v = 'bar'
        with self.assertRaises(TypeError):
            self.testobj[k] = v

    def test_setdefault_notexists_retreive(self):
        k = 'aBcDefg'
        v = ['foo', 'bar']
        actual = self.testobj.setdefault(k, v)
        self.assertIs(actual, v)
        self.assertIs(self.testobj[k.upper()], v)
        del self.testobj[k]

    def test_setdefault_exists(self):
        k = 'abcDef'
        v = ['foo','bar']
        d = ['other', 'another']
        self.testobj[k] = v
        actual = self.testobj.setdefault(k, d)
        self.assertIs(actual, v)
        del self.testobj[k]

    def test_setdefault_invalid_key(self):
        k = ('foo',)
        v = ['bar']
        with self.assertRaises(TypeError):
            self.testobj.setdefault(k, v)

    def test_setdefault_invalid_default(self):
        k = 'foo'
        v = 'bar'
        with self.assertRaises(TypeError):
            self.testobj.setdefault(k, v)
