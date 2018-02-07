from laurelin.ldap.attrsdict import AttrsDict

def test_init_update():
    """Test that types are properly checked at init"""

    test_ok = {'abc': ['def', 'ghi']}
    AttrsDict(test_ok)

    test_bad_key = {('abc',): ['def']}
    try:
        AttrsDict(test_bad_key)
        assert False
    except TypeError:
        pass

    test_bad_value = {'abc': 'def'}
    try:
        AttrsDict(test_bad_value)
        assert False
    except TypeError:
        pass

class TestContains(object):
    """Test __contains__"""

    def __init__(self):
        self.k1 = 'abCdef'
        self.k2 = 'abc'
        self.testobj = AttrsDict({
            self.k1: ['ghi', 'jkl'],
            self.k2: [],
        })

    def test_case_exact(self):
        assert (self.k1 in self.testobj)

    def test_case_insensitive(self):
        assert (self.k1.upper() in self.testobj)

    def test_empty_list(self):
        assert (self.k2 in self.testobj) is False

    def test_empty_list_insensitive(self):
        assert (self.k2.upper() in self.testobj) is False

    def test_non_existant_key(self):
        assert ('foo' in self.testobj) is False


class TestGets(object):
    """Tests get, getAttr, and __getitem__"""

    def __init__(self):
        self.k = 'abcDef'
        self.v = ['foo', 'bar']
        self.testobj = AttrsDict({
            self.k: self.v
        })

    def test_get(self):
        assert self.testobj.get(self.k) is self.v

    def test_get_insensitive(self):
        assert self.testobj[self.k.upper()] is self.v

    def test_getAttr_notexists(self):
        v = self.testobj.get_attr('foo')
        assert isinstance(v, list)
        assert (len(v) == 0)

    def test_getAttr_exists(self):
        assert self.testobj.get_attr(self.k) is self.v

    def test_get_default(self):
        expect = 'foobar'
        actual = self.testobj.get('foo', expect)
        assert expect is actual


class TestSetsDeletes(object):
    """Tests setting and deleting individual items"""

    def __init__(self):
        self.testobj = AttrsDict()

    def test_set_retreive_delete(self):
        k = 'abcdEf'
        v = ['foo', 'bar']
        self.testobj[k] = v
        assert (self.testobj[k.upper()] == v)
        del self.testobj[k]
        assert (k not in self.testobj)

    def test_invalid_key(self):
        k = ('foo',)
        v = ['bar']
        try:
            self.testobj[k] = v
            assert False
        except TypeError:
            pass

    def test_invalid_value(self):
        k = 'foo'
        v = 'bar'
        try:
            self.testobj[k] = v
            assert False
        except TypeError:
            pass

    def test_setdefault_notexists_retreive(self):
        k = 'aBcDefg'
        v = ['foo', 'bar']
        actual = self.testobj.setdefault(k, v)
        assert (actual is v)
        assert (self.testobj[k.upper()] is v)
        del self.testobj[k]

    def test_setdefault_exists(self):
        k = 'abcDef'
        v = ['foo','bar']
        d = ['other', 'another']
        self.testobj[k] = v
        actual = self.testobj.setdefault(k, d)
        assert (actual is v)
        del self.testobj[k]

    def test_setdefault_invalid_key(self):
        k = ('foo',)
        v = ['bar']
        try:
            self.testobj.setdefault(k, v)
            assert False
        except TypeError:
            pass

    def test_setdefault_invalid_default(self):
        k = 'foo'
        v = 'bar'
        try:
            self.testobj.setdefault(k, v)
            assert False
        except TypeError:
            pass
