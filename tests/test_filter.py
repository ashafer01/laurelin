from laurelin.ldap import filter, LDAPError
import unittest


class TestFilter(unittest.TestCase):
    def test_parse(self):
        """Exercise filter parsing"""
        good_filters = [
            '(foo=bar)',
            '(foo>=1)',
            '(foo<=1)',
            '(foo~=bar)',
            '(foo:=bar)',
            '(foo:dn:=bar)',
            '(foo:1.2.3.4:=bar)',
            '(:1.2.3.4:=bar)',
            '(foo:dn:1.2.3.4:=bar)',
            '(:dn:1.2.3.4:=bar)',
            '(foo=*)',
            '(foo=*abc*)',
            '(foo=abc*)',
            '(foo=*abc)',
            '(foo=abc*def)',
            '(foo=*abc*def*)',
            '(foo=abc*def*)',
            '(foo=*abc*def)',
            '(&(foo=bar))',
            '(&(foo=bar)(foo>=1)(foo:1.2.3.4:=bar))',
            '(|(foo=bar))',
            '(|(foo=bar)(foo<=1)(foo=*abc*def))',
            '(!(foo=bar))',
            '(&(foo=bar)(!(foo=bar))(|(foo=bar)(foo<=1)(foo=*abc*def)))',
        ]
        for f in good_filters:
            try:
                filter.parse(f)
            except Exception as e:
                self.fail('Failed on good filter - {0} - {1}: {2}'.format(f, e.__class__.__name__, str(e)))

        bad_filters = [
            'foo=bar',
            '(foo=bar',
            '(foo<1)',
            '(foo>1)',
            '(foo~bar)',
            '(foo:bar)',
            '(foo*)',
            '(:x:1.2.3.4:=foo)',
            '(::::::=foo)',
        ]
        for f in bad_filters:
            with self.assertRaises(LDAPError):
                filter.parse(f)
