from laurelin.ldap import filter, LDAPError
import unittest


class TestFilter(unittest.TestCase):
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
        '(foo=*abc*def*ghj*)',
        '(foo=*abc*def)',
        '(&(foo=bar))',
        '(&(foo=bar)(foo>=1)(foo:1.2.3.4:=bar))',
        '(|(foo=bar))',
        '(|(foo=bar)(foo<=1)(foo=*abc*def))',
        '(!(foo=bar))',
        '(&(foo=bar)(!(foo=bar))(|(foo=bar)(foo<=1)(foo=*abc*def)))',
    ]

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

    def test_parse(self):
        """Exercise filter parsing"""
        for f in self.good_filters:
            try:
                filter.parse(f)
            except Exception as e:
                self.fail('Failed on good filter - {0} - {1}: {2}'.format(f, e.__class__.__name__, str(e)))

        for f in self.bad_filters:
            with self.assertRaises(LDAPError):
                filter.parse(f)

    def test_rfc4511_filter_to_rfc4515_string(self):
        """Exercise reverse parsing function"""
        for f in self.good_filters:
            f_obj = filter.parse(f)
            self.assertEqual(f, filter.rfc4511_filter_to_rfc4515_string(f_obj))
