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

    def test_parse_standard_filter(self):
        """Exercise filter parsing"""
        for f in self.good_filters:
            try:
                filter.parse_standard_filter(f)
            except Exception as e:
                self.fail('Failed on good filter - {0} - {1}: {2}'.format(f, e.__class__.__name__, str(e)))

        for f in self.bad_filters:
            with self.assertRaises(LDAPError):
                filter.parse_standard_filter(f)

    def test_rfc4511_filter_to_rfc4515_string(self):
        """Exercise reverse parsing function"""
        for f in self.good_filters:
            f_obj = filter.parse_standard_filter(f)
            self.assertEqual(f, filter.rfc4511_filter_to_rfc4515_string(f_obj))

    def test_parse_unified_filter(self):
        """Ensure parse_unified_filter() produces equivalent rfc4511.Filter to parse()"""
        tests = [
            ('(abc=foo)', '(abc=foo)'),
            ('(&(abc=foo)(def=bar))', '(abc=foo) AND (def=bar)'),
            ('(&(abc=foo)(def=bar)(ghi=jkl))', '(abc=foo) AND (def=bar) AND (ghi=jkl)'),
            ('(|(abc=foo)(def=bar)(ghi=jkl))', '(abc=foo) OR (def=bar) OR (ghi=jkl)'),
            ('(&(abc=foo)(|(def=bar)(ghi=jkl)))', '(abc=foo) AND ((def=bar) OR (ghi=jkl))'),
            ('(&(abc=foo)(|(def=bar)(ghi=jkl))(xyz=abc))', '(abc=foo) AND ((def=bar) OR (ghi=jkl)) AND (xyz=abc)'),
            ('(|(abc=foo)(&(def=bar)(ghi=jkl)))', '(abc=foo) OR (def=bar) AND (ghi=jkl)'),
            ('(|(abc=foo)(&(def=bar)(ghi=jkl)))', '(abc=foo) OR ((def=bar) AND (ghi=jkl))'),
            ('(!(abc=foo))', 'NOT (abc=foo)'),
            ('(&(!(abc=foo))(!(def=bar)))', 'NOT (abc=foo) AND NOT (def=bar)'),
            ('(foo=abc AND def)', '(foo=abc AND def)'),
            ('(&(foo=abc AND def)(bar=xyz AND abc))', '(foo=abc AND def) AND (bar=xyz AND abc)'),
            ('(&(foo=abc OR def)(bar=xyz OR abc))', '(foo=abc OR def) AND (bar=xyz OR abc)'),
            ('(&(&(foo=abc)(bar=def))(foo=ghi)(bar=jkl))', '(&(foo=abc)(bar=def)) AND (foo=ghi) AND (bar=jkl)'),
        ]
        for standard, simple in tests:
            f_obj = filter.parse(simple)
            self.assertEqual(standard, filter.rfc4511_filter_to_rfc4515_string(f_obj),
                             msg="Orig simple filter: {0}".format(simple))
