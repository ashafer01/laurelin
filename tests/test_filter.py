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

    good_standard_and_simple_filters = [
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
        ('(!(!(foo=abc)))', 'NOT NOT (foo=abc)'),
        ('(!(&(foo=abc)(bar=def)))', 'NOT ((foo=abc) AND (bar=def))'),
        ('(!(|(foo=abc)(bar=def)))', 'NOT ((foo=abc) OR (bar=def))'),
    ]

    bad_simple_filters = [
        'foo=bar',
        'AND (foo=bar)',
        '(foo=bar) OR',
        '(foo=bar) AND OR (foo=abc)',
        '(foo=bar) NOT AND (foo=abc)',
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

    def test_standard_with_unified(self):
        """Ensure all the standard test filters produce equivalent results with unified parser"""
        for standard in self.good_filters:
            f_obj = filter.parse(standard)
            self.assertEqual(standard, filter.rfc4511_filter_to_rfc4515_string(f_obj),
                             msg="Standard test filter failed with unified parser!")

    def test_simple_with_unified(self):
        """Ensure all the simple test filters produce equivalent results with unified parser"""
        for standard, simple in self.good_standard_and_simple_filters:
            f_obj = filter.parse(simple)
            self.assertEqual(standard, filter.rfc4511_filter_to_rfc4515_string(f_obj),
                             msg="Simple test filter failed with unified parser!")

    def test_parse_unified_filter(self):
        """Ensure parse() produces equivalent rfc4511.Filter to parse_standard_filter()"""
        tests = [
            ('(&(&(foo=abc)(bar=def))(foo=ghi)(bar=jkl))', '(&(foo=abc)(bar=def)) AND (foo=ghi) AND (bar=jkl)'),
            ('(|(&(foo=abc)(|(bar=def)(foo=ghi))(bar=jkl))(foo=mno))',
             '((foo=abc) AND ((bar=def) OR (foo=ghi)) AND (bar=jkl)) OR (foo=mno)'),
            ('(!(foo=abc NOT def))', 'NOT (foo=abc NOT def)'),
        ]
        for standard, unified in tests:
            f_obj = filter.parse(unified)
            self.assertEqual(standard, filter.rfc4511_filter_to_rfc4515_string(f_obj),
                             msg="Orig unified filter: {0}".format(unified))

        for standard in self.bad_filters:
            with self.assertRaises(LDAPError):
                filter.parse(standard)

    def test_parse_simple_filter(self):
        for standard, simple in self.good_standard_and_simple_filters:
            f_obj = filter.parse_simple_filter(simple)
            self.assertEqual(standard, filter.rfc4511_filter_to_rfc4515_string(f_obj),
                             msg="Simple test filter did not produce consistent results!")

        for simple in self.bad_simple_filters:
            with self.assertRaises(LDAPError):
                filter.parse_simple_filter(simple)

    def test_parse_simple_filter_simple_only(self):
        """Ensure parse_simple_filter() only supports simple filters"""
        unified = '(&(foo=abc)(bar=def)) OR (&(foo=def)(bar=abc))'
        standard = '(&(foo=abc)(bar=def))'
        simple = '(foo=abc) AND (bar=def)'
        with self.assertRaises(LDAPError):
            filter.parse_simple_filter(unified)
        with self.assertRaises(LDAPError):
            filter.parse_simple_filter(standard)
        filter.parse_simple_filter(simple)
