from laurelin.ldap.exceptions import InvalidSyntaxError
from .utils import clear_rules, load_schema

schema = load_schema()


def setup():
    clear_rules()


def teardown():
    clear_rules()


def run_syntax(testobj, tests_good, tests_bad):
    for test in tests_good:
        testobj.validate(test)

    for test in tests_bad:
        try:
            testobj.validate(test)
            assert False
        except InvalidSyntaxError:
            pass


def test_bit_string():
    run_syntax(
        testobj = schema.BitString(),
        tests_good = (
            "'01010101'B",
            "'11110000'B",
            "'10101000010101'B",
            "''B",
            "'1'B",
        ),
        tests_bad = (
            '"01"B',
            "'01'b",
            "01B",
            "'02'B",
        ),
    )


def test_boolean():
    run_syntax(
        testobj = schema.Boolean(),
        tests_good = ('TRUE', 'FALSE'),
        tests_bad = ('true', 'false', 'foo'),
    )


def test_country_string():
    run_syntax(
        testobj = schema.CountryString(),
        tests_good = ('us', 'ca', 'a-'),
        tests_bad = ('abc', 'x\0'),
    )


def test_delivery_method():
    run_syntax(
        testobj = schema.DeliveryMethod(),
        tests_good = (
            'any',
            'mhs $ physical',
            'telex$ teletext',
            'g3fax $g4fax',
            'ia5   $    videotext',
            'any $ telephone $ physical $ g4fax',
        ),
        tests_bad = (
            'foo',
            'mhs # physical',
        ),
    )


def test_directory_string():
    run_syntax(
        testobj = schema.DirectoryString(),
        tests_good = ('abc',),
        tests_bad = (
            ['abc'],
            '',
        ),
    )


def test_dit_content_rule_description():
    run_syntax(
        testobj = schema.DITContentRuleDescription(),
        tests_good = ("( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )",),
        tests_bad = (),
    )


def test_dit_structure_rule_description():
    run_syntax(
        testobj = schema.DITStructureRuleDescription(),
        tests_good = ("( 2 DESC 'organization structure rule' FORM 2.5.15.3 )",),
        tests_bad = (),
    )


def test_enhanced_guide():
    run_syntax(
        testobj = schema.EnhancedGuide(),
        tests_good = (
            'person#(sn$EQ)#oneLevel',
            '1.234.5678 # ab$EQ|cd$LE&efgh$APPROX # baseobject',
            'test#abcd$EQ|(ab$EQ&cd$SUBSTR)#wholeSubtree',
            '1.23.45.678 # (ab$EQ|(cd$EQ&ef$GE&(gh$LE))&(ijk$SUBSTR)|(lmn$APPROX)) # oneLevel',
            '1.23.45.678 # (ab$EQ|(cd$EQ&ef$GE&(gh$LE))&(ijk$SUBSTR)|(lmn$APPROX|op$EQ|(q$EQ&r$EQ&(s$EQ|t$EQ)))) # oneLevel',
            'test # (!(abc$EQ))|(def$EQ) # baseobject',
        ),
        tests_bad = (),
    )


def test_distinguished_name():
    run_syntax(
        testobj = schema.DistinguishedName(),
        tests_good = (
            r'UID=jsmith,DC=example,DC=net',
            r'OU=Sales+CN=J.  Smith,DC=example,DC=net',
            r'CN=James \"Jim\" Smith\, III,DC=example,DC=net',
            r'CN=Before\0dAfter,DC=example,DC=net',
            r'1.3.6.1.4.1.1466.0=#04024869',
            r'CN=Lu\C4\8Di\C4\87',
        ),
        tests_bad = (),
    )


def test_generalized_time():
    run_syntax(
        testobj = schema.GeneralizedTime(),
        tests_good = (
            '199412161032Z', # spec example
            '199412160532-0500', # spec example
            '2017091209Z', # minutes optional
            '201709120935-08', # tz minutes optional
            '201709120936-0817', # including tz minutes
            '20170912093820Z', # including seconds
            '20170912094450.12345678Z', # including fraction
        ),
        tests_bad = (
            '20170912Z', # missing hour
            '2017001209Z', # month < 1
            '2017131209Z', # month > 12
            '2017090009Z', # day < 1
            '2017093209Z', # day > 31
            '201709121Z', # insufficient hours digits
            '2017091224Z', # hour > 23
            '20170912091Z', # insufficient minutes digits
            '201709120961Z', # minutes > 60
            '20170912091Z', # insufficient seconds digits
            '2017091209', # missing time zone
            '2017091209+24', # tz hour > 23
            '2017091209+0860', # tz minutes > 59
            '2017091209+080', # insufficient tz digits
            '2017091209+8', # insufficient tz digits
        ),
    )


def test_integer():
    run_syntax(
        testobj = schema.Integer(),
        tests_good = (
            '12345',
            '-12345',
        ),
        tests_bad = (
            '0123',
            'ab',
            '+123',
        ),
    )


def test_ldap_syntax_description():
    run_syntax(
        testobj = schema.LDAPSyntaxDescription(),
        tests_good = (
            "( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )",
        ),
        tests_bad = (),
    )


def test_matching_rule_description():
    run_syntax(
        testobj = schema.MatchingRuleDescription(),
        tests_good = (
            "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        ),
        tests_bad = (),
    )


def test_matching_rule_use_description():
    run_syntax(
        testobj = schema.MatchingRuleUseDescription(),
        tests_good = (
            "( 2.5.13.16 APPLIES ( givenName $ surname ) )",
        ),
        tests_bad = (),
    )


def test_name_and_optional_uid():
    run_syntax(
        testobj = schema.NameAndOptionalUID(),
        tests_good = (
            "1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB#'0101'B",
        ),
        tests_bad = (),
    )


def test_name_form_description():
    run_syntax(
        testobj = schema.NameFormDescription(),
        tests_good = (
            "( 2.5.15.3 NAME 'orgNameForm' OC organization MUST o )",
        ),
        tests_bad = (),
    )


def test_numeric_string():
    run_syntax(
        testobj = schema.NumericString(),
        tests_good = (
            '15 079 672 281',
            '123456',
        ),
        tests_bad = (
            '123a',
        ),
    )


def test_object_class_description():
    run_syntax(
        testobj = schema.ObjectClassDescription(),
        tests_good = (
            "( 2.5.6.2 NAME 'country' SUP top STRUCTURAL MUST c MAY ( searchGuide $ description ) )",
        ),
        tests_bad = (),
    )


def test_oid():
    run_syntax(
        testobj = schema.OID(),
        tests_good = (
            '1.2.3.4',
            'cn',
        ),
        tests_bad = (),
    )


def test_postal_address():
    run_syntax(
        testobj = schema.PostalAddress(),
        tests_good = (
            '1234 Main St.$Anytown, CA 12345$USA',
            r'\241,000,000 Sweepstakes$PO Box 1000000$Anytown, CA 12345$USA',
        ),
        tests_bad = (),
    )


def test_telephone_number():
    run_syntax(
        testobj = schema.TelephoneNumber(),
        tests_good = (
            '+1 512 315 0280',
            '+1-512-315-0280',
            '+61 3 9896 7830',
        ),
        tests_bad = (),
    )
