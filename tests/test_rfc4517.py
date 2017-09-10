from laurelin.ldap import rfc4517
from laurelin.ldap.exceptions import InvalidSyntaxError

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
        testobj = rfc4517.BitString(),
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
        testobj = rfc4517.Boolean(),
        tests_good = ('TRUE', 'FALSE'),
        tests_bad = ('true', 'false', 'foo'),
    )


def test_country_string():
    run_syntax(
        testobj = rfc4517.CountryString(),
        tests_good = ('us', 'ca', 'a-'),
        tests_bad = ('abc', 'x\0'),
    )


def test_delivery_method():
    run_syntax(
        testobj = rfc4517.DeliveryMethod(),
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
        testobj = rfc4517.DirectoryString(),
        tests_good = ('abc',),
        tests_bad = (
            ['abc'],
            '',
        ),
    )


def test_dit_content_rule_description():
    run_syntax(
        testobj = rfc4517.DITContentRuleDescription(),
        tests_good = ("( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )",),
        tests_bad = (),
    )


def test_dit_structure_rule_description():
    run_syntax(
        testobj = rfc4517.DITStructureRuleDescription(),
        tests_good = ("( 2 DESC 'organization structure rule' FORM 2.5.15.3 )",),
        tests_bad = (),
    )


def test_enhanced_guide():
    run_syntax(
        testobj = rfc4517.EnhancedGuide(),
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
    import laurelin.ldap.schema
    run_syntax(
        testobj = rfc4517.DistinguishedName(),
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
