from laurelin.ldap import rfc4517
from laurelin.ldap.exceptions import InvalidSyntaxError

def test_bit_string():
    testobj = rfc4517.BitString()

    tests_good = (
        "'01010101'B",
        "'11110000'B",
        "'10101000010101'B",
        "''B",
        "'1'B",
    )

    for test in tests_good:
        testobj.validate(test)

    tests_bad = (
        '"01"B',
        "'01'b",
        "01B",
        "'02'B",
    )

    for test in tests_bad:
        try:
            testobj.validate(test)
            assert False
        except InvalidSyntaxError:
            pass


def test_enhanced_guide():
    testobj = rfc4517.EnhancedGuide()

    tests_good = (
        'person#(sn$EQ)#oneLevel',
        '1.234.5678 # ab$EQ|cd$LE&efgh$APPROX # baseobject',
        'test#abcd$EQ|(ab$EQ&cd$SUBSTR)#wholeSubtree',
        '1.23.45.678 # (ab$EQ|(cd$EQ&ef$GE&(gh$LE))&(ijk$SUBSTR)|(lmn$APPROX)) # oneLevel',
        '1.23.45.678 # (ab$EQ|(cd$EQ&ef$GE&(gh$LE))&(ijk$SUBSTR)|(lmn$APPROX|op$EQ|(q$EQ&r$EQ&(s$EQ|t$EQ)))) # oneLevel',
        'test # (!(abc$EQ))|(def$EQ) # baseobject',
    )

    for test in tests_good:
        testobj.validate(test)


def test_distinguished_name():
    import laurelin.ldap.schema
    testobj = rfc4517.DistinguishedName()

    tests_good = (
        r'UID=jsmith,DC=example,DC=net',
        r'OU=Sales+CN=J.  Smith,DC=example,DC=net',
        r'CN=James \"Jim\" Smith\, III,DC=example,DC=net',
        r'CN=Before\0dAfter,DC=example,DC=net',
        r'1.3.6.1.4.1.1466.0=#04024869',
        r'CN=Lu\C4\8Di\C4\87',
    )

    for test in tests_good:
        testobj.validate(test)
