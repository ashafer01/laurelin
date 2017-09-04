from laurelin.ldap import rfc4517

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
