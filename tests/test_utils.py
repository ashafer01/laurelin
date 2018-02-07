from laurelin.ldap import utils

def test_findClosingParen():
    test_good = (
        ('(abc)def', 4),
        ('(abcd)', 5),
        ('()', 1),
        ('(())..', 3),
        ('(a(bc)(d(efg))hi)jk', 16),
    )

    for test, expected in test_good:
        actual = utils.find_closing_paren(test)
        assert actual == expected

    test_bad = (
        'a(bc)d',
        '(abcd',
    )

    for test in test_bad:
        try:
            utils.find_closing_paren(test)
            assert False
        except ValueError:
            pass


def test_validatePhoneNumber():
    test_good = (
        '+12345678901',
        '+1.234.567.8901',
        '(234) 567-8901',
        '234-5678',
        '123456789012345',
        '+41 22 749 08 88',
    )

    for test in test_good:
        assert utils.validate_phone_number(test)

    test_bad = (
        '123456',
        '+1 234+567-8901',
    )

    for test in test_bad:
        assert utils.validate_phone_number(test) is False
