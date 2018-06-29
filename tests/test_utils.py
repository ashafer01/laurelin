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


def test_run_once():
    class Foo(object):
        def __init__(self):
            self.foo_counter = 0
            self.bar_counter = 0

        @utils.run_once
        def foo(self):
            self.foo_counter += 1

        @utils.run_once
        def bar(self):
            self.bar_counter += 1

    class Bar(object):
        def __init__(self):
            self.foo_counter = 0

        @utils.run_once
        def foo(self):
            self.foo_counter += 1

    testobj = Foo()
    assert testobj.foo_counter == 0
    assert testobj.bar_counter == 0

    testobj.foo()
    assert testobj.foo_counter == 1

    testobj.bar()
    assert testobj.bar_counter == 1

    testobj.foo()
    assert testobj.foo_counter == 1

    testobj.bar()
    assert testobj.bar_counter == 1

    testobj2 = Bar()
    assert testobj2.foo_counter == 0

    testobj2.foo()
    assert testobj2.foo_counter == 1

    testobj2.foo()
    assert testobj2.foo_counter == 1
