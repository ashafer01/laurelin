from laurelin.ldap.attributetype import (
    AttributeType,
    DefaultAttributeType,
    get_attribute_type,
)
from laurelin.ldap.exceptions import LDAPSchemaError
from .utils import clear_attribute_types, load_schema


def setup():
    clear_attribute_types()


def teardown():
    clear_attribute_types()


def test_invalid_specs():
    bad = (
        # parameters out of order
        '''
          ( 2.5.4.1 NAME 'aliasedObjectName'
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
            EQUALITY distinguishedNameMatch
            SINGLE-VALUE )
        ''',
        # content before paren
        '''
          attributetype ( 2.5.4.1 NAME 'aliasedObjectName'
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
            EQUALITY distinguishedNameMatch
            SINGLE-VALUE )
        ''',
        # object class spec
        '''
          ( 2.5.6.2 NAME 'country'
             SUP top
             STRUCTURAL
             MUST c
             MAY ( searchGuide $
                   description ) )
        ''',
        # missing closing paren
        '''
          ( 2.5.4.0 NAME 'objectClass'
            EQUALITY objectIdentifierMatch
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
        ''',
    )

    for test in bad:
        try:
            t = AttributeType(test)
            t.register()
            assert False
        except LDAPSchemaError:
            pass


def test_duplicate_oid():
    spec = '''
      ( 2.5.4.0 NAME 'objectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
    '''

    t1 = AttributeType(spec)
    t1.register()
    try:
        t2 = AttributeType(spec)
        t2.register()
        assert False
    except LDAPSchemaError:
        pass
    finally:
        clear_attribute_types()


def test_duplicate_name():
    spec1 = '''
      ( 2.5.4.0 NAME 'objectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
    '''
    spec2 = '''
      ( 2.5.4.99999 NAME 'objectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
    '''

    t1 = AttributeType(spec1)
    t1.register()
    try:
        t2 = AttributeType(spec2)
        t2.register()
        assert False
    except LDAPSchemaError:
        pass
    finally:
        clear_attribute_types()


def test_supertype_inhertiance():
    supertype = '''
      ( 1.2.3.4 NAME 'testing'
        EQUALITY caseExactMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.7
        SINGLE-VALUE )
    '''

    subtype = '''
      ( 1.2.3.5 NAME 'subtesting'
        SUP 1.2.3.4 )
    '''

    t1 = AttributeType(supertype)
    t2 = AttributeType(subtype)
    t1.register()
    t2.register()

    try:
        assert t1.oid != t2.oid
        assert t1.names != t2.names

        assert t1.equality_oid == t2.equality_oid
        assert t1.syntax_oid == t2.syntax_oid
        assert t1.single_value == t2.single_value
    finally:
        clear_attribute_types()


def test_index():
    load_schema()
    spec = '''
      ( 1.2.3.4 NAME 'testing'
        EQUALITY caseIgnoreMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
    '''

    t = AttributeType(spec)
    t.register()

    values = [
        'abc',
        'DEF',
        'gHi',
        'JkL',
    ]

    assert t.index(values, 'ABC') == 0
    assert t.index(values, 'GHI') == 2

    try:
        t.index(values, 'foo')
        assert False
    except ValueError:
        pass
    finally:
        clear_attribute_types()


def test_getAttributeType():
    load_schema()
    spec = '''
      ( 1.2.3.4 NAME 'testing'
        EQUALITY caseIgnoreMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
    '''
    t1 = AttributeType(spec)
    t1.register()

    t2 = get_attribute_type('testing')
    t3 = get_attribute_type('1.2.3.4')

    try:
        assert t1 is t2
        assert t1 is t3
    finally:
        clear_attribute_types()


def test_default():
    test = get_attribute_type('foo')
    try:
        assert isinstance(test, DefaultAttributeType)
    finally:
        clear_attribute_types()
