from laurelin.ldap.attributetype import AttributeType, _oidAttributeTypes, _nameAttributeTypes
from laurelin.ldap.exceptions import LDAPSchemaError

def reset_registrations():
    _oidAttributeTypes.clear()
    _nameAttributeTypes.clear()


def setup():
    reset_registrations()


def teardown():
    reset_registrations()


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
            AttributeType(test)
            assert False
        except LDAPSchemaError:
            pass


def test_duplicate_oid():
    spec = '''
      ( 2.5.4.0 NAME 'objectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
    '''

    AttributeType(spec)
    try:
        AttributeType(spec)
        assert False
    except LDAPSchemaError:
        pass
    finally:
        reset_registrations()


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

    AttributeType(spec1)
    try:
        AttributeType(spec2)
        assert False
    except LDAPSchemaError:
        pass
    finally:
        reset_registrations()


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

    try:
        assert t1.oid != t2.oid
        assert t1.names != t2.names

        assert t1.equalityOID == t2.equalityOID
        assert t1.syntaxOID == t2.syntaxOID
        assert t1.singleValue == t2.singleValue
    finally:
        reset_registrations()


def test_index():
    spec = '''
      ( 1.2.3.4 NAME 'testing'
        EQUALITY caseIgnoreMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
    '''

    t = AttributeType(spec)

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
        reset_registrations()
