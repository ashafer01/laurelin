import six
import unittest
from importlib import import_module

from laurelin.ldap import objectclass, attributetype, rules, LDAPObject
from laurelin.ldap.objectclass import get_object_class, ObjectClass, DefaultObjectClass
from laurelin.ldap.attributetype import get_attribute_type, DefaultAttributeType
from laurelin.ldap.rules import get_matching_rule, get_syntax_rule
from laurelin.ldap.exceptions import LDAPValidationError
from .utils import load_schema, get_reload

reload = get_reload()


class TestSchema(unittest.TestCase):
    def setUp(self):
        load_schema()

        # reload built-in extensions defining new schema elements
        reload(import_module('laurelin.extensions.netgroups'))

    def test_object_classes(self):
        """Ensure all defined object classes have defined attributes and superclasses"""

        for oc_name in objectclass._name_object_classes:
            oc = objectclass._name_object_classes[oc_name]
            for attr in oc.must + oc.may:
                self.assertNotIsInstance(get_attribute_type(attr), DefaultAttributeType,
                                         'attribute {0} is not defined for objectClass {1}'.format(attr, oc_name))
            for sc_name in oc.superclasses:
                self.assertNotIsInstance(get_object_class(sc_name), DefaultObjectClass,
                                         'superclass {0} is not defined for objectClass {1}'.format(sc_name, oc_name))

    def test_attribute_types(self):
        """Ensure all attribute syntax rules, equality rules, and supertypes are defined"""

        for attr_name in attributetype._name_attribute_types:
            at = attributetype._name_attribute_types[attr_name]
            if at.supertype:
                self.assertNotIsInstance(get_attribute_type(at.supertype), DefaultAttributeType,
                                         'supertype {0} not defined for attr {1}'.format(at.supertype, attr_name))
            try:
                if at.equality_oid:
                    get_matching_rule(at.equality_oid)
            except KeyError:
                self.fail('equality matching rule {0} is not defined for attr {1}'.format(at.equality_oid, attr_name))

            try:
                if at.syntax_oid:
                    get_syntax_rule(at.syntax_oid)
            except KeyError:
                self.fail('syntax rule {0} is not defined for attr {1}'.format(at.syntax_oid, attr_name))

    def test_matching_rules(self):
        """Ensure all matching rule syntaxes are defined"""

        for rule_name in rules._name_matching_rules:
            mr = rules.get_matching_rule(rule_name)
            try:
                get_syntax_rule(mr.SYNTAX)
            except KeyError:
                self.fail('syntax rule {0} is not defined for matching rule {1}'.format(mr.SYNTAX, rule_name))


class TestSchemaValidator(unittest.TestCase):
    def setUp(self):
        self.schema = load_schema()

    def test_validate_object(self):
        """Exercise validate_object()"""
        sv = self.schema.SchemaValidator()

        # missing objectClass
        empty_object = LDAPObject('o=foo', {})
        with six.assertRaisesRegex(self, LDAPValidationError, 'missing objectClass'):
            sv.validate_object(empty_object)

        # missing required attribute cn, exercise optional attrs
        op = LDAPObject('o=foo', {
            'objectClass': ['top', 'organizationalPerson'],
            'sn': ['Test'],
        })
        with six.assertRaisesRegex(self, LDAPValidationError, 'missing attr'):
            sv.validate_object(op)

        # valid and invalid optional attrs
        op = LDAPObject('o=foo', {
            'objectClass': ['top', 'organizationalPerson'],
            'sn': ['Test'],
            'cn': ['The Test'],
            'title': ['Tester'],
            'badAttr': ['foo'],
        })
        with six.assertRaisesRegex(self, LDAPValidationError, 'not permitted'):
            sv.validate_object(op)

        # test attribute validation
        iop = LDAPObject('o=foo', {
            'objectClass': ['top', 'inetOrgPerson'],
            'sn': ['Test'],
            'cn': ['The Test'],
            'employeeNumber': ['abc', 'def']  # single-value violation
        })
        with six.assertRaisesRegex(self, LDAPValidationError, 'single-value'):
            sv.validate_object(iop)

        ObjectClass("""
            ( 99.99.99 NAME 'mockTestingClass'
                SUP top
                STRUCTURAL
                MAY creatorsName
            )
        """)
        obj_with_oper = LDAPObject('o=foo', {
            'objectClass': ['top', 'mockTestingClass'],
            'creatorsName': ['cn=foo'],  # operational attribute, not user modifiable
        })
        with six.assertRaisesRegex(self, LDAPValidationError, 'not user mod'):
            sv.validate_object(obj_with_oper)



if __name__ == '__main__':
    unittest.main()
