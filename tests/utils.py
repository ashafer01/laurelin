from laurelin.ldap import attributetype, objectclass, rules
from importlib import import_module
try:
    reload
except NameError:
    try:
        from imp import reload
    except ImportError:
        from importlib import reload


def clear_attribute_types():
    attributetype._name_attribute_types.clear()
    attributetype._oid_attribute_types.clear()


def clear_object_classes():
    objectclass._name_object_classes.clear()
    objectclass._oid_object_classes.clear()


def clear_rules():
    rules._oid_syntax_rules.clear()
    rules._oid_syntax_rule_objects.clear()
    rules._oid_matching_rules.clear()
    rules._name_matching_rules.clear()
    rules._oid_matching_rule_objects.clear()
    rules._name_matching_rule_objects.clear()


def clear_schema_registrations():
    clear_attribute_types()
    clear_object_classes()
    clear_rules()


def load_schema():
    schema_mod = 'laurelin.ldap.schema'
    schema = import_module(schema_mod)
    clear_schema_registrations()
    reload(schema)
    return import_module(schema_mod)

