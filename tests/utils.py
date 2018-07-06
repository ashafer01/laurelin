from laurelin.ldap import attributetype, objectclass, rules, extensions, BaseLaurelinExtension
from laurelin.ldap.extensible import schema


def get_reload():
    try:
        return reload
    except NameError:
        pass
    try:
        from importlib import reload
        return reload
    except ImportError:
        pass
    from imp import reload
    return reload


reload = get_reload()


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
    schema._syntax_registered_mods.clear()
    schema._matching_registered_mods.clear()


def clear_schema_registrations():
    clear_attribute_types()
    clear_object_classes()
    clear_rules()
    schema._object_class_registered_mods.clear()
    schema._attribute_type_registered_mods.clear()


def load_schema():
    extensions.base_schema.require()


def import_install_mock():
    try:
        import unittest.mock as mock
        return mock
    except ImportError:
        import mock
        return mock
