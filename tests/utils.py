from laurelin.ldap import attributetype, objectclass, rules, protoutils
from importlib import import_module
import six
from six.moves import range


def get_reload():
    try:
        return reload
    except NameError:
        try:
            from imp import reload
            return reload
        except ImportError:
            from importlib import reload
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


def clear_schema_registrations():
    clear_attribute_types()
    clear_object_classes()
    clear_rules()


def load_schema():
    schema_mod = 'laurelin.ldap.schema'
    clear_schema_registrations()
    schema = import_module(schema_mod)
    clear_schema_registrations()
    reload(schema)
    return import_module(schema_mod)


def import_install_mock():
    try:
        import unittest.mock as mock
        return mock
    except ImportError:
        try:
            import mock
            return mock
        except ImportError:
            import pip
            pip.main(['install', 'mock'])
            import mock
            return mock


def get_modify_value_set(lm, attr):
    mid, mod_req, ctrls = protoutils.unpack('modifyRequest', lm)

    changes = mod_req.getComponentByName('changes')
    for i in range(len(changes)):
        change = changes.getComponentByPosition(i)
        pa = change.getComponentByName('modification')
        have_attr = six.text_type(pa.getComponentByName('type'))
        if attr.lower() == have_attr.lower():
            vals = pa.getComponentByName('vals')
            return set(protoutils.seq_to_list(vals))
    raise Exception('attribute {0} was not present in the modifyRequest'.format(attr))
