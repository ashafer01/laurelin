from ..objectclass import ObjectClass
from ..attributetype import AttributeType
from ..rules import SyntaxRule, MatchingRule
from ..utils import get_obj_module
import six
import logging

logger = logging.getLogger(__name__)

_preregistered_syntax_rules = {}
_preregistered_matching_rules = {}
_preregistered_object_classes = {}
_preregistered_attribute_types = {}

_syntax_registered_mods = set()
_matching_registered_mods = set()
_object_class_registered_mods = set()
_attribute_type_registered_mods = set()


def _reg_mod_elements(prereg_dict, reg_set, modname):
    if modname in reg_set:
        return
    if modname not in prereg_dict:
        return
    for obj in prereg_dict[modname]:
        obj.register()
    reg_set.add(modname)


def register_module_syntax_rules(modname):
    _reg_mod_elements(_preregistered_syntax_rules, _syntax_registered_mods, modname)


def register_module_matching_rules(modname):
    _reg_mod_elements(_preregistered_matching_rules, _matching_registered_mods, modname)


def register_module_object_classes(modname):
    _reg_mod_elements(_preregistered_object_classes, _object_class_registered_mods, modname)


def register_module_attribute_types(modname):
    _reg_mod_elements(_preregistered_attribute_types, _attribute_type_registered_mods, modname)


def register_module_schema(modname):
    register_module_syntax_rules(modname)
    register_module_matching_rules(modname)
    register_module_attribute_types(modname)
    register_module_object_classes(modname)


class MetaLaurelinSchema(type):
    def __new__(mcs, name, bases, dct):
        cls = type.__new__(mcs, name, bases, dct)
        modname = get_obj_module(cls)
        for attr, value in dct.items():
            if attr.startswith('_'):
                continue
            if isinstance(value, six.class_types):
                if issubclass(value, SyntaxRule):
                    lst = _preregistered_syntax_rules.setdefault(modname, [])
                elif issubclass(value, MatchingRule):
                    lst = _preregistered_matching_rules.setdefault(modname, [])
                else:
                    logger.debug('Unhandled class type defined in class LaurelinSchema')
                    continue
            elif isinstance(value, ObjectClass):
                lst = _preregistered_object_classes.setdefault(modname, [])
            elif isinstance(value, AttributeType):
                lst = _preregistered_attribute_types.setdefault(modname, [])
            else:
                logger.debug('Unhandled object type defined in class LaurelinSchema')
                continue
            lst.append(value)
        return cls


@six.add_metaclass(MetaLaurelinSchema)
class BaseLaurelinSchema(object):
    """Base class for extensions defining schema elements"""
    pass
