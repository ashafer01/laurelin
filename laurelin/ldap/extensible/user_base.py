from ..controls import register_module_controls
from ..rules import register_module_syntax_rules, register_module_matching_rules
from ..utils import get_obj_module
from .. import ObjectClass, AttributeType, SyntaxRule, MatchingRule
import six
import logging

logger = logging.getLogger(__name__)


class BaseLaurelinExtension(object):
    """Base class for extensions that define schema and controls, required for any class not in AVAILABLE_EXTENSIONS"""
    NAME = '__undefined__'
    INSTANCE = None

    _schema_defined = set()

    def _define_schema(self):
        return

    def require_schema(self):
        modname = get_obj_module(self.__class__)
        register_module_syntax_rules(modname)
        register_module_matching_rules(modname)

        # use a class-level set rather than an instance level flag to allow easy resets during testing
        if modname not in BaseLaurelinExtension._schema_defined:
            self._define_schema()
            BaseLaurelinExtension._schema_defined.add(modname)

    def require_controls(self):
        modname = get_obj_module(self.__class__)
        register_module_controls(modname)

    def require(self):
        self.require_schema()
        self.require_controls()


_preregistered_syntax_rules = {}
_preregistered_matching_rules = {}
_preregistered_object_classes = {}
_preregistered_attribute_types = {}


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
            elif isinstance(value, ObjectClass):
                lst = _preregistered_object_classes.setdefault(modname, [])
            elif isinstance(value, AttributeType):
                lst = _preregistered_attribute_types.setdefault(modname, [])
            else:
                logger.debug('Unhandled object typed defined in class LaurelinSchema')
                continue
            lst.append(value)
        return cls



@six.add_metaclass(MetaLaurelinSchema)
class BaseLaurelinSchema(object):
    """Base class for extensions defining schema elements"""
    pass


class BaseLaurelinLDAPExtension(object):
    """Base class for extensions to the LDAP class"""
    def __init__(self, parent):
        """
        :param laurelin.ldap.LDAP parent: The parent LDAP instance
        """
        self.parent = parent


class BaseLaurelinLDAPObjectExtension(object):
    """Base class for extensions to the LDAPObject class"""
    def __init__(self, parent):
        """
        :param laurelin.ldap.LDAPObject parent: The parent LDAPObject instance
        """
        self.parent = parent
