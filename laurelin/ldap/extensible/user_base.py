from ..controls import register_module_controls
from ..rules import register_module_syntax_rules, register_module_matching_rules
from ..utils import get_obj_module


class BaseLaurelinExtension(object):
    """Base class for extensions that define schema and controls, required for any class not in AVAILABLE_EXTENSIONS"""
    NAME = '__undefined__'
    INSTANCE = None

    def __init__(self):
        self._schema_defined = False

    def _define_schema(self):
        raise NotImplemented()

    def require_schema(self):
        modname = get_obj_module(self.__class__)
        register_module_syntax_rules(modname)
        register_module_matching_rules(modname)
        try:
            if not self._schema_defined:
                self._define_schema()
                self._schema_defined = True
        except NotImplemented:
            pass

    def require_controls(self):
        modname = get_obj_module(self.__class__)
        register_module_controls(modname)

    def require(self):
        self.require_schema()
        self.require_controls()


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
