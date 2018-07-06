from .schema import register_module_schema
from .controls import register_module_controls
from ..utils import get_obj_module


class BaseLaurelinExtension(object):
    """Base class for extensions that define schema and controls, required for any class not in AVAILABLE_EXTENSIONS"""
    NAME = '__undefined__'
    INSTANCE = None

    def require_schema(self):
        modname = get_obj_module(self.__class__)
        register_module_schema(modname)

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
