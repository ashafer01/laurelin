from __future__ import absolute_import
from .base import LDAP
from .exceptions import LDAPExtensionError
from .ldapobject import LDAPObject
from .schema import load_base_schema
from importlib import import_module
import logging

logger = logging.getLogger(__name__)


def add_extension(modname):
    """Import an extension and prepare it for binding under its internally-defined name to LDAP and/or LDAPObject
    depending which extension classes are defined.

    :param str modname: The string module name containing an extension, can be any importable module, e.g.
                        "laurelin.extensions.netgroups"
    :rtype: None
    """
    mod = _import_extension(modname)
    ext_clsname = 'LaurelinExtension'
    try:
        ext_cls = getattr(mod, ext_clsname)
        # note: _import_extension has already checked that the class is the correct type if it exists
    except AttributeError:
        raise LDAPExtensionError('Extension {0} must define a class {1}'.format(modname, ext_clsname))
    ext_attr_name = ext_cls.NAME
    if ext_attr_name == LaurelinExtension.NAME:
        raise LDAPExtensionError('Extension {0}.{1} does not define a NAME'.format(modname, ext_clsname))
    if ext_attr_name in ExtensionBase.AVAILABLE_EXTENSIONS:
        raise LDAPExtensionError('{0} is already defined as an extension name'.format(ext_cls.NAME))
    if ext_attr_name in ExtensionBase.ADDITIONAL_EXTENSIONS:
        raise LDAPExtensionError('{0} is already loaded as an additional extension'.format(ext_cls.NAME))
    for cls in (LDAP, LDAPObject):
        ext_clsname = 'Laurelin{0}Extension'.format(cls.__name__)
        if hasattr(mod, ext_clsname) and hasattr(cls, ext_attr_name):
            raise LDAPExtensionError('{0} already has an attribute named {1}, cannot add extension {2}'.format(
                cls.__name__, ext_attr_name, modname
            ))
    ExtensionBase.ADDITIONAL_EXTENSIONS[ext_attr_name] = mod


def _import_extension(modname):
    """Import an extension module and run setup function if necessary"""
    mod = import_module(modname)
    flag_attr = 'LAURELIN_EXTENSION_SETUP_COMPLETE'
    if not getattr(mod, flag_attr, False):
        # need to setup extension
        logger.info('Setting up extension {0}'.format(modname))
        try:
            clsname = 'LaurelinExtension'
            ext_cls = getattr(mod, clsname)
            if not issubclass(ext_cls, LaurelinExtension):
                raise LDAPExtensionError('{0}.{1} does not subclass {2}.{3}'.format(modname, clsname, __name__,
                                                                                    clsname))
            if ext_cls.REQUIRES_BASE_SCHEMA:
                load_base_schema()
            ext_obj = ext_cls()
            ext_cls.INSTANCE = ext_obj
        except AttributeError:
            pass
        setattr(mod, flag_attr, True)
    return mod


class ExtensionBase(object):
    """Base for automatically-generated extension property classes inherited by LDAP and LDAPObject"""

    AVAILABLE_EXTENSIONS = {
        'descattrs': {
            'module': 'laurelin.extensions.descattrs',
            'pip_package': None,  # built-in
            'docstring': 'The built-in description attributes extension',
        },
        'netgroups': {
            'module': 'laurelin.extensions.netgroups',
            'pip_package': None,  # built-in
            'docstring': 'The built-in NIS netgroups extension',
        }
    }

    ADDITIONAL_EXTENSIONS = {}

    def __init__(self):
        self._extension_instances = {}

    def _get_extension_instance(self, name):
        try:
            return self._extension_instances[name]
        except KeyError:
            pass
        extinfo = self.AVAILABLE_EXTENSIONS[name]
        modname = extinfo['module']
        try:
            mod = _import_extension(modname)
        except ImportError:
            pip_package = extinfo['pip_package']
            if pip_package is None:
                raise LDAPExtensionError('Error importing built-in extension {0}. This may be a bug.'.format(modname))
            else:
                raise LDAPExtensionError('Error importing {0}, the extension may not be installed. Try `pip '
                                         'install {1}`'.format(modname, pip_package))
        obj = self._create_class_extension_instance(mod)
        self._extension_instances[name] = obj
        return obj

    def _create_class_extension_instance(self, mod):
        my_classname = self.__class__.__name__
        ext_classname = 'Laurelin{0}Extension'.format(my_classname)
        try:
            cls = getattr(mod, ext_classname)
        except AttributeError:
            raise LDAPExtensionError('Extension {0} does not define an extension class for {1}'.format(mod.__name__,
                                                                                                       my_classname))
        if not issubclass(cls, globals()[ext_classname]):
            raise LDAPExtensionError('Extension class {0}.{1} does not subclass {2}.{3}'.format(
                mod.__name__, ext_classname, __name__, ext_classname
            ))
        obj = cls(parent=self)
        return obj

    def __getattr__(self, item):
        try:
            return self._extension_instances[item]
        except KeyError:
            pass
        try:
            ext_mod = self.ADDITIONAL_EXTENSIONS[item]
        except KeyError:
            raise AttributeError(item)
        obj = self._create_class_extension_instance(ext_mod)
        self._extension_instances[item] = obj
        return obj


class LaurelinExtension(object):
    """Base class for extensions that define schema and controls, required for any class not in AVAILABLE_EXTENSIONS"""
    NAME = '__undefined__'
    INSTANCE = None
    REQUIRES_BASE_SCHEMA = False

    def __init__(self):
        raise NotImplemented()


class LaurelinLDAPExtension(object):
    """Base class for extensions to the LDAP class"""
    def __init__(self, parent):
        """
        :param laurelin.ldap.LDAP parent: The parent LDAP instance
        """
        self.parent = parent


class LaurelinLDAPObjectExtension(object):
    """Base class for extensions to the LDAPObject class"""
    def __init__(self, parent):
        """
        :param laurelin.ldap.LDAPObject parent: The parent LDAPObject instance
        """
        self.parent = parent
