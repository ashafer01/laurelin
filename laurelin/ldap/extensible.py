from __future__ import absolute_import
from .base import LDAP
from .exceptions import LDAPExtensionError
from .ldapobject import LDAPObject
from .schema import load_base_schema
from importlib import import_module
import logging

logger = logging.getLogger(__name__)

# extensions must define a class with this name
EXTENSION_CLSNAME = 'LaurelinExtension'

# extensions may define classes following this pattern, where {0} is one of "LDAP" or "LDAPObject"
CLASS_EXTENSION_FMT = 'Laurelin{0}Extension'


def add_extension(modname):
    """Import an extension and prepare it for binding under its internally-defined name to LDAP and/or LDAPObject
    depending which extension classes are defined.

    :param str modname: The string module name containing an extension, can be any importable module, e.g.
                        "laurelin.extensions.netgroups"
    :rtype: None
    """

    # import the extension and get the extension class
    mod = _import_extension(modname)
    try:
        ext_cls = getattr(mod, EXTENSION_CLSNAME)
        # note: _import_extension has already checked that the class is the correct type if it exists
    except AttributeError:
        raise LDAPExtensionError('Extension {0} must define a class {1}'.format(modname, EXTENSION_CLSNAME))

    ext_attr_name = ext_cls.NAME

    # check if the class defined a NAME
    if ext_attr_name == BaseLaurelinExtension.NAME:
        raise LDAPExtensionError('Extension {0}.{1} does not define a NAME'.format(modname, EXTENSION_CLSNAME))

    # check if the extension has already been added, return if this exact module is already loaded, exception if its
    # a different module
    try:
        existing_ext_mod = Extensible.ADDITIONAL_EXTENSIONS[ext_attr_name]
        if existing_ext_mod is not mod:
            raise LDAPExtensionError('NAME {0} is already loaded as an additional extension {1}'.format(
                ext_attr_name, existing_ext_mod.__name__
            ))
        else:
            logger.debug('Extension module {0} with NAME {1} has already been added'.format(modname, ext_attr_name))
            return
    except KeyError:
        # no existing additional extension with the same NAME
        pass

    # check if the extension is predefined, return if the predefined extension uses the same modname, exception
    # otherwise
    try:
        ext_info = Extensible.AVAILABLE_EXTENSIONS[ext_attr_name]
        if ext_info['module'] != modname:
            raise LDAPExtensionError('{0} is already defined as an extension name'.format(ext_cls.NAME))
        else:
            logger.debug('Extension module {0} does not need to be added'.format(modname))
            return
    except KeyError:
        # no predefined extension by this NAME
        pass

    # if the extension defines class extensions, ensure the name does not collide with an actual attribute
    for cls in (LDAP, LDAPObject):
        ext_clsname = CLASS_EXTENSION_FMT.format(cls.__name__)
        if hasattr(mod, ext_clsname) and hasattr(cls, ext_attr_name):
            raise LDAPExtensionError('{0} already has an attribute named {1}, cannot add extension {2}'.format(
                cls.__name__, ext_attr_name, modname
            ))

    # store the imported module for later use
    Extensible.ADDITIONAL_EXTENSIONS[ext_attr_name] = mod


def _import_extension(modname):
    """Import an extension module and run setup functions if necessary"""
    mod = import_module(modname)
    flag_attr = 'LAURELIN_EXTENSION_SETUP_COMPLETE'
    if not getattr(mod, flag_attr, False):
        # need to setup extension
        logger.info('Setting up extension {0}'.format(modname))
        try:
            ext_cls = getattr(mod, EXTENSION_CLSNAME)
            if not issubclass(ext_cls, BaseLaurelinExtension):
                raise LDAPExtensionError('{0}.{1} does not subclass {2}.BaseLaurelinExtension'.format(
                    modname, EXTENSION_CLSNAME, __name__
                ))
            if ext_cls.REQUIRES_BASE_SCHEMA:
                load_base_schema()

            # call one-time setup functions
            ext_obj = ext_cls()
            for method in ('define_schema', 'define_controls'):
                try:
                    getattr(ext_obj, method)()
                except (NotImplemented, AttributeError):
                    pass

            # store the instance on a class attribute
            ext_cls.INSTANCE = ext_obj
        except AttributeError:
            pass
        setattr(mod, flag_attr, True)
    return mod


class Extensible(object):
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

    _EXTENSIBLE_CLASSES = ('LDAP', 'LDAPObject')

    def __init__(self):
        self._extension_instances = {}
        self._extended_classname = None

    def _get_extended_classname(self):
        """Find the name of the class we are extending. Allows users to subclass LDAP or LDAPObject"""
        if self._extended_classname:
            return self._extended_classname
        else:
            for cls in self.__class__.__mro__:
                if cls.__name__ in Extensible._EXTENSIBLE_CLASSES:
                    self._extended_classname = cls.__name__
                    return cls.__name__
            else:
                raise TypeError('This class does not inherit a known extensible class')

    def _get_extension_instance(self, name):
        """This gets called and returned by auto-generated @property methods as their only line"""
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
        obj = self._create_class_extension_instance(name, mod)
        return obj

    def _create_class_extension_instance(self, name, mod):
        """Creates a new instance of the class extension for this class defined in mod"""
        my_classname = self._get_extended_classname()
        ext_classname = CLASS_EXTENSION_FMT.format(my_classname)
        base_classname = 'Base' + ext_classname
        try:
            cls = getattr(mod, ext_classname)
        except AttributeError:
            raise LDAPExtensionError('Extension {0} does not define an extension class for {1}'.format(mod.__name__,
                                                                                                       my_classname))
        if not issubclass(cls, globals()[base_classname]):
            raise LDAPExtensionError('Extension class {0}.{1} does not subclass {2}.{3}'.format(
                mod.__name__, ext_classname, __name__, base_classname
            ))
        obj = cls(parent=self)
        self._extension_instances[name] = obj
        return obj

    def __getattr__(self, item):
        # this acts like the auto-generated @property methods but fully dynamic, using modules that have been added
        # using add_extension()
        try:
            return self._extension_instances[item]
        except KeyError:
            pass
        try:
            ext_mod = self.ADDITIONAL_EXTENSIONS[item]
        except KeyError:
            raise AttributeError(item)
        obj = self._create_class_extension_instance(item, ext_mod)
        return obj


class BaseLaurelinExtension(object):
    """Base class for extensions that define schema and controls, required for any class not in AVAILABLE_EXTENSIONS"""
    NAME = '__undefined__'
    INSTANCE = None
    REQUIRES_BASE_SCHEMA = False

    def define_schema(self):
        raise NotImplemented()

    def define_controls(self):
        raise NotImplemented()


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
