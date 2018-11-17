from __future__ import absolute_import
from . import user_base
from .user_base import BaseLaurelinExtension
from ..exceptions import LDAPExtensionError
from importlib import import_module
import logging

logger = logging.getLogger('laurelin.ldap.extensible')

# extensions must define a class with this name
EXTENSION_CLSNAME = 'LaurelinExtension'

# extensions may define classes following this pattern, where {0} is one of "LDAP" or "LDAPObject"
CLASS_EXTENSION_FMT = 'Laurelin{0}Extension'


def add_extension(modname):
    """Import an extension and prepare it for binding under its internally-defined name to LDAP and/or LDAPObject
    depending which extension classes are defined. This is only needed for extensions not yet patched into
    AVAILABLE_EXTENSIONS.

    :param str modname: The string module name containing an extension, can be any importable module, e.g.
                        "laurelin.extensions.netgroups"
    :rtype: None
    """

    # import the extension and get the extension class
    mod = _import_extension(modname)
    try:
        ext_cls = getattr(mod, EXTENSION_CLSNAME)
    except AttributeError:
        raise LDAPExtensionError('Extension {0} must define a class {1}'.format(modname, EXTENSION_CLSNAME))

    # note: _import_extension has already checked that the class is the correct type if it exists

    ext_attr_name = ext_cls.NAME

    # check if the class defined a NAME
    if ext_attr_name == BaseLaurelinExtension.NAME:
        raise LDAPExtensionError('Extension {0}.{1} does not define a NAME'.format(modname, EXTENSION_CLSNAME))

    # check if the extension has already been added, return if this exact module is already loaded, exception if its
    # a different module
    try:
        existing_ext_mod = Extensible.ADDITIONAL_EXTENSIONS[ext_attr_name]
        if existing_ext_mod is not mod:
            # the 2 extension modules are not identical; report that a different extension by this NAME is already
            # added
            raise LDAPExtensionError('NAME {0} is already loaded as an additional extension {1}'.format(
                ext_attr_name, existing_ext_mod.__name__
            ))
        else:
            # the 2 extension modules are identical; quietly move on
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
            # the module names of the 2 extensions differ; assume they are different extensions and report that the
            # NAME is already in use
            raise LDAPExtensionError('{0} is already defined as an extension name'.format(ext_cls.NAME))
        else:
            # the modules names of the 2 extensions are equal; assume they are the same extension and quietly move on
            logger.debug('Extension module {0} does not need to be added'.format(modname))
            return
    except KeyError:
        # no predefined extension by this NAME
        pass

    # store the imported module for later use
    Extensible.ADDITIONAL_EXTENSIONS[ext_attr_name] = mod


def _import_extension(modname):
    """Import an extension module and run setup functions if necessary"""
    mod = import_module(modname)
    flag_attr = '__LAURELIN_EXTENSION_SETUP_COMPLETE'
    if not getattr(mod, flag_attr, False):
        # need to setup extension
        logger.info('Setting up extension {0}'.format(modname))
        try:
            ext_cls = getattr(mod, EXTENSION_CLSNAME)
            if not issubclass(ext_cls, BaseLaurelinExtension):
                raise LDAPExtensionError('{0}.{1} does not subclass laurelin.ldap.BaseLaurelinExtension'.format(
                    modname, EXTENSION_CLSNAME
                ))

            # call one-time setup functions
            ext_obj = ext_cls()
            ext_obj.require()

            # store the instance on a class attribute
            ext_cls.INSTANCE = ext_obj
        except AttributeError:
            pass
        setattr(mod, flag_attr, True)
    return mod


class Extensible(object):
    """Base for automatically-generated extension property classes"""

    AVAILABLE_EXTENSIONS = {
        'base_schema': {
            'module': 'laurelin.extensions.base_schema',
            'pip_package': None,  # built-in
            'docstring': 'The standard base schema from various RFCs'
        },
        'descattrs': {
            'module': 'laurelin.extensions.descattrs',
            'pip_package': None,  # built-in
            'docstring': 'The built-in description attributes extension',
        },
        'netgroups': {
            'module': 'laurelin.extensions.netgroups',
            'pip_package': None,  # built-in
            'docstring': 'The built-in NIS netgroups extension',
        },
        'paged_results': {
            'module': 'laurelin.extensions.pagedresults',
            'pip_package': None,  # built-in
            'docstring': 'Built-in extension defining standard paged results control for search'
        },
    }

    ADDITIONAL_EXTENSIONS = {}

    def __init__(self):
        self._extension_instances = {}
        self._built_in_only = False

    def _get_extension_instance(self, name):
        """This gets called and returned by auto-generated @property methods as their only line"""
        if self._built_in_only and self.AVAILABLE_EXTENSIONS[name]['pip_package'] is not None:
            raise RuntimeError('3rd-party extensions have been disabled')
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
        obj = self._create_extension_instance(name, mod)
        return obj

    def _create_extension_instance(self, name, mod):
        raise NotImplementedError()

    def __getattr__(self, item):
        # this acts like the auto-generated @property methods but fully dynamic, using modules that have been added
        # using add_extension()
        try:
            return self._extension_instances[item]
        except KeyError:
            pass
        try:
            ext_mod = self.ADDITIONAL_EXTENSIONS[item]
            if self._built_in_only:
                raise RuntimeError('3rd-party extensions have been disabled')
        except KeyError:
            raise AttributeError(item)
        obj = self._create_extension_instance(item, ext_mod)
        return obj


class ExtensibleClass(Extensible):
    """Base for auto-generated classes inherited by LDAP and LDAPObject"""

    EXTENSIBLE_CLASSES = ('LDAP', 'LDAPObject')

    def __init__(self):
        Extensible.__init__(self)
        self._extended_classname = None

    def _get_extended_classname(self):
        """Find the name of the class we are extending. Allows users to subclass LDAP or LDAPObject"""
        if self._extended_classname:
            return self._extended_classname
        else:
            for cls in self.__class__.__mro__:
                if cls.__name__ in self.EXTENSIBLE_CLASSES:
                    self._extended_classname = cls.__name__
                    return cls.__name__
            raise TypeError('This class does not inherit a known extensible class')

    def _create_extension_instance(self, name, mod):
        """Creates a new instance of the class extension for this class defined in mod"""
        my_classname = self._get_extended_classname()
        ext_classname = CLASS_EXTENSION_FMT.format(my_classname)
        base_classname = 'Base' + ext_classname
        try:
            cls = getattr(mod, ext_classname)
        except AttributeError:
            raise LDAPExtensionError('Extension {0} does not define an extension class for {1}'.format(
                mod.__name__, my_classname
            ))
        if not issubclass(cls, getattr(user_base, base_classname)):
            raise LDAPExtensionError('Extension class {0}.{1} does not subclass laurelin.ldap.{2}'.format(
                mod.__name__, ext_classname, base_classname
            ))
        obj = cls(parent=self)
        self._extension_instances[name] = obj
        return obj


class ExtensionsBase(Extensible):
    """Base for the auto-generated class giving access to all LaurelinExtension instances"""
    def _create_extension_instance(self, name, mod):
        instance = getattr(mod, EXTENSION_CLSNAME).INSTANCE
        return self._extension_instances.setdefault(name, instance)
