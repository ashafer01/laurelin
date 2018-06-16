from __future__ import absolute_import
from .exceptions import LDAPExtensionError
from importlib import import_module


class ExtensionBase(object):
    """Base for extension property classes inherited by LDAP and LDAPObject"""

    AVAILABLE_EXTENSIONS = {
        'descattrs': {
            'module': 'laurelin.extensions.descattrs',
            'pip_package': None,  # built-in
        },
        'netgroups': {
            'module': 'laurelin.extensions.netgroups',
            'pip_package': None,  # built-in
        }
    }

    def __init__(self):
        self._extension_instances = {}

    def _get_extension_instance(self, name):
        try:
            return self._extension_instances[name]
        except KeyError:
            extinfo = self.AVAILABLE_EXTENSIONS[name]
            modname = extinfo['module']
            try:
                mod = import_module(modname)
            except ImportError:
                pip_package = extinfo['pip_package']
                if pip_package is None:
                    raise LDAPExtensionError('Error importing built-in extension {0}. This may be a '
                                             'bug.'.format(modname))
                else:
                    raise LDAPExtensionError('Error importing {0}, the extension may not be installed. Try `pip '
                                             'install {1}`'.format(modname, pip_package))

            my_classname = self.__class__.__name__
            ext_classname = 'Laurelin{0}Extension'.format(my_classname)
            try:
                cls = getattr(mod, ext_classname)
            except AttributeError:
                raise LDAPExtensionError('Extension {0} does not define an extension class for '
                                         '{1}'.format(mod.__name__, my_classname))
            if not issubclass(cls, globals()[ext_classname]):
                raise LDAPExtensionError('Extension class {0}.{1} does not subclass {2}.{3}'.format(
                    mod.__name__, ext_classname, __name__, ext_classname
                ))
            obj = cls(parent=self)
            self._extension_instances[name] = obj
            return obj


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
