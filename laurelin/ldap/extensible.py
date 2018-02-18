from __future__ import absolute_import
from .exceptions import LDAPExtensionError


class Extensible(object):
    @classmethod
    def EXTEND(cls, method_list):
        """Install extension methods to the class

        :param method_list: A list of callables
        :raises LDAPExtensionError: if a name is alread an attribute of the class
        """
        for method in method_list:
            if not hasattr(cls, method.__name__):
                setattr(cls, method.__name__, method)
            else:
                raise LDAPExtensionError('Cannot add extension attribute {0} - class {1} already has an attribute by '
                                         'that name'.format(method.__name__, cls.__name__))
