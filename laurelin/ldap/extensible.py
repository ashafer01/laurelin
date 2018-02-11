from __future__ import absolute_import
from .exceptions import LDAPExtensionError


class Extensible(object):
    @classmethod
    def EXTEND(cls, method_list):
        """Install extension methods to the class

        :param method_list: A list of callables alone or a tuple of (name: str, callable)
        :raises LDAPExtensionError: if a name is alread an attribute of the class, or if a tuple list entry does not
                                    have exactly 2 values
        """
        for method in method_list:
            if isinstance(method, tuple):
                if len(method) != 2:
                    raise LDAPExtensionError('Cannot add extension attribute, must have 2 tuple values.')
                name = method[0]
                method = method[1]
            else:
                name = method.__name__
            if not hasattr(cls, name):
                setattr(cls, name, method)
            else:
                raise LDAPExtensionError('Cannot add extension attribute {0} - class {1} already has an attribute by '
                                         'that name'.format(name, cls.__name__))
