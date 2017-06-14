from __future__ import absolute_import
from .errors import LDAPExtensionError

class Extensible(object):
    @classmethod
    def EXTEND(cls, *names):
        def _extend(method):
            if len(names) == 0:
                _names = (method.__name__,)
            else:
                _names = names
            for name in _names:
                if not hasattr(cls, name):
                    setattr(cls, name, method)
                else:
                    raise LDAPExtensionError('Cannot add extension attribute {0} - class {1}'
                        ' already has an attribute by that name'.format(name, cls.__name__))
            return method
        return _extend

