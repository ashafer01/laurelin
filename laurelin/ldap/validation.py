import six
from six.moves import range

_validators = []

def getValidators():
    return _validators


class MetaValidator(type):
    """Metaclass which registers instances of subclasses"""
    def __new__(meta, name, bases, dct):
        cls = type.__new__(meta, name, bases, dct)
        if not name.startswith('Base'):
            _validators.append(cls())
        return cls


@six.add_metaclass(MetaValidator)
class BaseValidator(object):
    pass
