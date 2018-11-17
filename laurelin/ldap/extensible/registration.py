from ..attributetype import AttributeType
from ..exceptions import LDAPExtensionError
from ..controls import Control
from ..objectclass import ObjectClass
from ..rules import SyntaxRule, MatchingRule
from ..utils import get_obj_module
import six
import logging

logger = logging.getLogger(__name__)

_preregistered_elements = {}
_registered_mods = set()

_recognized_subclasses = (SyntaxRule, MatchingRule, Control)
_recognized_instances = (ObjectClass, AttributeType)


class MetaLaurelinTransiter(type):
    """Prepares schema elements and controls defined as attributes of infraclasses for registration"""
    def __new__(mcs, name, bases, dct):
        cls = type.__new__(mcs, name, bases, dct)
        modname = get_obj_module(cls)

        for attr, value in dct.items():
            if attr.startswith('_'):
                continue

            if isinstance(value, six.class_types) and issubclass(value, _recognized_subclasses):
                is_element = True
            elif isinstance(value, _recognized_instances):
                is_element = True
            else:
                is_element = False

            if is_element:
                if modname not in _preregistered_elements:
                    _preregistered_elements[modname] = []
                _preregistered_elements[modname].append(value)

        return cls


@six.add_metaclass(MetaLaurelinTransiter)
class LaurelinTransiter(object):
    """Base class for classes in extensions defining schema elements or controls"""
    pass


class LaurelinRegistrar(object):
    """The require() method on this class registers all schema and controls in a module.

    If this class is subclassed in an extension module (such as with LaurelinExtension), there is no need to pass an
    argument to the constructor. However, for extensions with many schema elements or controls, it may be desirable to
    break up these objects into multiple submodules that are imported on end-user request.

    In such a setup, an instance of LaurelinRegistrar would need to be created and exposed to the end-user for each
    submodule so that they can call ``.require()`` on it. This constructor would need to be passed ``__name__``.

    Note that if this is applied to a package, require() will function on all imported submodules of the package.
    """

    def __init__(self, modname=None):
        if modname:
            self.modname = modname
        else:
            self.modname = get_obj_module(self.__class__)
            if self.modname == __name__:
                raise LDAPExtensionError('You must pass __name__ to LaurelinRegistrar()')

    def require(self):
        """Register schema elements and controls defined in any LaurelinTransiter subclass in the same module as the
        calling class. If the calling class is defined in an __init__.py, also register schema/controls for submodules
        that have been imported.
        """
        if self.modname in _registered_mods:
            return
        package_prefix = self.modname + '.'
        for key_modname, elements in _preregistered_elements.items():
            # check for prefix to allow definition in submodules of a package
            if key_modname in _registered_mods:
                continue
            if key_modname == self.modname or key_modname.startswith(package_prefix):
                logger.debug('Registering schema and controls for {0}'.format(key_modname))
                for obj in elements:
                    obj.register()
                _registered_mods.add(self.modname)
