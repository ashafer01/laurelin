from ..utils import get_obj_module
from ..controls import Control
import six
import logging

logger = logging.getLogger(__name__)

_preregistered_controls = {}
_controls_registered_mods = set()


def register_module_controls(modname):
    if modname in _controls_registered_mods:
        return
    if modname not in _preregistered_controls:
        return
    for obj in _preregistered_controls[modname]:
        obj.register()
    _controls_registered_mods.add(modname)


class MetaLaurelinControls(type):
    def __new__(mcs, name, bases, dct):
        cls = type.__new__(mcs, name, bases, dct)
        modname = get_obj_module(cls)
        for attr, value in dct.items():
            if attr.startswith('_'):
                continue
            if isinstance(value, six.class_types):
                if issubclass(value, Control):
                    lst = _preregistered_controls.setdefault(modname, [])
                else:
                    logger.debug('Unhandled class type defined in class LaurelinControls')
                    continue
            else:
                logger.debug('Unhandled object type defined in class LaurelinControls')
                continue
            lst.append(value)
        return cls


@six.add_metaclass(MetaLaurelinControls)
class BaseLaurelinControls(object):
    pass
