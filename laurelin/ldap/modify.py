"""Contains utilities for performing object modification"""

from __future__ import absolute_import
from .attributetype import get_attribute_type
from .rfc4511 import Operation
from .constants import DELETE_ALL
import six


class Mod(object):
    """Describes a single modify operation"""
    ADD = Operation('add')
    REPLACE = Operation('replace')
    DELETE = Operation('delete')

    @staticmethod
    def op_to_string(op):
        """Convert one of the :class:`Mod` constants to a string, e.g. "ADD", "REPLACE", "DELETE"."""
        if op == Mod.ADD:
            return 'ADD'
        elif op == Mod.REPLACE:
            return 'REPLACE'
        elif op == Mod.DELETE:
            return 'DELETE'
        else:
            raise ValueError()

    @staticmethod
    def string(op):
        """Translte LDIF changetype strings to constant. e.g. "replace" -> :attr:`.Mod.REPLACE`"""
        if op == 'add':
            return Mod.ADD
        elif op == 'replace':
            return Mod.REPLACE
        elif op == 'delete':
            return Mod.DELETE
        else:
            raise ValueError()

    def __init__(self, op, attr, vals):
        if (op != Mod.ADD) and (op != Mod.REPLACE) and (op != Mod.DELETE):
            raise ValueError()
        if vals is not DELETE_ALL and not isinstance(vals, list):
            vals = [vals]
        if (op == Mod.ADD) and (len(vals) == 0):
            raise ValueError('No values to add')
        self.op = op
        self.attr = attr
        self.vals = vals

    def __repr__(self):
        if self.vals:
            vals = str(self.vals)
        else:
            vals = 'DELETE_ALL'
        return 'Mod({0}, {1}, {2})'.format(repr(self.op), repr(self.attr), vals)


def _mod_op_repr(operation_obj):
    """Uses laurelin constant name representation for mod operations"""
    try:
        intval = int(operation_obj)
        name = operation_obj.namedValues.getName(intval)
        if name == 'add':
            return 'Mod.ADD'
        elif name == 'replace':
            return 'Mod.REPLACE'
        elif name == 'delete':
            return 'Mod.DELETE'
        else:
            return '{0}({1})'.format(operation_obj.__class__.__name__, repr(name))
    except Exception:
        return '{0}(<schema object>)'.format(operation_obj.__class__.__name__)


Operation.__repr__ = _mod_op_repr

def Modlist(op, attrs_dict):
    """Generate a modlist from a dictionary"""

    if not isinstance(attrs_dict, dict):
        raise TypeError('attrs_dict must be dict')
    modlist = []
    for attr, vals in six.iteritems(attrs_dict):
        modlist.append(Mod(op, attr, vals))
    return modlist


## Smart modlist functions which will prevent errors


def AddModlist(cur_attrs, new_attrs):
    """Generate a modlist to add only new attribute values that are not known to exist"""

    if not isinstance(cur_attrs, dict):
        raise TypeError('cur_attrs must be dict')
    if not isinstance(new_attrs, dict):
        raise TypeError('new_attrs must be dict')
    add_attrs = {}
    for attr, vals in six.iteritems(new_attrs):
        if attr in cur_attrs:
            attr_type = get_attribute_type(attr)
            for val in vals:
                try:
                    attr_type.index(cur_attrs[attr], val)
                    # attribute value already exists, do nothing
                except ValueError:
                    # attribute value does not exist, add it
                    if attr not in add_attrs:
                        add_attrs[attr] = []
                    add_attrs[attr].append(val)
        else:
            add_attrs[attr] = vals
    return Modlist(Mod.ADD, add_attrs)


def DeleteModlist(cur_attrs, del_attrs):
    """Generate a modlist to delete only attribute values that are known to exist"""

    if not isinstance(del_attrs, dict):
        raise TypeError('cur_attrs must be dict')
    if not isinstance(del_attrs, dict):
        raise TypeError('del_attrs must be dict')
    _del_attrs = {}
    for attr, vals in six.iteritems(del_attrs):
        if attr in cur_attrs:
            if not vals:
                _del_attrs[attr] = vals
            else:
                attr_type = get_attribute_type(attr)
                for val in vals:
                    try:
                        attr_type.index(cur_attrs[attr], val)
                        # attribute value exists, delete it
                        if attr not in _del_attrs:
                            _del_attrs[attr] = []
                        _del_attrs[attr].append(val)
                    except ValueError:
                        # attribute value does not exist, do nothing
                        pass
    return Modlist(Mod.DELETE, _del_attrs)
