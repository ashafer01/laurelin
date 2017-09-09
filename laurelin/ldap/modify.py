"""Contains utilities for performing object modification"""

from __future__ import absolute_import
from .attributetype import getAttributeType
from .rfc4511 import Operation
import six

class Mod(object):
    """Describes a single modify operation"""
    ADD = Operation('add')
    REPLACE = Operation('replace')
    DELETE = Operation('delete')

    @staticmethod
    def opToString(op):
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
        """Translte LDIF changetype strings to constant"""
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
        if not isinstance(vals, list):
            vals = [vals]
        if (op == Mod.ADD) and (len(vals) == 0):
            raise ValueError('No values to add')
        self.op = op
        self.attr = attr
        self.vals = vals

    def __str__(self):
        if len(self.vals) == 0:
            vals = '<all values>'
        else:
            vals = str(self.vals)
        return 'Mod({0}, {1}, {2})'.format(Mod.opToString(self.op), self.attr, vals)

    def __repr__(self):
        return 'Mod(Mod.{0}, {1}, {2})'.format(Mod.opToString(self.op), repr(self.attr),
            repr(self.vals))

def Modlist(op, attrsDict):
    """Generate a modlist from a dictionary"""

    if not isinstance(attrsDict, dict):
        raise TypeError('attrsDict must be dict')
    modlist = []
    for attr, vals in six.iteritems(attrsDict):
        modlist.append(Mod(op, attr, vals))
    return modlist

## Smart modlist functions which will prevent errors

def AddModlist(curAttrs, newAttrs):
    """Generate a modlist to add only new attribute values that are not known to exist"""

    if not isinstance(curAttrs, dict):
        raise TypeError('curAttrs must be dict')
    if not isinstance(newAttrs, dict):
        raise TypeError('newAttrs must be dict')
    addAttrs = {}
    for attr, vals in six.iteritems(newAttrs):
        if attr in curAttrs:
            attrType = getAttributeType(attr)
            for val in vals:
                try:
                    attrType.index(curAttrs[attr], val)
                    # attribute value already exists, do nothing
                except ValueError:
                    # attribute value does not exist, add it
                    if attr not in addAttrs:
                        addAttrs[attr] = []
                    addAttrs[attr].append(val)
        else:
            addAttrs[attr] = vals
    return Modlist(Mod.ADD, addAttrs)

def DeleteModlist(curAttrs, delAttrs):
    """Generate a modlist to delete only attribute values that are known to exist"""

    if not isinstance(delAttrs, dict):
        raise TypeError('curAttrs must be dict')
    if not isinstance(delAttrs, dict):
        raise TypeError('delAttrs must be dict')
    _delAttrs = {}
    for attr, vals in six.iteritems(delAttrs):
        if attr in curAttrs:
            if not vals:
                _delAttrs[attr] = vals
            else:
                attrType = getAttributeType(attr)
                for val in vals:
                    try:
                        attrType.index(curAttrs[attr], val)
                        # attribute value exists, delete it
                        if attr not in _delAttrs:
                            _delAttrs[attr] = []
                        _delAttrs[attr].append(val)
                    except ValueError:
                        # attribute value does not exist, do nothing
                        pass
    return Modlist(Mod.DELETE, _delAttrs)

def ReplaceModlist(*args):
    """For completeness - a replace operation should never return an error:

     * All attribute values will be replaced with those given if the attribute exists
     * Attributes will be created if they do not exist
     * Specifying a 0-length entry will delete that attribute
     * Attributes not mentioned are not touched
    """
    attrsDict = args[-1]
    return Modlist(Mod.REPLACE, attrsDict)
