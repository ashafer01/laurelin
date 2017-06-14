from __future__ import absolute_import
from .modify import (
    Mod,
    dictModAdd,
    dictModReplace,
    dictModDelete,
)
import six

class AttrsDict(dict):
    """Stores attributes and provides utility methods without any server or object affinity

     Dict keys are attribute names, and dict values are a list of attribute values
    """

    def getAttr(self, attr):
        return self.get(attr, [])

    def iterattrs(self):
        for attr, vals in six.iteritems(self):
            for val in vals:
                yield (attr, val)

    def deepcopy(self):
        """return a native dict copy of self"""
        ret = {}
        for attr, vals in six.iteritems(self):
            ret[attr] = []
            for val in vals:
                ret[attr].append(val)
        return ret

    ## local modify methods
    ## accept same input as online versions, but only update the local attributes dictionary

    def modify_local(self, modlist):
        for mod in modlist:
            if mod.op == Mod.ADD:
                self.addAttrs_local({mod.attr: mod.vals})
            elif mod.op == Mod.REPLACE:
                self.replaceAttrs_local({mod.attr: mod.vals})
            elif mod.op == Mod.DELETE:
                self.deleteAttrs_local({mod.attr: mod.vals})
            else:
                raise ValueError('Invalid mod op')

    addAttrs_local = dictModAdd
    replaceAttrs_local = dictModReplace
    deleteAttrs_local = dictModDelete

    ## dict overrides for enforcing types

    def __init__(self, attrsDict=None):
        if attrsDict is not None:
            AttrsDict.validate(attrsDict)
            dict.__init__(self, attrsDict)

    def __contains__(self, attr):
        if dict.__contains__(self, attr):
            return (len(self[attr]) > 0)
        else:
            return False

    def __setitem__(self, attr, values):
        AttrsDict.validateValues(values)
        dict.__setitem__(self, attr, values)

    def setdefault(self, attr, default=None):
        if not isinstance(attr, six.string_types):
            raise TypeError('attribute name must be string')
        if default is None:
            default = []
        try:
            AttrsDict.validateValues(default)
            return dict.setdefault(self, attr, default)
        except TypeError as e:
            raise TypeError('invalid default - {0}'.format(e.message))

    def update(self, attrsDict):
        AttrsDict.validate(attrsDict)
        dict.update(self, attrsDict)

    @staticmethod
    def validate(attrsDict):
        if isinstance(attrsDict, AttrsDict):
            return
        if not isinstance(attrsDict, dict):
            raise TypeError('must be dict')
        for attr in attrsDict:
            if not isinstance(attr, six.string_types):
                raise TypeError('attribute name must be string')
            AttrsDict.validateValues(attrsDict[attr])

    @staticmethod
    def validateValues(attrValList):
        if not isinstance(attrValList, list):
            raise TypeError('must be list')
        for val in attrValList:
            # TODO binary data support throughout...
            if not isinstance(val, six.string_types):
                raise TypeError('attribute values must be string')
