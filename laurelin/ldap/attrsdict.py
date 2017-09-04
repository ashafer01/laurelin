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

    ## dict overrides for case-insensitive keys and enforcing types

    def __init__(self, attrsDict=None):
        self._keys = {}
        if attrsDict is not None:
            self.update(attrsDict)

    def __contains__(self, attr):
        try:
            key = self._keys[six.text_type(attr).lower()]
            if dict.__contains__(self, key):
                return (len(self[key]) > 0)
            else:
                return False
        except KeyError:
            return False

    def __setitem__(self, attr, values):
        AttrsDict.validateAttr(attr)
        AttrsDict.validateValues(values)
        self._keys[attr.lower()] = attr
        dict.__setitem__(self, attr, values)

    def setdefault(self, attr, default=None):
        AttrsDict.validateAttr(attr)
        if default is None:
            default = []
        try:
            AttrsDict.validateValues(default)
        except TypeError as e:
            raise TypeError('invalid default - {0}'.format(str(e)))
        try:
            return self[attr]
        except KeyError:
            self[attr] = default
            return default

    def __getitem__(self, key):
        key = self._keys[key.lower()]
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def update(self, attrsDict):
        AttrsDict.validate(attrsDict)
        dict.update(self, attrsDict)
        for key in self:
            self._keys[key.lower()] = key

    def __delitem__(self, key):
        lkey = key.lower()
        key = self._keys[lkey]
        dict.__delitem__(self, key)
        del self._keys[lkey]

    def clear(self):
        dict.clear(self)
        self._keys.clear()

    @staticmethod
    def validate(attrsDict):
        if isinstance(attrsDict, AttrsDict):
            return
        if not isinstance(attrsDict, dict):
            raise TypeError('must be dict')
        for attr in attrsDict:
            AttrsDict.validateAttr(attr)
            AttrsDict.validateValues(attrsDict[attr])

    @staticmethod
    def validateAttr(attr):
        if not isinstance(attr, six.string_types):
            raise TypeError('attribute name must be string')

    @staticmethod
    def validateValues(attrValList):
        if not isinstance(attrValList, list):
            raise TypeError('must be list')
        for val in attrValList:
            # TODO binary data support throughout...
            if not isinstance(val, six.string_types):
                raise TypeError('attribute values must be string')
