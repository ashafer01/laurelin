"""structured description field methods
 this implements the common pattern of storing arbitrary key=value data in description fields
"""

from laurelin.ldap import LDAPObject
from laurelin.ldap.attrsdict import AttrsDict

DESC_ATTR_DELIM = '='

@LDAPObject.EXTEND()
def descAttrs(self):
    self.refreshMissing(['description'])
    ret = AttrsDict()
    self._unstructuredDesc = set()
    for desc in self.getAttr('description'):
        if DESC_ATTR_DELIM in desc:
            key, value = desc.split(DESC_ATTR_DELIM, 1)
            vals = ret.setdefault(key, [])
            vals.append(value)
        else:
            self._unstructuredDesc.add(desc)
    return ret

@LDAPObject.EXTEND()
def _modifyDescAttrs(self, method, attrsDict):
    self._requireLDAP()
    descDict = self.descAttrs()
    method(descDict, attrsDict)
    descStrings = []
    for key, values in six.iteritems(descDict):
        for value in values:
            descStrings.append(key + DESC_ATTR_DELIM + value)
    self.replace_attrs({'description': descStrings + list(self._unstructuredDesc)}, )

def dictModAdd(toDict, attrsDict):
    """Adds attributes from attrsDict to toDict"""
    for attr, vals in six.iteritems(attrsDict):
        if attr not in toDict:
            toDict[attr] = vals
        else:
            for val in vals:
                if val not in toDict[attr]:
                    toDict[attr].append(val)

def dictModReplace(toDict, attrsDict):
    """Replaces attribute values in toDict with those from attrsDict"""
    toDict.update(attrsDict)

def dictModDelete(toDict, attrsDict):
    """Deletes attribute values from toDict that appear in attrsDict"""
    for attr, delVals in six.iteritems(attrsDict):
        if attr in toDict:
            if delVals:
                for val in delVals:
                    try:
                        toDict[attr].remove(val)
                    except Exception:
                        pass
            else:
                del toDict[attr]

@LDAPObject.EXTEND()
def addDescAttrs(self, attrsDict):
    self._modifyDescAttrs(dictModAdd, attrsDict)

@LDAPObject.EXTEND()
def replaceDescAttrs(self, attrsDict):
    self._modifyDescAttrs(dictModReplace, attrsDict)

@LDAPObject.EXTEND()
def deleteDescAttrs(self, attrsDict):
    self._modifyDescAttrs(dictModDelete, attrsDict)
