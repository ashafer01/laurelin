from rfc4511 import Operation

# describes a single modify operation
class Mod(object):
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

    # translate ldif modify operation strings to constant
    @staticmethod
    def string(op):
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

# generate a modlist from a dictionary
def Modlist(op, attrsDict):
    if not isinstance(attrsDict, dict):
        raise TypeError()
    modlist = []
    for attr, vals in attrsDict.iteritems():
        modlist.append(Mod(op, attr, vals))
    return modlist

## Smart modlist functions which will prevent errors

# generate a modlist to add only new attribute values that are not known to exist
def AddModlist(curAttrs, newAttrs):
    if not isinstance(curAttrs, dict):
        raise TypeError('curAttrs must be dict')
    if not isinstance(newAttrs, dict):
        raise TypeError('newAttrs must be dict')
    addAttrs = {}
    for attr, vals in newAttrs.iteritems():
        if attr in curAttrs:
            for val in vals:
                if val not in curAttrs[attr]:
                    if attr not in addAttrs:
                        addAttrs[attr] = []
                    addAttrs[attr].append(val)
        else:
            addAttrs[attr] = vals
    return Modlist(Mod.ADD, addAttrs)

# generate a modlist to delete only attribute values that are known to exist
def DeleteModlist(curAttrs, delAttrs):
    if not isinstance(delAttrs, dict):
        raise TypeError('curAttrs must be dict')
    if not isinstance(delAttrs, dict):
        raise TypeError('delAttrs must be dict')
    _delAttrs = {}
    for attr, vals in delAttrs.iteritems():
        if attr in curAttrs:
            if len(vals) == 0:
                _delAttrs[attr] = vals
            else:
                for val in vals:
                    if val in curAttrs[attr]:
                        if attr not in _delAttrs:
                            _delAttrs[attr] = []
                        _delAttrs[attr].append(val)
    return Modlist(Mod.DELETE, _delAttrs)

# for completeness - a replace operation should never return an error:
# # all attribute values will be replaced with those given if the attribute exists
# # attributes will be created if they do not exist
# # specifying a 0-length entry will delete that attribute
# # attributes not mentioned are not touched
def ReplaceModlist(*args):
    attrsDict = args[-1]
    return Modlist(Mod.REPLACE, attrsDict)
