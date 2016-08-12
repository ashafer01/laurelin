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
