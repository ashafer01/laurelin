from __future__ import absolute_import
from .attrsdict import AttrsDict
from .attrvaluelist import AttrValueList
from .constants import Scope
from .exceptions import (
    LDAPError,
    Abandon,
    LDAPTransactionError,
)
from .extensible import Extensible
from .modify import (
    Mod,
    Modlist,
    AddModlist,
    DeleteModlist,
)
import six


class LDAPObject(AttrsDict, Extensible):
    """Represents a single object with optional server affinity

     Many methods will raise an exception if used without a server connection. To instantiate an
     LDAPObject bound to a server connection, use LDAP.obj()

     Attributes and values are stored using the mapping interface inherited from AttrsDict.
    """

    def __init__(self, dn,
        attrsDict=None,
        ldapConn=None,
        relativeSearchScope=Scope.SUBTREE,
        rdnAttr=None
        ):

        self.dn = dn
        self.ldapConn = ldapConn
        self.relativeSearchScope = relativeSearchScope
        self.rdnAttr = rdnAttr
        AttrsDict.__init__(self)
        if attrsDict:
            AttrsDict.validate(attrsDict)
            for attr, values in six.iteritems(attrsDict):
                self[attr] = values

    def __repr__(self):
        return "LDAPObject(dn='{0}', attrs={1})".format(self.dn, AttrsDict.__repr__(self))

    def __eq__(self, other):
        if not isinstance(other, LDAPObject):
            return False
        elif self.dn != other.dn:
            return False
        else:
            return AttrsDict.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __setitem__(self, attr, values):
        if not isinstance(values, list):
            raise TypeError('must be list')
        values = AttrValueList(attr, values)
        AttrsDict.__setitem__(self, attr, values)

    def _hasLDAP(self):
        return (self.ldapConn is not None)

    def _requireLDAP(self):
        if not self._hasLDAP():
            raise RuntimeError('No LDAP instance')

    ## relative methods

    def _rdnAttr(self, rdn):
        if '=' not in rdn:
            if self.rdnAttr is not None:
                return '{0}={1}'.format(self.rdnAttr, rdn)
            else:
                raise ValueError('No rdnAttr specified, must supply full RDN attr=val')
        else:
            return rdn

    def RDN(self, rdn):
        rdn = self._rdnAttr(rdn)
        return '{0},{1}'.format(rdn, self.dn)

    def _setObjKwdDefaults(self, objKwds):
        """set inherited attributes on keywords dictionary, to make its way into new LDAPObjects"""
        objKwds.setdefault('relativeSearchScope', self.relativeSearchScope)
        objKwds.setdefault('rdnAttr', self.rdnAttr)

    def obj(self, rdn, attrsDict=None, tag=None, *args, **kwds):
        self._setObjKwdDefaults(kwds)
        if self._hasLDAP():
            return self.ldapConn.obj(self.RDN(rdn), attrsDict=attrsDict, tag=tag, *args, **kwds)
        else:
            if tag is not None:
                raise LDAPError('tagging requires LDAP instance')
            return LDAPObject(self.RDN(rdn), attrsDict=attrsDict, *args, **kwds)

    def getChild(self, rdn, attrs=None, **kwds):
        self._requireLDAP()
        self._setObjKwdDefaults(kwds)
        return self.ldapConn.get(self.RDN(rdn), attrs, **kwds)

    def addChild(self, rdn, attrsDict, **kwds):
        self._requireLDAP()
        self._setObjKwdDefaults(kwds)
        return self.ldapConn.add(self.RDN(rdn), attrsDict, **kwds)

    def search(self, filter=None, attrs=None, *args, **kwds):
        self._requireLDAP()
        self._setObjKwdDefaults(kwds)
        return self.ldapConn.search(self.dn, self.relativeSearchScope, filter, attrs, *args, **kwds)

    def find(self, rdn, attrs=None, **kwds):
        self._requireLDAP()
        self._setObjKwdDefaults(kwds)
        if self.relativeSearchScope == Scope.BASE:
            raise LDAPError('Object has no children')
        elif self.relativeSearchScope == Scope.ONELEVEL:
            return self.getChild(rdn, attrs, **kwds)
        elif self.relativeSearchScope == Scope.SUBTREE:
            filter = '({0})'.format(self._rdnAttr(rdn))
            res = list(self.search(filter=filter, attrs=attrs, limit=2, **kwds))
            n = len(res)
            if n == 0:
                raise NoSearchResults()
            elif n == 1:
                return res[0]
            else:
                raise MultipleSearchResults()
        else:
            raise ValueError('Unknown relativeSearchScope')

    def compare(self, attr, value):
        self._requireLDAP()
        return self.ldapConn.compare(self.dn, attr, value)

    ## object-specific methods

    def formatLDIF(self):
        lines = ['dn: {0}'.format(self.dn)]
        for attr, val in self.iterattrs():
            lines.append('{0}: {1}'.format(attr, val))
        lines.append('')
        return '\n'.join(lines)

    def hasObjectClass(self, objectClass):
        self.refreshMissing(['objectClass'])
        return (objectClass in self['objectClass'])

    def refresh(self, attrs=None):
        self._requireLDAP()
        self.update(self.ldapConn.get(self.dn, attrs))

    def refreshAll(self):
        self._requiredLDAP()
        self.refresh(['*', '+'])

    def refreshMissing(self, attrs):
        missingAttrs = []
        for attr in attrs:
            if attr not in self:
                missingAttrs.append(attr)
        if len(missingAttrs) > 0:
            self.refresh(missingAttrs)

    ## object modify methods

    def modify(self, modlist, **ctrlKwds):
        self._requireLDAP()
        self.ldapConn.modify(self.dn, modlist, current=self, **ctrlKwds)
        self._localModify(modlist)

    def addAttrs(self, attrsDict, **ctrlKwds):
        if not self.ldapConn.strictModify:
            self.refreshMissing(list(attrsDict.keys()))
        modlist = AddModlist(self, attrsDict)
        self.modify(modlist, **ctrlKwds)

    def replaceAttrs(self, attrsDict, **ctrlKwds):
        modlist = Modlist(Mod.REPLACE, attrsDict)
        self.modify(modlist, **ctrlKwds)

    def deleteAttrs(self, attrsDict, **ctrlKwds):
        if not self.ldapConn.strictModify:
            self.refreshMissing(list(attrsDict.keys()))
        modlist = DeleteModlist(self, attrsDict)
        self.modify(modlist, **ctrlKwds)

    def _localModify(self, modlist):
        """Perform local modify after writing to server"""
        for mod in modlist:
            if mod.op == Mod.ADD:
                if mod.attr not in self:
                    self[mod.attr] = mod.vals
                else:
                    self[mod.attr].extend(mod.vals)
            elif mod.op == Mod.REPLACE:
                if mod.vals:
                    self[mod.attr] = mod.vals
                else:
                    del self[mod.attr]
            elif mod.op == Mod.DELETE:
                if mod.attr in self:
                    if mod.vals:
                        for val in mod.vals:
                            try:
                                self._deleteAttrValue(mod.attr, val)
                            except ValueError:
                                pass
                    else:
                        del self[mod.attr]
            else:
                raise ValueError('Invalid mod op')

    def _deleteAttrValue(self, attr, val):
        """Delete a single local attribute value"""
        self[attr].remove(val)
        if not self[attr]:
            del self[attr]

    ## online-only object-level methods

    def delete(self, **ctrlKwds):
        """delete the entire object from the server, and render this instance useless"""
        self._requireLDAP()
        self.ldapConn.delete(self.dn, **ctrlKwds)
        self.clear()
        self.dn = None
        self.ldapConn = None

    def modDN(self, newRDN, cleanAttr=True, newParent=None, **ctrlKwds):
        """change the object DN, and possibly its location in the tree"""
        self._requireLDAP()
        curRDN, curParent = self.dn.split(',', 1)
        if newParent is None:
            parent = curParent
        else:
            parent = newParent
        self.ldapConn.modDN(self.dn, newRDN, cleanAttr, parent, **ctrlKwds)
        if cleanAttr:
            rdnAttr, rdnVal = curRDN.split('=', 1)
            try:
                self._deleteAttrValue(rdnAttr, rdnVal)
            except Exception:
                pass
        rdnAttr, rdnVal = newRDN.split('=', 1)
        if rdnAttr not in self:
            self[rdnAttr] = [rdnVal]
        elif rdnVal not in self[rdnAttr]:
            self[rdnAttr].append(rdnVal)
        self.dn = '{0},{1}'.format(newRDN, parent)

    def rename(self, newRDN, cleanAttr=True, **ctrlKwds):
        return self.modDN(newRDN, cleanAttr, **ctrlKwds)

    def move(self, newDN, cleanAttr=True, **ctrlKwds):
        newRDN, newParent = newDN.split(',', 1)
        return self.modDN(newRDN, cleanAttr, newParent, **ctrlKwds)

    ## validation methods

    def validate(self):
        """Validate the object, assuming all attributes are present locally"""
        self.ldapConn.validateObject(self, write=False)

    def validateModify(self, modlist):
        """Validate a modification list"""
        self.ldapConn.validateModify(self.dn, modlist, self)

    ## transactions

    def modTransaction(self):
        return ModTransactionObject(self)


class ModTransactionObject(LDAPObject):
    """Provides a transaction-like construct for building up a single modify operation"""

    def __init__(self, ldapObject):
        self._origObj = ldapObject
        self._modlist = []

        LDAPObject.__init__(self,
            dn=ldapObject.dn,
            attrsDict=ldapObject.deepcopy(),
            ldapConn=ldapObject.ldapConn,
            relativeSearchScope=ldapObject.relativeSearchScope,
            rdnAttr=ldapObject.rdnAttr,
        )

    def __enter__(self):
        return self

    def __exit__(self, etype, e, trace):
        self._modlist = []
        if etype == Abandon:
            return True

    def commit(self):
        self._origObj.modify(self._modlist)
        self._modlist = []

    def modify(self, modlist):
        self.validateModify(modlist)
        self._modlist.extend(modlist)
        self._localModify(modlist)

    def addChild(self, rdn, attrsDict, **kwds):
        raise LDAPTransactionError('add not included in modify transaction')

    def delete(self, **ctrlKwds):
        raise LDAPTransactionError('delete not included in modify transaction')

    def modDN(self, newRDN, cleanAttr=True, newParent=None, **ctrlKwds):
        raise LDAPTransactionError('modDN not included in modify transaction')
