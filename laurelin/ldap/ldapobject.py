from __future__ import absolute_import
from .attrsdict import AttrsDict
from .constants import Scope
from .exceptions import LDAPError
from .extensible import Extensible
from .modify import (
    dictModAdd,
    dictModReplace,
    dictModDelete,
)
import logging
import six

logger = logging.getLogger(__name__)

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
        self._unstructuredDesc = set()
        AttrsDict.__init__(self, attrsDict)

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

    def refreshMissing(self, attrs):
        missingAttrs = []
        for attr in attrs:
            if attr not in self:
                missingAttrs.append(attr)
        if len(missingAttrs) > 0:
            self.refresh(missingAttrs)

    def commit(self):
        """update the server with the local attributes dictionary"""
        self._requireLDAP()
        self.ldapConn.replaceAttrs(self.dn, self)
        self._removeEmptyAttrs()

    def compare(self, attr, value):
        if attr in self:
            logger.debug('Doing local compare for {0} ({1} = {2})'.format(self.dn, attr, value))
            return (value in self.getAttr(attr))
        elif self._hasLDAP():
            return self.ldapConn.compare(self.dn, attr, value)
        else:
            raise RuntimeError('No LDAP object')

    def _removeEmptyAttrs(self):
        """clean any 0-length attributes from the local dictionary so as to match the server
         called automatically after writing to the server
        """
        for attr in self.keys():
            if len(self[attr]) == 0:
                del self[attr]

    ## online modify methods
    ## these call the LDAP methods of the same name, passing the object's DN as the first
    ## argument, then call the matching local modify method after a successful request to the
    ## server

    def modify(self, modlist, **ctrlKwds):
        self._requireLDAP()
        self.ldapConn.modify(self.dn, modlist, **ctrlKwds)
        self.modify_local(modlist)
        self._removeEmptyAttrs()

    def addAttrs(self, attrsDict, **ctrlKwds):
        self._requireLDAP()
        if not self.ldapConn.strictModify:
            self.refreshMissing(list(attrsDict.keys()))
        self.ldapConn.addAttrs(self.dn, attrsDict, current=self, **ctrlKwds)
        self.addAttrs_local(attrsDict)

    def replaceAttrs(self, attrsDict, **ctrlKwds):
        self._requireLDAP()
        self.ldapConn.replaceAttrs(self.dn, attrsDict, **ctrlKwds)
        self.replaceAttrs_local(attrsDict)
        self._removeEmptyAttrs()

    def deleteAttrs(self, attrsDict, **ctrlKwds):
        self._requireLDAP()
        if not self.ldapConn.strictModify:
            self.refreshMissing(list(attrsDict.keys()))
        self.ldapConn.deleteAttrs(self.dn, attrsDict, current=self, **ctrlKwds)
        self.deleteAttrs_local(attrsDict)
        self._removeEmptyAttrs()

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
                self[rdnAttr].remove(rdnVal)
                self._removeEmptyAttrs()
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
