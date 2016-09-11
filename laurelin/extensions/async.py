from laurelin.ldap.base import (
    LDAP,
    LDAP_rw,
    LDAPObject,
    _checkSuccessResult,
)
from laurelin.ldap.modify import Mod, Modlist
from laurelin.ldap.errors import UnexpectedResponseType
from laurelin.ldap.rfc4511 import AbandonRequest

## LDAP extension methods

def searchAsync(self, *args, **kwds):
    mID = self._sendSearch(*args, **kwds)
    return AsyncSearchHandle(self, mID)

def compareAsync(self, *args):
    mID = self._sendCompare(*args)
    return AsyncCompareHandle(self, mID)

LDAP.EXTEND([
    searchAsync,
    compareAsync,
])

## LDAP_rw extension methods

def addAsync(self, DN, attrs):
    mID = self._sendAdd(DN, attrs)
    return AsyncAddHandle(self, mID, self.obj(DN, attrs))

def deleteAsync(self, DN):
    mID = self._sendDelete(DN)
    return AsyncResultHandle(self, mID, 'delResponse')

def modifyAsync(self, DN, modlist):
    mID = self._sendModify(DN, modlist)
    return AsyncResultHandle(self, mID, 'modifyResponse')

def addAttrsAsync(self, DN, attrsDict):
    return self.modifyAsync(DN, Modlist(Mod.ADD, attrsDict))

def deleteAttrValuesAsync(self, DN, attrsDict):
    return self.modifyAsync(DN, Modlist(Mod.DELETE, attrsDict))

def deleteAttrsAsync(self, DN, attrs):
    if not isinstance(attrs, list):
        attrs = [attrs]
    return self.deleteAttrValuesAsync(DN, dict.fromkeys(attrs, []))

def replaceAttrsAsync(self, DN, attrsDict):
    return self.modifyAsync(DN, Modlist(Mod.REPLACE, attrsDict))

LDAP_rw.EXTEND([
    addAsync,
    deleteAsync,
    modifyAsync,
    addAttrsAsync,
    deleteAttrValuesAsync,
    deleteAttrsAsync,
    replaceAttrsAsync,
])

## async handles

class AsyncHandle(object):
    def __init__(self, ldapConn, messageID):
        self.messageID = messageID
        self.sock = ldapConn.sock
        self.ldapConn = ldapConn
        self.abandoned = False

    def _check(self):
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.abandoned:
            raise AbandonedAsyncError()

    def wait(self):
        self._check()
        return self.sock.recvAll(self.messageID)

    def abandon(self):
        self._check()
        logger.debug('Abandoning messageID={0}'.format(self.messageID))
        self.abandoned = True
        self.sock.sendMessage('abandonRequest', AbandonRequest(self.messageID))
        self.sock.abandonedMID.append(self.messageID)

class AsyncSearchHandle(AsyncHandle):
    def wait(self):
        self._check()
        return self.ldapConn._searchResultsAll(self.messageID)

    def iter(self):
        self._check()
        return self.ldapConn._searchResultsIter(self.messageID)

class AsyncCompareHandle(AsyncHandle):
    def wait(self):
        self._check()
        return self.ldapConn._compareResult(self.messageID)

class AsyncResultHandle(AsyncHandle):
    def __init__(self, ldapConn, messageID, operation):
        AsyncHandle.__init__(self, ldapConn, messageID)
        self.operation = operation

    def wait(self):
        msg = AsyncHandle.wait(self)[0]
        return _checkSuccessResult(msg, self.operation)

class AsyncAddHandle(AsyncResultHandle):
    def __init__(self, ldapConn, messageID, ldapObj):
        AsyncResultHandle.__init__(self, ldapConn, messageID, 'addResponse')
        self.ldapObj = ldapObj

    def wait(self):
        AsyncResultHandle.wait(self)
        return self.ldapObj
