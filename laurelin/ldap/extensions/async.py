from ldap.base import LDAP, LDAP_rw, LDAPObject, _unpack, _checkSuccessResult, _processCompareResults
from ldap.modify import Mod, Modlist

## LDAP extension methods

def searchAsync(self, *args, **kwds):
    mID = self._sendSearch(*args, **kwds)
    return AsyncSearchHandle(self, mID)

def compareAsync(self, *args):
    mID = self._sendCompare(*args)
    return AsyncHandle(self, mID, _processCompareResults)

LDAP.EXTEND([
    searchAsync,
    compareAsync,
])

## LDAP_rw extension methods

def addAsync(self, DN, attrs):
    mID = self._sendAdd(DN, attrs)
    return AsyncAddHandle(self, mID, LDAPObject(DN, attrs, self))

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
    def __init__(self, ldapConn, messageID, postProcess=lambda x: x):
        self.messageID = messageID
        self.sock = ldapConn.sock
        self.ldapConn = ldapConn
        self.abandoned = False
        self.postProcess = postProcess

    def wait(self):
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.abandoned:
            raise AbandonedAsyncError()
        logger.debug('Waiting for at least 1 object for messageID={0}'.format(self.messageID))
        ret = []
        while len(ret) < 1:
            if self.abandoned:
                logger.debug('Abandoned; stopping wait')
                break
            ret += self.sock.recvResponse(self.messageID)
        logger.debug('Done waiting for messageID={0}'.format(self.messageID))
        return self.postProcess(ret)

    def abandon(self):
        if self.sock.unbound:
            raise ConnectionUnbound()
        logger.debug('Abandoning messageID={0}'.format(self.messageID))
        self.abandoned = True
        self.sock.sendMessage('abandonRequest', AbandonRequest(self.messageID))
        self.sock.abandonedMID.append(self.messageID)

class AsyncSearchHandle(AsyncHandle):
    def wait(self):
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.abandoned:
            raise AbandonedAsyncError()
        return self.ldapConn._recvSearchResults(self.messageID)

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
