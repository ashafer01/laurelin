from laurelin.ldap.base import LDAP, LDAP_rw, LDAPObject
from laurelin.ldap.modify import Mod, Modlist
from laurelin.ldap.errors import UnexpectedResponseType
from laurelin.ldap.rfc4511 import AbandonRequest

## LDAP extension methods

def search_async(self, *args, **kwds):
    fetchResultRefs = kwds.pop('fetchResutlRefs', self.defaultFetchResultRefs)
    mID = self._sendSearch(*args, **kwds)
    return AsyncSearchHandle(self, mID, fetchResultRefs)

def compare_async(self, *args):
    mID = self._sendCompare(*args)
    return AsyncCompareHandle(self, mID)

LDAP.EXTEND([
    search_async,
    compare_async,
])

## LDAP_rw extension methods

def add_async(self, DN, attrs):
    mID = self._sendAdd(DN, attrs)
    return AsyncAddHandle(self, mID, self.obj(DN, attrs))

def delete_async(self, DN):
    mID = self._sendDelete(DN)
    return AsyncResultHandle(self, mID, 'delResponse')

def modify_async(self, DN, modlist):
    mID = self._sendModify(DN, modlist)
    return AsyncResultHandle(self, mID, 'modifyResponse')

def addAttrs_async(self, DN, attrsDict):
    return self.modify_async(DN, Modlist(Mod.ADD, attrsDict))

def deleteAttrValues_async(self, DN, attrsDict):
    return self.modify_async(DN, Modlist(Mod.DELETE, attrsDict))

def deleteAttrs_async(self, DN, attrs):
    if not isinstance(attrs, list):
        attrs = [attrs]
    return self.deleteAttrValues_async(DN, dict.fromkeys(attrs, []))

def replaceAttrs_async(self, DN, attrsDict):
    return self.modify_async(DN, Modlist(Mod.REPLACE, attrsDict))

LDAP_rw.EXTEND([
    add_async,
    delete_async,
    modify_async,
    addAttrs_async,
    deleteAttrValues_async,
    deleteAttrs_async,
    replaceAttrs_async,
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
        raise NotImplementedError()

    def abandon(self):
        self._check()
        logger.debug('Abandoning messageID={0}'.format(self.messageID))
        self.abandoned = True
        self.sock.sendMessage('abandonRequest', AbandonRequest(self.messageID))
        self.sock.abandonedMID.append(self.messageID)

class AsyncSearchHandle(AsyncHandle):
    def __init__(self, ldapConn, messageID, fetchResultRefs=None):
        AsyncHandle.__init__(self, ldapConn, messageID)
        self.fetchResultRefs = fetchResultRefs

    def wait(self):
        self._check()
        return self.ldapConn._searchResultsAll(self.messageID, self.fetchResultRefs)

    def iter(self):
        self._check()
        return self.ldapConn._searchResults_iter(self.messageID, self.fetchResultRefs)

class AsyncCompareHandle(AsyncHandle):
    def wait(self):
        self._check()
        return self.ldapConn._compareResult(self.messageID)

class AsyncResultHandle(AsyncHandle):
    def __init__(self, ldapConn, messageID, operation):
        AsyncHandle.__init__(self, ldapConn, messageID)
        self.operation = operation

    def wait(self):
        self._check()
        return self.ldapConn._successResult(self.messageID, self.operation)

class AsyncAddHandle(AsyncResultHandle):
    def __init__(self, ldapConn, messageID, ldapObj):
        AsyncResultHandle.__init__(self, ldapConn, messageID, 'addResponse')
        self.ldapObj = ldapObj

    def wait(self):
        AsyncResultHandle.wait(self)
        return self.ldapObj
