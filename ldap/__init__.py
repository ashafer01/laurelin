__all__ = []

import logging
logger = logging.getLogger('pyldap')
stderrHandler = logging.StreamHandler()
stderrHandler.setFormatter(logging.Formatter('[%(asctime)s] %(name)s %(levelname)s : %(message)s'))
logger.addHandler(stderrHandler)
logger.setLevel(logging.DEBUG)

from rfc4511 import LDAPDN, LDAPString, ResultCode, Integer0ToMax as NonNegativeInteger
from rfc4511 import SearchRequest, AttributeSelection, BindRequest, AuthenticationChoice
from rfc4511 import LDAPMessage, MessageID, ProtocolOp, Version, UnbindRequest, CompareRequest
from rfc4511 import Simple as SimpleCreds, TypesOnly, AttributeValueAssertion
from rfc4511 import AttributeDescription, AssertionValue, AbandonRequest
from filter import parse as parseFilter
from base import Scope, DerefAliases, LDAPError
from net import LDAPSocket

# unpack an object from an LDAPMessage envelope
def _unpack(op, ldapMessage):
    po = ldapMessage.getComponentByName('protocolOp')
    ret = po.getComponentByName(op)
    if ret is not None:
        return ret
    else:
        raise UnexpectedResponseType()

# recv all objects from given LDAPSocket until we get a SearchResultDone; return a list of LDAPObject
def _recvSearchResults(sock, messageID):
    ret = []
    logger.debug('Receiving all search results for messageID={0}'.format(messageID))
    while True:
        for msg in sock.recvResponse(messageID):
            try:
                entry = _unpack('searchResEntry', msg)
                DN = unicode(entry.getComponentByName('objectName'))
                attrs = {}
                _attrs = entry.getComponentByName('attributes')
                for i in range(0, len(_attrs)):
                    _attr = _attrs.getComponentByPosition(i)
                    attrType = unicode(_attr.getComponentByName('type'))
                    _vals = _attr.getComponentByName('vals')
                    vals = []
                    for j in range(0, len(_vals)):
                        vals.append(unicode(_vals.getComponentByPosition(j)))
                    attrs[attrType] = vals
                ret.append(LDAPObject(DN, attrs))
                logger.debug('Got search result object {0}'.format(DN))
            except UnexpectedResponseType:
                done = _unpack('searchResDone', msg)
                result = done.getComponentByName('resultCode')
                if result == ResultCode('success'):
                    logger.debug('Search completed successfully')
                    return ret
                else:
                    raise LDAPError('Search returned {0}'.format(repr(result)))

# convert compare result codes to boolean
def _processCompareResults(ldapMessages):
    res = _unpack('compareResponse', ldapMessages[0]).getComponentByName('resultCode')
    if res == ResultCode('compareTrue'):
        logger.debug('Compared True')
        return True
    elif res == ResultCode('compareFalse'):
        logger.debug('Compared False')
        return False
    else:
        raise LDAPError('Got compare result {0}'.format(repr(res)))

# for storing reusable sockets
_sockets = {}

class LDAPObject(dict):
    def __init__(self, dn, attrs):
        self.dn = dn
        dict.__init__(self, attrs)

    def __repr__(self):
        return "LDAPObject(dn='{0}', attrs={1})".format(self.dn, dict.__repr__(self))

class LDAP(object):
    ## global defaults
    DEFAULT_FILTER = '(objectClass=*)'
    DEFAULT_DEREF_ALIASES = DerefAliases.ALWAYS
    DEFAULT_SEARCH_TIMEOUT = 0
    DEFAULT_CONNECT_TIMEOUT = 5

    ## other constants
    NO_ATTRS = '1.1'
    ALL_USER_ATTRS = '*'

    def __init__(self, hostURI,
        reuseConnection=True,
        reuseConnectionFrom=None,
        connectTimeout=DEFAULT_CONNECT_TIMEOUT,
        searchTimeout=DEFAULT_SEARCH_TIMEOUT,
        derefAliases=DEFAULT_DEREF_ALIASES,
        ):

        ## setup
        self.defaultSearchTimeout = searchTimeout
        self.defaultDerefAliases = derefAliases

        ## connect
        if reuseConnectionFrom is not None:
            self.sock = reuseConnectionFrom.sock
        elif reuseConnection:
            if hostURI not in _sockets:
                _sockets[hostURI] = LDAPSocket(hostURI, connectTimeout)
            self.sock  = _sockets[hostURI]
        else:
            self.sock = LDAPSocket(hostURI, connectTimeout)
        logger.debug('Connected to {0} (#{1})'.format(hostURI, self.sock.ID))

    def simpleBind(self, user, pw):
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.sock.bound:
            raise ConnectionAlreadyBound()

        ## prepare bind request
        br = BindRequest()
        br.setComponentByName('version', Version(3))
        br.setComponentByName('name', LDAPDN(unicode(user)))
        ac = AuthenticationChoice()
        ac.setComponentByName('simple', SimpleCreds(unicode(pw)))
        br.setComponentByName('authentication', ac)

        ## send request
        logger.debug('Binding on {0} (#{1}) as {2}'.format(self.sock.URI, self.sock.ID, user))
        self.sock.sendMessage('bindRequest', br)

        ## receive and handle response
        bindRes = _unpack('bindResponse', self.sock.recvResponse()[0])
        bindResCode = bindRes.getComponentByName('resultCode')
        if bindResCode == ResultCode('success'):
            logger.debug('Bind successful')
            self.sock.bound = True
            return True
        else:
            raise LDAPError('Bind failure, got response {0}'.format(repr(bindResCode)))

    def unbind(self):
        if self.sock.unbound:
            raise ConnectionUnbound()

        self.sock.sendMessage('unbindRequest', UnbindRequest())
        self.sock.close()
        self.sock.unbound = True
        logger.debug('Unbound on {0} (#{1})'.format(self.sock.URI, self.sock.ID))
        try:
            _sockets.pop(self.sock.URI)
        except KeyError:
            pass

    # get a specific object by DN
    def get(self, DN, attrList=None):
        if self.sock.unbound:
            raise ConnectionUnbound()
        results = self.search(DN, Scope.BASE, attrList=attrList, limit=2)
        n = len(results)
        if n == 0:
            raise NoSearchResults()
        elif n > 1:
            raise MultipleSearchResults()
        else:
            return results[0]

    # send a search request
    def _sendSearch(self, baseDN, scope, filterStr=None, attrList=None, searchTimeout=None,
        limit=0, derefAliases=None, attrsOnly=False):
        if self.sock.unbound:
            raise ConnectionUnbound()

        req = SearchRequest()
        if filterStr is None:
            filterStr = LDAP.DEFAULT_FILTER
        if searchTimeout is None:
            searchTimeout = self.defaultSearchTimeout
        if derefAliases is None:
            derefAliases = self.defaultDerefAliases
        req.setComponentByName('baseObject', LDAPDN(baseDN))
        req.setComponentByName('scope', scope)
        req.setComponentByName('derefAliases', derefAliases)
        req.setComponentByName('sizeLimit', NonNegativeInteger(limit))
        req.setComponentByName('timeLimit', NonNegativeInteger(searchTimeout))
        req.setComponentByName('typesOnly', TypesOnly(attrsOnly))
        req.setComponentByName('filter', parseFilter(filterStr))

        attrs = AttributeSelection()
        i = 0
        if attrList is None:
            attrList = [LDAP.ALL_USER_ATTRS]
        if not isinstance(attrList, list):
            attrList = [attrList]
        for desc in attrList:
            attrs.setComponentByPosition(i, LDAPString(desc))
            i += 1
        req.setComponentByName('attributes', attrs)

        mID = self.sock.sendMessage('searchRequest', req)
        logger.debug('Sent search request (ID {0}): baseDN={1}, scope={2}, filterStr={3}'.format(mID, baseDN, scope, filterStr))
        return mID

    def search(self, *args, **kwds):
        mID = self._sendSearch(*args, **kwds)
        return _recvSearchResults(self.sock, mID)

    def searchAsync(self, *args, **kwds):
        mID = self._sendSearch(*args, **kwds)
        return AsyncSearchHandle(self.sock, mID)

    # send a compare request
    def _sendCompare(self, DN, attr, value):
        if self.sock.unbound:
            raise ConnectionUnbound()

        cr = CompareRequest()
        cr.setComponentByName('entry', LDAPDN(unicode(DN)))
        ava = AttributeValueAssertion()
        ava.setComponentByName('attributeDesc', AttributeDescription(unicode(attr)))
        ava.setComponentByName('assertionValue', AssertionValue(unicode(value)))
        cr.setComponentByName('ava', ava)

        mID = self.sock.sendMessage('compareRequest', cr)
        logger.debug('Sent compare request (ID {0}): {1} ({2} = {3})'.format(mID, DN, attr, value))
        return mID

    def compare(self, *args):
        mID = self._sendCompare(*args)
        return _processCompareResults(self.sock.recvResponse(mID))

    def compareAsync(self, *args):
        mID = self._sendCompare(*args)
        return AsyncHandle(self.sock, mID, _processCompareResults)

class AsyncHandle(object):
    def __init__(self, sock, messageID, postProcess=lambda x: x):
        self.messageID = messageID
        self.sock = sock
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
            ret += self.sock.recvResponse(self.messageID)
        logger.debug('Done waiting for messageID={0}'.format(self.messageID))
        return self.postProcess(ret)

    def abandon(self):
        if self.sock.unbound:
            raise ConnectionUnbound()
        logger.debug('Abandoning messageID={0}'.format(self.messageID))
        self.sock.sendMessage('abandonRequest', AbandonRequest(self.messageID))
        self.abandoned = True

class AsyncSearchHandle(AsyncHandle):
    def wait(self):
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.abandoned:
            raise AbandonedAsyncError()
        return _recvSearchResults(self.sock, self.messageID)

class UnexpectedResponseType(LDAPError):
    pass

class UnexpectedSearchResults(LDAPError):
    pass

class NoSearchResults(UnexpectedSearchResults):
    pass

class MultipleSearchResults(UnexpectedSearchResults):
    pass

class InvalidBindState(LDAPError):
    pass

class ConnectionAlreadyBound(InvalidBindState):
    def __init__(self):
        LDAPError.__init__(self, 'The connection has already been bound')

class ConnectionUnbound(InvalidBindState):
    def __init__(self):
        LDAPError.__init__(self, 'The connection has been unbound')

class AbandonedAsyncError(LDAPError):
    pass
