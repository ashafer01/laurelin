__all__ = []

from urlparse import urlparse
import logging
logger = logging.getLogger('pyldap')
stderrHandler = logging.StreamHandler()
stderrHandler.setFormatter(logging.Formatter('[%(asctime)s] %(name)s %(levelname)s : %(message)s'))
logger.addHandler(stderrHandler)
logger.setLevel(logging.DEBUG)

from rfc4511 import LDAPDN, LDAPString, ResultCode, Integer0ToMax as NonNegativeInteger
from rfc4511 import SearchRequest, AttributeSelection, BindRequest, AuthenticationChoice
from rfc4511 import LDAPMessage, MessageID, ProtocolOp, Version, UnbindRequest, CompareRequest
from rfc4511 import Simple as SimpleCreds, TypesOnly, AttributeValueAssertion, AddRequest
from rfc4511 import AttributeDescription, AssertionValue, AbandonRequest, AttributeList, Attribute
from rfc4511 import AttributeValue, Vals, DelRequest
from filter import parse as parseFilter
from base import Scope, DerefAliases, LDAPError
from net import LDAPSocket, LDAPConnectionError

# unpack an object from an LDAPMessage envelope
def _unpack(op, ldapMessage):
    po = ldapMessage.getComponentByName('protocolOp')
    ret = po.getComponentByName(op)
    if ret is not None:
        return ret
    else:
        raise UnexpectedResponseType()

# recv all objects from given LDAPSocket until we get a SearchResultDone; return a list of
# LDAPObject (and SearchReferenceHandle if any result references are returned from the server)
# TODO this may block indefinitely if abandoned
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
                try:
                    done = _unpack('searchResDone', msg)
                    result = done.getComponentByName('resultCode')
                    if result == ResultCode('success'):
                        logger.debug('Search completed successfully')
                        return ret
                    else:
                        raise LDAPError('Search returned {0}'.format(repr(result)))
                except UnexpectedResponseType:
                    resref = _unpack('searchResRef', msg)
                    URIs = []
                    for i in range(0, len(resref)):
                        URIs.append(unicode(resref.getComponentByPosition(i)))
                    logger.debug('Got search reference to: {0}'.format(' | '.join(URIs)))
                    ret.append(SearchReferenceHandle(URIs))

# convert compare result codes to boolean
def _processCompareResults(ldapMessages):
    mID = ldapMessages[0].getComponentByName('messageID')
    res = _unpack('compareResponse', ldapMessages[0]).getComponentByName('resultCode')
    if res == ResultCode('compareTrue'):
        logger.debug('Compared True (ID {0})'.format(mID))
        return True
    elif res == ResultCode('compareFalse'):
        logger.debug('Compared False (ID {0})'.format(mID))
        return False
    else:
        raise LDAPError('Got compare result {0} (ID {1})'.format(repr(res), mID))

# check for success result
def _checkResultCode(ldapMessage, operation):
    mID = ldapMessage.getComponentByName('messageID')
    res = _unpack(operation, ldapMessage).getComponentByName('resultCode')
    if res == ResultCode('success'):
        logger.debug('LDAP operation (ID {0}) was successful'.format(mID))
        return True
    else:
        raise LDAPError('Got {0} for {1} (ID {2})'.format(repr(res), operation, mID))

# perform a search based on an RFC4516 URI
def searchByURI(uri):
    parsedURI = urlparse(uri)
    hostURI = '{0}://{1}'.format(parsedURI.scheme, parsedURL.netloc)
    ldap = LDAP(hostURI, reuseConnection=False)
    DN = parsedURI.path
    params = parsedURI.query.split('?')
    nparams = len(params)
    if (nparams > 0) and (len(params[0]) > 0):
        attrList = params[0].split(',')
    else:
        attrList = [LDAP.ALL_USER_ATTRS]
    if (nparams > 1) and (len(params[1]) > 0):
        scope = Scope.string(params[1])
    else:
        scope = Scope.BASE
    if (nparams > 2) and (len(params[2]) > 0):
        filter = params[2]
    else:
        filter = LDAP.DEFAULT_FILTER
    if (nparams > 3) and (len(params[3]) > 0):
        raise LDAPError('Extensions for searchByURL not yet implemented')
    return ldap.search(DN, scope, filterStr=filter, attrList=attrList)

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

class LDAP_rw(LDAP):
    # send a request to add a new object
    # pass either (DN, attrs) or an LDAPObject
    def _sendAdd(self, *args):
        if self.sock.unbound:
            raise ConnectionUnbound()

        if (len(args) == 1):
            if not isinstance(args[0], LDAPObject):
                raise TypeError('Single argument must be LDAPObject')
            DN = args[0].dn
            attrs = args[0]
        elif (len(args) == 2):
            if not isinstance(args[0], basestring):
                raise TypeError('DN must be string type')
            if not isinstance(args[1], dict):
                raise TypeError('attrs must be dict')
            DN = args[0]
            attrs = args[1]
        else:
            raise TypeError('expected 1 or 2 arguments, got {0}'.format(len(args)))

        ar = AddRequest()
        ar.setComponentByName('entry', LDAPDN(DN))
        al = AttributeList()
        i = 0
        for attrType, attrVals in attrs.iteritems():
            attr = Attribute()
            attr.setComponentByName('type', AttributeDescription(attrType))
            vals = Vals()
            j = 0
            for val in attrVals:
                vals.setComponentByPosition(j, AttributeValue(val))
                j += 1
            attr.setComponentByName('vals', vals)
            al.setComponentByPosition(i, attr)
            i += 1
        ar.setComponentByName('attributes', al)
        mID = self.sock.sendMessage('addRequest', ar)
        logger.debug('Sent add request (ID {0}) for DN {1}'.format(mID, DN))
        return mID

    def add(self, *args):
        mID = self._sendAdd(*args)
        return _checkResultCode(self.sock.recvResponse(mID)[0], 'addResponse')

    def addAsync(self, *args):
        mID = self._sendAdd(*args)
        return AsyncResultHandle(self.sock, mID, 'addResponse')

    # delete an object
    def _sendDelete(self, DN):
        if self.sock.unbound:
            raise ConnectionUnbound()
        mID = self.sock.sendMessage('delRequest', DelRequest(DN))
        logger.debug('Sent delete request (ID {0}) for DN {1}'.format(mID, DN)
        return mID

    def delete(self, DN):
        mID = self._sendDelete(DN)
        return _checkResultCode(self.sock.recvResponse(mID)[0], 'delResponse')

    def deleteAsync(self, DN):
        mID = self._sendDelete(DN)
        return AsyncResultHandle(self.sock, mID, 'delResponse')

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

class AsyncResultHandle(AsyncHandle):
    def __init__(self, sock, messageID, operation):
        AsyncHandle.__init__(self, sock, messageID)
        self.operation = operation

    def wait(self):
        msg = AsyncHandle.wait(self)[0]
        return _checkResultCode(msg, self.operation)

class SearchReferenceHandle(object):
    def __init__(self, URIs):
        self.URIs = URIs

    def get(self):
        # If multiple URIs are present, the client assumes that any supported URI
        # may be used to progress the operation. ~ RFC4511 sec 4.5.3 p28
        for uri in self.URIs:
            try:
                return searchByURI(uri)
            except LDAPConnectionError as e:
                logger.warning('Error connecting to URI {0} ({1})'.format(uri, e.message))
        logger.error('No more URIs to try')
        raise LDAPError('Could not complete reference URI search with any supplied URIs')

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
