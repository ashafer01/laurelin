__all__ = []

from socket import create_connection
from urlparse import urlparse

from pyasn1.codec.ber.encoder import encode as BEREncode
from pyasn1.codec.ber.decoder import decode as BERDecode
from pyasn1.error import SubstrateUnderrunError

from rfc4511 import LDAPDN, LDAPString, ResultCode, Integer0ToMax as NonNegativeInteger
from rfc4511 import SearchRequest, AttributeSelection, BindRequest, AuthenticationChoice
from rfc4511 import LDAPMessage, MessageID, ProtocolOp, Version, UnbindRequest, CompareRequest
from rfc4511 import Simple as SimpleCreds, TypesOnly, AttributeValueAssertion
from rfc4511 import AttributeDescription, AssertionValue, AbandonRequest
from filter import parse as parseFilter
from base import Scope, DerefAliases

class LDAPError(Exception):
    pass

class UnexpectedSearchResults(LDAPError):
    pass

class NoSearchResults(UnexpectedSearchResults):
    pass

class MultipleSearchResults(UnexpectedSearchResults):
    pass

class UnexpectedDN(UnexpectedSearchResults):
    pass

class UnexpectedResponseType(LDAPError):
    pass

class UnboundConnectionError(LDAPError):
    def __init__(self):
        LDAPError.__init__(self, 'The connection has been unbound')

def LDAPSocket(object):
    RECV_BUFFER = 4096

    def __init__(self, hostURI, connectTimeout=5):
        parsedURI = urlparse(hostURI)
        if parsedURI.scheme == 'ldap':
            ap = parsedURI.netloc.split(':', 1)
            address = ap[0]
            if len(ap) == 1:
                port = 389
            else:
                port = int(ap[1])
        else:
            raise LDAPError('Unsupported scheme "{0}"'.format(parsedURI.scheme))
        self.addr = (address, port)
        self.sock = create_connection(self.addr, connectTimeout)
        self.unbound = False

    def sendMessage(self, op, obj):
        mID = self._messageID
        lm = LDAPMessage()
        lm.setComponentByName('messageID', MessageID(mID))
        po = ProtocolOp()
        po.setComponentByName(op, obj)
        lm.setComponentByName('protocolOp', po)
        self._messageID += 1
        self.sock.sendall(BEREncode(lm))
        return mID

    def recvResponse(self, raw=''):
        ret = []
        try:
            raw += self.sock.recv(RECV_BUFFER)
            while len(raw) > 0:
                response, raw = BERDecode(raw, asn1Spec=LDAPMessage())
                ret.append(response)
            return ret
        except SubstrateUnderrunError:
            ret += self.recvResponse(raw)
            return ret

    def close(self):
        return self.sock.close()

# unpack an object from an LDAPMessage envelope
def _unpack(ops, ldapMessage):
    if not hasattr(ops, '__iter__'):
        ops = [ops]
    po = ldapMessage.getComponentByName('protocolOp')
    for op in ops:
        ret = po.getComponentByName(op)
        if ret is not None:
            return ret
        else:
            raise UnexpectedResponseType()

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
        reuseConnectionFrom=None
        connectTimeout=DEFAULT_CONNECT_TIMEOUT,
        searchTimeout=DEFAULT_SEARCH_TIMEOUT,
        derefAliases=DEFAULT_DEREF_ALIASES,
        ):

        ## setup
        self.defaultSearchTimeout = searchTimeout
        self.defaultDerefAliases = derefAliases
        self._messageID = 1

        ## connect
        if reuseConnectionFrom is not None:
            self.sock = reuseConnectionFrom.sock
        elif reuseConnection:
            if self.sockAddr not in _sockets:
                _sockets[hostURI] = LDAPSocket(hostURI, connectTimeout)
            self.sock  = _sockets[hostURI]
        else:
            self.sock = LDAPSocket(hostURI, connectTimeout)

    def simpleBind(self, user, pw):
        if self.sock.unbound:
            raise UnboundConnectionError()

        ## prepare bind request
        br = BindRequest()
        br.setComponentByName('version', Version(3))
        br.setComponentByName('name', LDAPDN(unicode(user)))
        ac = AuthenticationChoice()
        ac.setComponentByName('simple', SimpleCreds(unicode(pw)))
        br.setComponentByName('authentication', ac)

        ## send request
        self.sock.sendMessage('bindRequest', br)

        ## receive and handle response
        bindRes = _unpack('bindResponse', self.sock.recvResponse()[0])
        bindResCode = bindRes.getComponentByName('resultCode')
        if bindResCode == ResultCode('success'):
            return True
        else:
            raise LDAPError('Bind failure, got response {0}'.format(repr(bindResCode)))

    def unbind(self):
        if self.sock.unbound:
            raise UnboundConnectionError()

        self.sock.sendMessage('unbindRequest', UnbindRequest())
        self.sock.close()
        self.sock.unbound = True
        try:
            _sockets.pop(self.sockAddr)
        except KeyError:
            pass

    # get a specific object by DN
    def get(self, DN, attrList=None):
        if self.sock.unbound:
            raise UnboundConnectionError()
        results = self.search(DN, Scope.BASE, attrList=attrList, limit=2)
        n = len(results)
        if n == 0:
            raise NoSearchResults()
        elif n > 1:
            raise MultipleSearchResults()
        else:
            return results[0]

    # do a search and run a callback on each result object
    # useful for large result sets which do not need to be stored in memory
    # if callback returns non-None, this will be stored in a list and returned
    def searchCallback(self, callback, baseDN, scope, filterStr=None, attrList=None, searchTimeout=None,
        limit=0, derefAliases=None, attrsOnly=False):
        if self.sock.unbound:
            raise UnboundConnectionError()

        ## prepare search request
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

        ## send request
        self.sock.sendMessage('searchRequest', req)

        ## receive and process response
        searchResults = []
        for res in self.sock.recvResponse():
            po = res.getComponentByName('protocolOp')
            entry = po.getComponentByName('searchResEntry')
            if entry is not None:
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
                processed = callback(LDAPObject(DN, attrs))
                if processed is not None:
                    searchResults.append(processed)
            elif po.getComponentByName('searchResDone') is not None:
                break
            else:
                raise UnexpectedResponseType()
        return searchResults

    # do a search and read all results into memory
    def search(self, *args, **kwds):
        if self.sock.unbound:
            raise UnboundConnectionError()
        def storeRes(obj):
            return obj
        return self.searchCallback(storeRes, *args, **kwds)

    # return True if the object identified by DN has the given attr=value
    def compare(self, DN, attr, value):
        if self.sock.unbound:
            raise UnboundConnectionError()

        cr = CompareRequest()
        cr.setComponentByName('entry', LDAPDN(unicode(DN)))
        ava = AttributeValueAssertion()
        ava.setComponentByName('attributeDesc', AttributeDescription(unicode(attr)))
        ava.setComponentByName('assertionValue', AssertionValue(unicode(value)))
        cr.setComponentByName('ava', ava)

        self.sock.sendMessage('compareRequest', cr)
        res = _unpack('compareResponse', self.sock.recvResponse()[0]).getComponentByName('resultCode')
        if res == ResultCode('compareTrue'):
            return True
        elif res == ResultCode('compareFalse'):
            return False
        else:
            raise LDAPError('Got compare result {0}'.format(repr(res)))

    def abandon(self, messageID):
        if self.sock.unbound:
            raise UnboundConnectionError()

        self.sock.sendMessage('abandonRequest', AbandonRequest(messageID))
