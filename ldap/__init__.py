__all__ = []

from socket import create_connection
from urlparse import urlparse

from pyasn1.codec.ber.encoder import encode as BEREncode
from pyasn1.codec.ber.decoder import decode as BERDecode
from pyasn1.error import SubstrateUnderrunError

from rfc4511 import LDAPDN, LDAPString, ResultCode, Integer0ToMax as NonNegativeInteger
from rfc4511 import SearchRequest, AttributeSelection, BindRequest, AuthenticationChoice
from rfc4511 import LDAPMessage, MessageID, ProtocolOp, Version as VersionInteger
from rfc4511 import Simple as SimpleCreds, TypesOnly
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

class LDAPObject(dict):
    def __init__(self, dn, attrs):
        self.dn = dn
        dict.__init__(self, attrs)

    def __repr__(self):
        return "LDAPObject(dn='{0}', attrs={1})".format(self.dn, dict.__repr__(self))

RECV_BUFFER = 4096

_sockets = {}

class LDAP(object):
    ## global defaults
    DEFAULT_FILTER = '(objectClass=*)'
    DEFAULT_DEREF_ALIASES = DerefAliases.ALWAYS
    DEFAULT_SEARCH_TIMEOUT = 0

    ## other constants
    NO_ATTRS = '1.1'
    ALL_USER_ATTRS = '*'

    def __init__(self, hostURI, searchTimeout=DEFAULT_SEARCH_TIMEOUT,
        derefAliases=DEFAULT_DEREF_ALIASES, connectTimeout=5, reuseConnection=True):

        ## setup
        self.defaultSearchTimeout = searchTimeout
        self.defaultDerefAliases = derefAliases

        self._messageID = 1

        ## handle URI
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
        addr = (address, port)

        ## connect
        if reuseConnection:
            if addr not in _sockets:
                _sockets[addr] = create_connection(addr, connectTimeout)
            self.sock = _sockets[addr]
        else:
            self.sock = create_connection(addr, connectTimeout)

    def _sendMessage(self, op, obj):
        lm = LDAPMessage()
        lm.setComponentByName('messageID', self._messageID)
        po = ProtocolOp()
        po.setComponentByName(op, obj)
        lm.setComponentByName('protocolOp', po)
        self._messageID += 1
        raw = BEREncode(lm)
        self.sock.sendall(raw)

    def _recvResponse(self, raw=''):
        ret = []
        try:
            raw += self.sock.recv(RECV_BUFFER)
            while len(raw) > 0:
                response, raw = BERDecode(raw, asn1Spec=LDAPMessage())
                ret.append(response)
            return ret
        except SubstrateUnderrunError:
            ret += self._recvResponse(raw)
            return ret

    def simpleBind(self, user, pw):
        ## prepare bind request
        br = BindRequest()
        br.setComponentByName('version', VersionInteger(3))
        br.setComponentByName('name', LDAPDN(unicode(user)))
        ac = AuthenticationChoice()
        ac.setComponentByName('simple', SimpleCreds(unicode(pw)))
        br.setComponentByName('authentication', ac)

        ## send request
        self._sendMessage('bindRequest', br)

        ## receive and handle response
        po = self._recvResponse()[0].getComponentByName('protocolOp')
        bindRes = po.getComponentByName('bindResponse')
        if bindRes is not None:
            bindResCode = bindRes.getComponentByName('resultCode')
            if bindResCode == ResultCode('success'):
                return True
            else:
                raise LDAPError('Bind failure, got response {0}'.format(repr(bindResCode)))
        else:
            raise UnexpectedResponseType()

    # get a specific object by DN
    def get(self, DN, attrList=None):
        results = self.search(DN, Scope.BASE, attrList=attrList, limit=2)
        n = len(results)
        if n == 0:
            raise NoSearchResults()
        elif n > 1:
            raise MultipleSearchResults()
        else:
            return results[0]

    # do a search and return a list of objects
    def search(self, baseDN, scope, filterStr=None, attrList=None, searchTimeout=None,
        limit=0, derefAliases=None, attrsOnly=False):

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
        self._sendMessage('searchRequest', req)

        ## receive and process response
        searchResults = []
        for res in self._recvResponse():
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
                searchResults.append(LDAPObject(DN, attrs))
            elif po.getComponentByName('searchResDone') is not None:
                break
            else:
                raise UnexpectedResponseType()
        return searchResults
