__all__ = []

from socket import create_connection
from urlparse import urlparse
from pyasn1.codec.ber import encoder as BEREncoder

from rfc4511 import LDAPDN, Scope as _Scope, AttributeSelection, DerefAliases as _DerefAliases
from rfc4511 import SearchRequest, LDAPString, NonNegativeInteger, univ
from rfc4511 import BindRequest, AuthenticationChoice, LDAPMessage, MessageID, ProtocolOp
from filter import parse as parseFilter

class Scope:
    BASE = _Scope('baseObject')
    ONELEVEL = _Scope('singleLevel')
    SUBTREE = _Scope('wholeSubtree')

class DerefAliases:
    NEVER = _DerefAliases('neverDerefAliases')
    SEARCH = _DerefAliases('derefInSearching')
    BASE = _DerefAliases('derefFindingBaseObj')
    ALWAYS = _DerefAliases('derefAlways')

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

class LDAPObject(dict):
    def __init__(self, dn, attrs):
        self.dn = dn
        dict.__init__(self, attrs)

    def __getattr__(self, key):
        return self[key]

class LDAP(object):
    ## global defaults
    DEFAULT_FILTER = '(objectClass=*)'
    DEFAULT_DEREF_ALIASES = DerefAliases.ALWAYS
    DEFAULT_SEARCH_TIMEOUT = 0

    ## other constants
    NO_ATTRS = '1.1'
    ALL_USER_ATTRS = '*'

    def __init__(self, hostURI, searchTimeout=LDAP.DEFAULT_SEARCH_TIMEOUT,
        derefAliases=LDAP.DEFAULT_DEREF_ALIASES, connectTimeout=5):

        self.defaultSearchTimeout = searchTimeout
        self.defaultDerefAliases = derefAliases

        self._messageID = 1

        ## connect
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
        self.sock = create_connection((address, port), connectTimeout)

    def _sendMessage(self, op, obj):
        lm = LDAPMessage()
        lm.setComponentByName('messageID', self._messageID)
        po = ProtocolOp()
        po.setComponentByName(op, obj)
        lm.setComponentByName('protocolOp', po)
        self._messageID += 1
        self.sock.sendall(BEREncoder.encode(lm))

    def simpleBind(self, user, pw):
        ## prepare bind request
        br = BindRequest()
        br.setComponentByName('version', univ.Integer(3))
        br.setComponentByName('name', LDAPDN(user))
        ac = AuthenticationChoice()
        ac.setComponentByName('simple', univ.OctetString(pw))
        br.setComponentByName('authentication', ac)

        ## send request
        self._sendMessage('bindRequest', br)

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
        req.setComponentByName('typesOnly', univ.Boolean(attrsOnly))
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

        ## receive response

        ## process response
