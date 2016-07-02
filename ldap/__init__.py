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
from rfc4511 import AttributeValue, Vals, DelRequest, ModifyDNRequest, RelativeLDAPDN, NewSuperior
from rfc4511 import ModifyRequest, Changes, Change, Operation, PartialAttribute
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

# check for success result
def _checkResultCode(ldapMessage, operation):
    mID = ldapMessage.getComponentByName('messageID')
    res = _unpack(operation, ldapMessage).getComponentByName('resultCode')
    if res == ResultCode('success'):
        logger.debug('LDAP operation (ID {0}) was successful'.format(mID))
        return True
    else:
        raise LDAPError('Got {0} for {1} (ID {2})'.format(repr(res), operation, mID))

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
                    _checkResultCode(msg, 'searchResDone')
                    return ret
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
    ret = ldap.search(DN, scope, filterStr=filter, attrList=attrList)
    ldap.unbind()
    return ret

# for storing reusable sockets
_sockets = {}

class LDAPObject(dict):
    def __init__(self, dn, attrs={}, ldapObj=None):
        self.dn = dn
        self.ldapObj = ldapObj
        dict.__init__(self, attrs)

    def __repr__(self):
        return "LDAPObject(dn='{0}', attrs={1})".format(self.dn, dict.__repr__(self))

    def formatLDIF(self):
        lines = ['dn: {0}'.format(self.dn)]
        for attr, vals in self.iteritems():
            for val in vals:
                lines.append('{0}: {1}'.format(attr, val))
        lines.append('')
        return '\n'.join(lines)

    def refresh(self, attrs=None):
        if isinstance(self.ldapObj, LDAP):
            self.update(self.ldapObj.get(self.dn, attrs))
            return True
        else:
            raise RuntimeError('No LDAP object')

    def addAttrs(self, attrsDict):
        if isinstance(self.ldapObj, LDAP_rw):
            self.ldapObj.addAttrs(self.dn, attrsDict)
            for attr, vals in attrsDict.iteritems():
                if attr not in self:
                    self[attr] = vals
                else:
                    for val in vals:
                        if val not in self[attr]:
                            self[attr].append(val)
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def replaceAttrs(self, attrsDict):
        if isinstance(self.ldapObj, LDAP_rw):
            self.ldapObj.replaceAttrs(self.dn, attrsDict)
            self.update(attrsDict)
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def deleteAttrValues(self, attrsDict):
        if isinstance(self.ldapObj, LDAP_rw):
            self.ldapObj.deleteAttrValues(self.dn, attrsDict)
            for attr, vals in attrsDict.iteritems():
                if attr in self:
                    if len(vals) == 0:
                        self.pop(attr)
                    else:
                        for val in vals:
                            try:
                                self[attr].remove(val)
                            except:
                                pass
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def deleteAttrs(self, attrs):
        if isinstance(self.ldapObj, LDAP_rw):
            if not isinstance(attrs, list):
                attrs = [attrs]
            self.ldapObj.deleteAttrs(self.dn, attrs)
            for attr in attrs:
                try:
                    self.pop(attr)
                except:
                    pass
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def delete(self):
        if isinstance(self.ldapObj, LDAP_rw):
            self.ldapObj.delete(self.dn)
            self.clear()
            self.dn = None
            self.ldapObj = None
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def modDN(self, newRDN, cleanAttr=True, newParent=None):
        if isinstance(self.ldapObj, LDAP_rw):
            curRDN, curParent = self.dn.split(',', 1)
            self.ldapObj.modDN(self.dn, newRDN, cleanAttr, newParent)
            if cleanAttr:
                rdnAttr, rdnVal = curRDN.split('=', 1)
                try:
                    self[rdnAttr].remove(rdnVal)
                except:
                    pass
            rdnAttr, rdnVal = newRDN.split('=', 1)
            if rdnAttr not in self:
                self[rdnAttr] = [rdnVal]
            elif rdnVal not in self[rdnAttr]:
                self[rdnAttr].append(rdnVal)
            if newParent is None:
                parent = curParent
            else:
                parent = newParent
            self.dn = '{0},{1}'.format(newRDN, parent)
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def rename(self, newRDN, cleanAttr=True):
        return self.modDN(newRDN, cleanAttr)

    def move(self, newDN, cleanAttr=True):
        newRDN, newParent = newDN.split(',', 1)
        return self.modDN(newRDN, cleanAttr, newParent)

class LDAP(object):
    ## global defaults
    DEFAULT_FILTER = '(objectClass=*)'
    DEFAULT_DEREF_ALIASES = DerefAliases.ALWAYS
    DEFAULT_SEARCH_TIMEOUT = 0
    DEFAULT_CONNECT_TIMEOUT = 5

    ## other constants
    NO_ATTRS = '1.1'
    ALL_USER_ATTRS = '*'

    def __init__(self, connectTo,
        reuseConnection=True,
        connectTimeout=DEFAULT_CONNECT_TIMEOUT,
        searchTimeout=DEFAULT_SEARCH_TIMEOUT,
        derefAliases=DEFAULT_DEREF_ALIASES,
        ):

        ## setup
        self.defaultSearchTimeout = searchTimeout
        self.defaultDerefAliases = derefAliases

        ## connect
        if isinstance(connectTo, basestring):
            self.hostURI = connectTo
            if reuseConnection:
                if self.hostURI not in _sockets:
                    _sockets[self.hostURI] = LDAPSocket(self.hostURI, connectTimeout)
                self.sock  = _sockets[self.hostURI]
            else:
                self.sock = LDAPSocket(self.hostURI, connectTimeout)
        elif isinstance(connectTo, LDAP):
            self.hostURI = connectTo.hostURI
            self.sock = connectTo.sock
        else:
            raise TypeError('Must supply URI string or LDAP instance for connectTo')
        logger.debug('Connected to {0} (#{1})'.format(self.hostURI, self.sock.ID))

    def simpleBind(self, user, pw):
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.sock.bound:
            raise ConnectionAlreadyBound()

        br = BindRequest()
        br.setComponentByName('version', Version(3))
        br.setComponentByName('name', LDAPDN(unicode(user)))
        ac = AuthenticationChoice()
        ac.setComponentByName('simple', SimpleCreds(unicode(pw)))
        br.setComponentByName('authentication', ac)

        mID = self.sock.sendMessage('bindRequest', br)
        logger.debug('Sent bind request (ID {0}) on connection #{1} for {2}'.format(mID, self.sock.ID, user))
        return _checkResultCode(self.sock.recvResponse()[0], 'bindResponse')

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
        logger.debug('Sent delete request (ID {0}) for DN {1}'.format(mID, DN))
        return mID

    def delete(self, DN):
        mID = self._sendDelete(DN)
        return _checkResultCode(self.sock.recvResponse(mID)[0], 'delResponse')

    def deleteAsync(self, DN):
        mID = self._sendDelete(DN)
        return AsyncResultHandle(self.sock, mID, 'delResponse')

    # exposes all options of the protocol-level ModifyDNRequest
    def modDN(self, DN, newRDN, cleanAttr=True, newSuperior=None):
        if self.sock.unbound:
            raise ConnectionUnbound()
        mdr = ModifyDNRequest()
        mdr.setComponentByName('entry', LDAPDN(DN))
        mdr.setComponentByName('newrdn', RelativeLDAPDN(newRDN))
        mdr.setComponentByName('deleteoldrdn', cleanAttr)
        if newSuperior is not None:
            mdr.setComponentByName('newSuperior', NewSuperior(newSuperior))
        mID = self.sock.sendMessage('modDNRequest', mdr)
        return _checkResultCode(self.sock.recvResponse(mID)[0], 'modDNResponse')

    # edit the RDN of an object
    def rename(self, DN, newRDN, cleanAttr=True):
        return self.modDN(DN, newRDN, cleanAttr)

    # move object, possibly changing RDN as well
    def move(self, DN, newDN, cleanAttr=True):
        rdn, superior = newDN.split(',', 1)
        return self.modDN(DN, rdn, cleanAttr, superior)

    # change attributes on an object
    def _sendModify(self, DN, modlist):
        if self.sock.unbound:
            raise ConnectionUnbound()
        mr = ModifyRequest()
        mr.setComponentByName('object', LDAPDN(DN))
        cl = Changes()
        i = 0
        logger.debug('Modifying DN {0}'.format(DN))
        for mod in modlist:
            logger.debug('> {0}'.format(str(mod)))
            cl.setComponentByPosition(i, mod.toChange())
            i += 1
        mr.setComponentByName('changes', cl)
        mID = self.sock.sendMessage('modifyRequest', mr)
        logger.debug('Sent modify request (ID {0}) for DN {1}'.format(mID, DN))
        return mID

    def modify(self, DN, modlist):
        mID = self._sendModify(DN, modlist)
        return _checkResultCode(self.sock.recvResponse(mID)[0], 'modifyResponse')

    def modifyAsync(self, DN, modlist):
        mID = self._sendModify(DN, modlist)
        return AsyncResultHandle(self.sock, mID, 'modifyResponse')

    # add new attributes and values
    def addAttrs(self, DN, attrsDict):
        return self.modify(DN, Modlist(Mod.ADD, attrsDict))

    def addAttrsAsync(self, DN, attrsDict):
        return self.modifyAsync(DN, Modlist(Mod.ADD, attrsDict))

    # delete specific attribute values
    # specifying a 0-length entry will delete all values
    def deleteAttrValues(self, DN, attrsDict):
        return self.modify(DN, Modlist(Mod.DELETE, attrsDict))

    def deleteAttrValuesAsync(self, DN, attrsDict):
        return self.modifyAsync(DN, Modlist(Mod.DELETE, attrsDict))

    # delete all values for one or more attributes
    def deleteAttrs(self, DN, attrs):
        if not isinstance(attrs, list):
            attrs = [attrs]
        return self.deleteAttrValues(DN, dict.fromkeys(attrs, []))

    def deleteAttrsAsync(self, DN, attrs):
        if not isinstance(attrs, list):
            attrs = [attrs]
        return self.deleteAttrValuesAsync(DN, dict.fromkeys(attrs, []))

    # replace all values on given attributes with the passed values
    # attributes will be created if they do not exist
    def replaceAttrs(self, DN, attrsDict):
        return self.modify(DN, Modlist(Mod.REPLACE, attrsDict))

    def replaceAttrsAsync(self, DN, attrsDict):
        return self.modifyAsync(DN, Modlist(Mod.REPLACE, attrsDict))

## async handles

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

## other classes

# returned when the server returns a SearchResultReference
class SearchReferenceHandle(object):
    def __init__(self, URIs):
        self.URIs = URIs

    def fetch(self):
        # If multiple URIs are present, the client assumes that any supported URI
        # may be used to progress the operation. ~ RFC4511 sec 4.5.3 p28
        for uri in self.URIs:
            try:
                return searchByURI(uri)
            except LDAPConnectionError as e:
                logger.warning('Error connecting to URI {0} ({1})'.format(uri, e.message))
        raise LDAPError('Could not complete reference URI search with any supplied URIs')

# describes a single modify operation
class Mod(object):
    ADD = Operation('add')
    REPLACE = Operation('replace')
    DELETE = Operation('delete')

    @staticmethod
    def opToString(op):
        if op == Mod.ADD:
            return 'ADD'
        elif op == Mod.REPLACE:
            return 'REPLACE'
        elif op == Mod.DELETE:
            return 'DELETE'
        else:
            raise ValueError()

    @staticmethod
    def stringToOp(opStr):
        opStr = opStr.lower()
        return Operation(opStr)

    def __init__(self, op, attr, vals):
        if (op != Mod.ADD) and (op != Mod.REPLACE) and (op != Mod.DELETE):
            raise ValueError()
        if not isinstance(vals, list):
            raise TypeError()
        self.op = op
        self.attr = attr
        self.vals = vals

    def __str__(self):
        if len(self.vals) == 0:
            vals = '<all values>'
        else:
            vals = str(self.vals)
        return 'Mod({0}, {1}, {2})'.format(Mod.opToString(self.op), self.attr, vals)

    def __repr__(self):
        return 'Mod(Mod.{0}, {1}, {2})'.format(Mod.opToString(self.op), repr(self.attr), repr(self.vals))

    # convert to protocol object
    def toChange(self):
        c = Change()
        c.setComponentByName('operation', self.op)
        pa = PartialAttribute()
        pa.setComponentByName('type', AttributeDescription(self.attr))
        vals = Vals()
        i = 0
        for v in self.vals:
            vals.setComponentByPosition(i, AttributeValue(v))
            i += 1
        pa.setComponentByName('vals', vals)
        c.setComponentByName('modification', pa)
        return c

# generate a modlist from a dictionary
def Modlist(op, attrsDict):
    if not isinstance(attrsDict, dict):
        raise TypeError()
    modlist = []
    for attr, vals in attrsDict.iteritems():
        modlist.append(Mod(op, attr, vals))
    return modlist

## Exceptions

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
