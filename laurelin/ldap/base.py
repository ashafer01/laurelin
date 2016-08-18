import logging
from urlparse import urlparse

from rfc4511 import (
    LDAPDN,
    LDAPString,
    Integer0ToMax as NonNegativeInteger,
    ResultCode,
    BindRequest,
    UnbindRequest,
    SearchRequest,
    CompareRequest,
    AbandonRequest,
    AddRequest,
    ModifyRequest,
    DelRequest,
    ModifyDNRequest,
    Version,
    AuthenticationChoice,
    Simple as SimpleCreds,
    AttributeSelection,
    AttributeDescription,
    TypesOnly,
    AttributeValueAssertion,
    AssertionValue,
    AttributeList,
    Attribute,
    AttributeValue,
    PartialAttribute,
    Vals,
    RelativeLDAPDN,
    NewSuperior,
    Changes,
    Change,
    Scope as _Scope,
    DerefAliases as _DerefAliases,
)
from filter import parse as parseFilter
from net import LDAPSocket, LDAPConnectionError
from errors import *
from modify import Mod, Modlist, AddModlist, DeleteModlist

logger = logging.getLogger('laurelin.ldap')
stderrHandler = logging.StreamHandler()
stderrHandler.setFormatter(logging.Formatter('[%(asctime)s] %(name)s %(levelname)s : %(message)s'))
logger.addHandler(stderrHandler)
logger.setLevel(logging.DEBUG)

class Scope:
    BASE = _Scope('baseObject')
    ONELEVEL = _Scope('singleLevel')
    SUBTREE = _Scope('wholeSubtree')

    # translate RFC4516 URL scope strings to constant
    @staticmethod
    def string(str):
        str = str.lower()
        if str == 'base':
            return Scope.BASE
        elif str == 'one':
            return Scope.ONELEVEL
        elif str == 'sub':
            return Scope.SUBTREE
        else:
            raise ValueError()

class DerefAliases:
    NEVER = _DerefAliases('neverDerefAliases')
    SEARCH = _DerefAliases('derefInSearching')
    BASE = _DerefAliases('derefFindingBaseObj')
    ALWAYS = _DerefAliases('derefAlways')

class Extensible(object):
    @classmethod
    def EXTEND(cls, methods):
        for method in methods:
            if isinstance(method, tuple):
                name, method = method
            else:
                name = method.__name__
            if not hasattr(cls, name):
                setattr(cls, name, method)
            else:
                raise LDAPExtensionError('Cannot add extension attribute {0} - class {1} already '
                    'has an attribute by that name'.format(name, cls.__name__))

# for storing reusable sockets
_sockets = {}

class LDAP(Extensible):
    # global defaults
    DEFAULT_FILTER = '(objectClass=*)'
    DEFAULT_DEREF_ALIASES = DerefAliases.ALWAYS
    DEFAULT_SEARCH_TIMEOUT = 0
    DEFAULT_CONNECT_TIMEOUT = 5
    DEFAULT_STRICT_MODIFY = False
    DEFAULT_REUSE_CONNECTION = True
    DEFAULT_SSL_CAFILE = None
    DEFAULT_SSL_CAPATH = None
    DEFAULT_SSL_CADATA = None

    # other constants
    NO_ATTRS = '1.1'
    ALL_USER_ATTRS = '*'

    def __init__(self, connectTo,
        reuseConnection=DEFAULT_REUSE_CONNECTION,
        baseDC=None,
        connectTimeout=DEFAULT_CONNECT_TIMEOUT,
        searchTimeout=DEFAULT_SEARCH_TIMEOUT,
        derefAliases=DEFAULT_DEREF_ALIASES,
        strictModify=DEFAULT_STRICT_MODIFY,
        sslCAFile=DEFAULT_SSL_CAFILE,
        sslCAPath=DEFAULT_SSL_CAPATH,
        sslCAData=DEFAULT_SSL_CADATA,
        ):

        # setup
        self.defaultSearchTimeout = searchTimeout
        self.defaultDerefAliases = derefAliases
        self.strictModify = strictModify

        self._taggedObjects = {}

        # connect
        if isinstance(connectTo, basestring):
            self.hostURI = connectTo
            if reuseConnection:
                if self.hostURI not in _sockets:
                    _sockets[self.hostURI] = LDAPSocket(self.hostURI, connectTimeout, sslCAFile,
                        sslCAPath, sslCAData)
                self.sock = _sockets[self.hostURI]
            else:
                self.sock = LDAPSocket(self.hostURI, connectTimeout, sslCAFile, sslCAPath,
                    sslCAData)
            logger.debug('Connected to {0} (#{1})'.format(self.hostURI, self.sock.ID))
            if baseDC is not None:
                for dcpart in baseDC.split(','):
                    if not dcpart.startswith('dc='):
                        raise ValueError('Invalid base domain component')
                self.baseDC = baseDC
            else:
                logger.debug('Querying server to find baseDC')
                o = self.get('', ['namingContexts'])
                self.baseDC = None
                for nc in o.get('namingContexts', []):
                    if nc.startswith('dc='):
                        self.baseDC = nc
                        break
                if self.baseDC is None:
                    raise RuntimeError('No baseDC supplied and none found from server')
        elif isinstance(connectTo, LDAP):
            self.hostURI = connectTo.hostURI
            self.sock = connectTo.sock
            self.baseDC = connectTo.baseDC
            logger.debug('Connected to {0} (#{1}) from existing object'.format(
                self.hostURI, self.sock.ID))
        else:
            raise TypeError('Must supply URI string or LDAP instance for connectTo')

        logger.debug('Creating base object for {0}'.format(self.baseDC))
        self.base = self.obj(self.baseDC, relativeSearchScope=Scope.SUBTREE)

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
        logger.debug('Sent bind request (ID {0}) on connection #{1} for {2}'.format(mID,
            self.sock.ID, user))
        ret = _checkSuccessResult(self.sock.recvResponse()[0], 'bindResponse')
        self.sock.bound = ret
        return ret

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

    close = unbind

    # get a tagged object
    def tag(self, tag):
        try:
            return self._taggedObjects[tag]
        except KeyError:
            raise TagError('tag {0} does not exist'.format(tag))

    # create an LDAPObject without querying the server
    def obj(self, DN, attrs={}, tag=None, *args, **kwds):
        obj = LDAPObject(DN, attrs=attrs, ldapConn=self, *args, **kwds)
        if tag is not None:
            if tag in self._taggedObjects:
                return TagError('tag {0} already exists'.format(tag))
            else:
                self._taggedObjects[tag] = obj
        return obj

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

    # simply check if a DN exists
    def exists(self, DN):
        if self.sock.unbound:
            raise ConnectionUnbound()
        try:
            self.get(DN, [])
            return True
        except NoSearchResults:
            return False
        except MultipleSearchResults:
            return True

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
        logger.debug('Sent search request (ID {0}): baseDN={1}, scope={2}, filterStr={3}, '
            ' attrs={4}'.format(mID, baseDN, scope, filterStr, repr(attrList)))
        return mID

    # recv all objects from given LDAPSocket until we get a SearchResultDone; return a list of
    # LDAPObject (and SearchReferenceHandle if any result references are returned from the server)
    def _recvSearchResults(self, messageID):
        ret = []
        logger.debug('Receiving all search results for messageID={0}'.format(messageID))
        while True:
            if messageID in self.sock.abandonedMIDs:
                logger.debug('ID={0} abandoned while receiving search results'.format(messageID))
                return ret
            for msg in self.sock.recvResponse(messageID):
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
                    ret.append(LDAPObject(DN, attrs, self))
                    logger.debug('Got search result entry {0}'.format(DN))
                except UnexpectedResponseType:
                    try:
                        res = _unpack('searchResDone', msg).getComponentByName('resultCode')
                        if res == ResultCode('success') or res == ResultCode('noSuchObject'):
                            logger.debug('Got all search results for ID {0}, result is {1}'.format(
                                messageID, repr(res)
                            ))
                            return ret
                        else:
                            raise LDAPError('Got {0} for search results (ID {1})'.format(
                                repr(res), messageID
                            ))
                    except UnexpectedResponseType:
                        resref = _unpack('searchResRef', msg)
                        URIs = []
                        for i in range(0, len(resref)):
                            URIs.append(unicode(resref.getComponentByPosition(i)))
                        logger.debug('Got search reference to: {0}'.format(' | '.join(URIs)))
                        ret.append(SearchReferenceHandle(URIs))

    def search(self, *args, **kwds):
        mID = self._sendSearch(*args, **kwds)
        return self._recvSearchResults(mID)

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

class LDAP_rw(LDAP):
    ## add a new object

    def _sendAdd(self, DN, attrs):
        if self.sock.unbound:
            raise ConnectionUnbound()

        if not isinstance(DN, basestring):
            raise TypeError('DN must be string type')
        if not isinstance(attrs, dict):
            raise TypeError('attrs must be dict')

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

    # returns a corresponding LDAPObject on success
    def add(self, DN, attrs):
        mID = self._sendAdd(DN, attrs)
        _checkSuccessResult(self.sock.recvResponse(mID)[0], 'addResponse')
        return self.obj(DN, attrs)

    ## search+add patterns

    def addOrModAddIfExists(self, DN, attrs):
        try:
            cur = self.get(DN)
            cur.addAttrs(attrs)
            return cur
        except NoSearchResults:
            return self.add(DN, attrs)

    def addOrModReplaceIfExists(self, DN, attrs):
        try:
            cur = self.get(DN)
            cur.replaceAttrs(attrs)
            return cur
        except NoSearchResults:
            return self.add(DN, attrs)

    def addIfNotExists(self, DN, attrs):
        try:
            cur = self.get(DN)
            logger.debug('Object {0} already exists on addIfNotExists'.format(DN))
            return cur
        except NoSearchResults:
            logger.debug('Object {0} does not exist on addIfNotExists, adding'.format(DN))
            return self.add(DN, attrs)

    ## delete an object

    def _sendDelete(self, DN):
        if self.sock.unbound:
            raise ConnectionUnbound()
        mID = self.sock.sendMessage('delRequest', DelRequest(DN))
        logger.debug('Sent delete request (ID {0}) for DN {1}'.format(mID, DN))
        return mID

    def delete(self, DN):
        mID = self._sendDelete(DN)
        return _checkSuccessResult(self.sock.recvResponse(mID)[0], 'delResponse')

    ## change object DN

    # exposes all options of the protocol-level ModifyDNRequest
    def modDN(self, DN, newRDN, cleanAttr=True, newParent=None):
        if self.sock.unbound:
            raise ConnectionUnbound()
        mdr = ModifyDNRequest()
        mdr.setComponentByName('entry', LDAPDN(DN))
        mdr.setComponentByName('newrdn', RelativeLDAPDN(newRDN))
        mdr.setComponentByName('deleteoldrdn', cleanAttr)
        if newParent is not None:
            mdr.setComponentByName('newSuperior', NewSuperior(newParent))
        mID = self.sock.sendMessage('modDNRequest', mdr)
        return _checkSuccessResult(self.sock.recvResponse(mID)[0], 'modDNResponse')

    # edit the RDN of an object
    def rename(self, DN, newRDN, cleanAttr=True):
        return self.modDN(DN, newRDN, cleanAttr)

    # move object, possibly changing RDN as well
    def move(self, DN, newDN, cleanAttr=True):
        rdn, parent = newDN.split(',', 1)
        return self.modDN(DN, rdn, cleanAttr, parent)

    ## change attributes on an object

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

            c = Change()
            c.setComponentByName('operation', mod.op)
            pa = PartialAttribute()
            pa.setComponentByName('type', AttributeDescription(mod.attr))
            vals = Vals()
            j = 0
            for v in mod.vals:
                vals.setComponentByPosition(j, AttributeValue(v))
                j += 1
            pa.setComponentByName('vals', vals)
            c.setComponentByName('modification', pa)

            cl.setComponentByPosition(i, c)
            i += 1
        mr.setComponentByName('changes', cl)
        mID = self.sock.sendMessage('modifyRequest', mr)
        logger.debug('Sent modify request (ID {0}) for DN {1}'.format(mID, DN))
        return mID

    def modify(self, DN, modlist):
        mID = self._sendModify(DN, modlist)
        return _checkSuccessResult(self.sock.recvResponse(mID)[0], 'modifyResponse')

    # add new attributes and values
    def addAttrs(self, DN, attrsDict, current=None):
        if current is not None:
            modlist = AddModlist(current, attrsDict)
        elif not self.strictModify:
            current = self.get(DN, attrsDict.keys())
            modlist = AddModlist(current, attrsDict)
        else:
            modlist = Modlist(Mod.ADD, attrsDict)
        return self.modify(DN, modlist)

    # delete specific attribute values
    # specifying a 0-length entry will delete all values
    def deleteAttrValues(self, DN, attrsDict, current=None):
        if current is not None:
            modlist = DeleteModlist(current, attrsDict)
        elif not self.strictModify:
            current = self.get(DN, attrsDict.keys())
            modlist = DeleteModlist(current, attrsDict)
        else:
            modlist = Modlist(Mod.DELETE, attrsDict)
        return self.modify(DN, modlist)

    # delete all values for one or more attributes
    def deleteAttrs(self, DN, attrs, current=None):
        if not isinstance(attrs, list):
            attrs = [attrs]
        return self.deleteAttrValues(DN, dict.fromkeys(attrs, []), current)

    # replace all values on given attributes with the passed values
    # attributes not mentioned in attrsDict are not touched
    # attributes will be created if they do not exist
    # specifying a 0-length entry will delete that attribute
    def replaceAttrs(self, DN, attrsDict):
        return self.modify(DN, Modlist(Mod.REPLACE, attrsDict))

    # process a basic LDIF
    # TODO: full RFC 2849 implementation
    def processLDIF(self, ldifStr):
        ldifLines = ldifStr.splitlines()
        if not ldifLines[0].startswith('dn:'):
            raise ValueError('Missing dn')
        DN = ldifLines[0][3:].strip()
        if not ldifLines[1].startswith('changetype:'):
            raise ValueError('Missing changetype')
        changetype = ldifLines[1][11:].strip()

        if changetype == 'add':
            attrs = {}
            for line in ldifLines[2:]:
                attr, val = line.split(':', 1)
                if attr not in attrs:
                    attrs[attr] = []
                attrs[attr].append(val)
            return self.add(DN, attrs)
        elif changetype == 'delete':
            return self.delete(DN)
        elif changetype == 'modify':
            modOp = None
            modAttr = None
            vals = []
            modlist = []
            for line in ldifLines[2:]:
                if modOp is None:
                    _modOp, _modAttr = line.split(':')
                    modOp = Mod.string(_modOp)
                    modAttr = _modAttr.strip()
                    vals = []
                elif line == '-':
                    if modOp == 'add' and len(vals) == 0:
                        raise ValueError('no attribute values to add')
                    modlist += Modlist(modOp, {modAttr: vals})
                else:
                    if line.startswith(modAttr):
                        vals.append(line[len(modAttr)+1:].strip())
                    else:
                        raise ValueError('Unexpected attribute')
            return self.modify(DN, modlist)
        else:
            raise ValueError('changetype {0} unknown/not yet implemented'.format(changetype))

class LDAPObject(dict, Extensible):
    def __init__(self, dn,
        attrs={},
        ldapConn=None,
        relativeSearchScope=Scope.SUBTREE,
        rdnAttr=None
        ):

        self.dn = dn
        self.ldapConn = ldapConn
        self.relativeSearchScope = relativeSearchScope
        self.rdnAttr = rdnAttr
        dict.__init__(self, attrs)

    def __repr__(self):
        return "LDAPObject(dn='{0}', attrs={1})".format(self.dn, dict.__repr__(self))

    ## relative methods

    def RDN(self, rdn):
        if self.rdnAttr is not None:
            if not rdn.startswith(self.rdnAttr + '='):
                rdn = '{0}={1}'.format(self.rdnAttr, rdn)
        elif '=' not in rdn:
            raise ValueError('No rdnAttr specified, must supply full RDN attr=val')
        return '{0},{1}'.format(rdn, self.dn)

    def obj(self, rdn, tag=None, relativeSearchScope=None, rdnAttr=None, *args, **kwds):
        if relativeSearchScope is None:
            relativeSearchScope = self.relativeSearchScope
        if rdnAttr is None:
            rdnAttr = self.rdnAttr
        return self.ldapConn.obj(self.RDN(rdn), tag=tag, relativeSearchScope=relativeSearchScope,
            rdnAttr=rdnAttr, *args, **kwds)

    def getChild(self, rdn, attrs=None):
        if isinstance(self.ldapConn, LDAP):
            return self.ldapConn.get(self.RDN(rdn), attrs)
        else:
            raise RuntimeError('No LDAP object')

    def search(self, filter, attrs=None, *args, **kwds):
        if isinstance(self.ldapConn, LDAP):
            return self.ldapConn.search(self.dn, self.relativeSearchScope, filter, attrs,
                *args, **kwds)
        else:
            raise RuntimeError('No LDAP object')

    ## object-specific methods

    def iterattrs(self):
        for attr, vals in self.iteritems():
            for val in vals:
                yield (attr, val)
        raise StopIteration()

    def deepcopy(self):
        ret = {}
        for attr, val in self.iterattrs():
            if attr not in ret:
                ret[attr] = []
            ret[attr].append(val)
        return ret

    def formatLDIF(self):
        lines = ['dn: {0}'.format(self.dn)]
        for attr, val in self.iterattrs():
            lines.append('{0}: {1}'.format(attr, val))
        lines.append('')
        return '\n'.join(lines)

    def refresh(self, attrs=None):
        if isinstance(self.ldapConn, LDAP):
            self.update(self.ldapConn.get(self.dn, attrs))
            return True
        else:
            raise RuntimeError('No LDAP object')

    def refreshMissing(self, attrs):
        missingAttrs = []
        for attr in attrs:
            if attr not in self:
                missingAttrs.append(attr)
        if len(missingAttrs) > 0:
            self.refresh(missingAttrs)
        return True

    def compare(self, attr, value):
        if attr in self:
            logger.debug('Doing local compare for {0} ({1} = {2})'.format(self.dn, attr, value))
            return (value in self[attr])
        elif isinstance(self.ldapConn, LDAP):
            return self.ldapConn.compare(self.dn, attr, value)
        else:
            raise RuntimeError('No LDAP object')

    def hasObjectClass(self, objectClass):
        if 'objectClass' not in self:
            self.refresh(['objectClass'])
        return (objectClass in self['objectClass'])

    # update the server with the local attributes dictionary
    def commit(self):
        if isinstance(self.ldapConn, LDAP_rw):
            self.ldapConn.replaceAttrs(self.dn, self)
            self.removeEmptyAttrs()
        else:
            raise RuntimeError('No LDAP_rw object')

    # remove any 0-length attributes from the local dictionary so as to match the server
    # called automatically after writing to the server
    def removeEmptyAttrs(self):
        for attr in self.keys():
            if len(self[attr]) == 0:
                self.pop(attr)

    ## local modify methods
    ## accept same input as online versions, but only update the local attributes dictionary

    def localModify(self, modlist):
        for mod in modlist:
            if mod.op == Mod.ADD:
                self.localAddAttrs({mod.attr: mod.vals})
            elif mod.op == Mod.REPLACE:
                self.localReplaceAttrs({mod.attr: mod.vals})
            elif mod.op == Mod.DELETE:
                self.localDeleteAttrValues({mod.attr: mod.vals})
            else:
                raise ValueError('Invalid mod op')

    def localAddAttrs(self, attrsDict):
        for attr, vals in attrsDict.iteritems():
            if attr not in self:
                self[attr] = vals
            else:
                for val in vals:
                    if val not in self[attr]:
                        self[attr].append(val)

    def localReplaceAttrs(self, attrsDict):
        self.update(attrsDict)

    def localDeleteAttrValues(self, attrsDict):
        for attr, vals in attrsDict.iteritems():
            if attr in self:
                if len(vals) > 0:
                    for val in vals:
                        try:
                            self[attr].remove(val)
                        except:
                            pass
                else:
                    self[attr] = []

    def localDeleteAttrs(self, attrsList):
        self.localDeleteAttrValues(dict.fromkeys(attrsList, []))

    ## online modify methods
    ## these call the LDAP_rw methods of the same name, passing the object's DN as the first
    ## argument, then call the matching local modify method after a successful request to the
    ## server

    def modify(self, modlist):
        if isinstance(self.ldapConn, LDAP_rw):
            self.ldapConn.modify(self.dn, modlist)
            self.localModify(modlist)
            self.removeEmptyAttrs()
        else:
            raise RuntimeError('No LDAP_rw object')

    def addAttrs(self, attrsDict):
        if isinstance(self.ldapConn, LDAP_rw):
            if not self.ldapConn.strictModify:
                self.refreshMissing(attrsDict.keys())
            self.ldapConn.addAttrs(self.dn, attrsDict, current=self)
            self.localAddAttrs(attrsDict)
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def replaceAttrs(self, attrsDict):
        if isinstance(self.ldapConn, LDAP_rw):
            self.ldapConn.replaceAttrs(self.dn, attrsDict)
            self.localReplaceAttrs(attrsDict)
            self.removeEmptyAttrs()
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def deleteAttrValues(self, attrsDict):
        if isinstance(self.ldapConn, LDAP_rw):
            if not self.ldapConn.strictModify:
                self.refreshMissing(attrsDict.keys())
            self.ldapConn.deleteAttrValues(self.dn, attrsDict, current=self)
            self.localDeleteAttrValues(attrsDict)
            self.removeEmptyAttrs()
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def deleteAttrs(self, attrs):
        if isinstance(self.ldapConn, LDAP_rw):
            if not isinstance(attrs, list):
                attrs = [attrs]
            if not self.ldapConn.strictModify:
                self.refreshMissing(attrs)
            self.ldapConn.deleteAttrs(self.dn, attrs, current=self)
            self.localDeleteAttrs(attrs)
            self.removeEmptyAttrs()
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    # delete the object
    def delete(self):
        if isinstance(self.ldapConn, LDAP_rw):
            self.ldapConn.delete(self.dn)
            self.clear()
            self.dn = None
            self.ldapConn = None
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    # change object DN
    def modDN(self, newRDN, cleanAttr=True, newParent=None):
        if isinstance(self.ldapConn, LDAP_rw):
            curRDN, curParent = self.dn.split(',', 1)
            if newParent is None:
                parent = curParent
            else:
                parent = newParent
            self.ldapConn.modDN(self.dn, newRDN, cleanAttr, parent)
            if cleanAttr:
                rdnAttr, rdnVal = curRDN.split('=', 1)
                try:
                    self[rdnAttr].remove(rdnVal)
                    self.removeEmptyAttrs()
                except:
                    pass
            rdnAttr, rdnVal = newRDN.split('=', 1)
            if rdnAttr not in self:
                self[rdnAttr] = [rdnVal]
            elif rdnVal not in self[rdnAttr]:
                self[rdnAttr].append(rdnVal)
            self.dn = '{0},{1}'.format(newRDN, parent)
            return True
        else:
            raise RuntimeError('No LDAP_rw object')

    def rename(self, newRDN, cleanAttr=True):
        return self.modDN(newRDN, cleanAttr)

    def move(self, newDN, cleanAttr=True):
        newRDN, newParent = newDN.split(',', 1)
        return self.modDN(newRDN, cleanAttr, newParent)

# unpack an object from an LDAPMessage envelope
def _unpack(op, ldapMessage):
    po = ldapMessage.getComponentByName('protocolOp')
    ret = po.getComponentByName(op)
    if ret is not None:
        return ret
    else:
        raise UnexpectedResponseType()

# check for success result
def _checkSuccessResult(ldapMessage, operation):
    mID = ldapMessage.getComponentByName('messageID')
    res = _unpack(operation, ldapMessage).getComponentByName('resultCode')
    if res == ResultCode('success'):
        logger.debug('LDAP operation (ID {0}) was successful'.format(mID))
        return True
    else:
        raise LDAPError('Got {0} for {1} (ID {2})'.format(repr(res), operation, mID))

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