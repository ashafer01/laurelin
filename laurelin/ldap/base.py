"""Contains base classes for laurelin.ldap"""

from __future__ import absolute_import
import logging
from warnings import warn

from .rfc4511 import (
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
    SaslCredentials,
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
    AbandonRequest,
)
from .filter import parse as parseFilter
from .net import LDAPSocket, LDAPConnectionError
from .errors import *
from .modify import (
    Mod,
    Modlist,
    AddModlist,
    DeleteModlist,
    dictModAdd,
    dictModReplace,
    dictModDelete,
)
import six
from six.moves import range
from six.moves.urllib.parse import urlparse

logger = logging.getLogger('laurelin.ldap')
logger.addHandler(logging.NullHandler())
logger.setLevel(logging.DEBUG) # set to DEBUG to allow handler levels full discretion

# this delimits key from value in structured description fields
DESC_ATTR_DELIM = '='

# Commonly reused protocol objects
V3 = Version(3)
EMPTY_DN = LDAPDN('')
RESULT_saslBindInProgress = ResultCode('saslBindInProgress')
RESULT_success = ResultCode('success')
RESULT_noSuchObject = ResultCode('noSuchObject')
RESULT_compareTrue = ResultCode('compareTrue')
RESULT_compareFalse = ResultCode('compareFalse')

def _unpack(op, ldapMessage):
    """Unpack an object from an LDAPMessage envelope"""
    mID = ldapMessage.getComponentByName('messageID')
    po = ldapMessage.getComponentByName('protocolOp')
    ret = po.getComponentByName(op)
    if ret is not None:
        return mID, ret
    else:
        raise UnexpectedResponseType()

class Scope:
    """Scope constants

     These instruct the server how far to take a search, relative to the base object
     * Scope.BASE - only search the base object
     * Scope.ONE  - search the base object and its immediate children
     * Scope.SUB  - search the base object and all of its descendants
    """

    BASE = _Scope('baseObject')
    ONELEVEL = _Scope('singleLevel')
    ONE = ONELEVEL
    SUBTREE = _Scope('wholeSubtree')
    SUB = SUBTREE

    @staticmethod
    def string(str):
        """translate RFC4516 URL scope strings to constant"""
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
    """DerefAliases constants

     These instruct the server when to automatically resolve an alias object, rather than return the
     alias object itself
     * DerefAliases.NEVER  - always return the alias object
     * DerefAliases.SEARCH - dereferences search results, but not the base object itself
     * DerefAliases.BASE   - dereferences the search base object, but not search results
     * DerefAliases.ALWAYS - dereferences both the search base object and results
    """

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
    """Provides the connection to the LDAP DB"""

    # global defaults
    DEFAULT_FILTER = '(objectClass=*)'
    DEFAULT_DEREF_ALIASES = DerefAliases.ALWAYS
    DEFAULT_SEARCH_TIMEOUT = 0
    DEFAULT_CONNECT_TIMEOUT = 5
    DEFAULT_STRICT_MODIFY = False
    DEFAULT_REUSE_CONNECTION = True
    DEFAULT_SSL_VERIFY = True
    DEFAULT_SSL_CAFILE = None
    DEFAULT_SSL_CAPATH = None
    DEFAULT_SSL_CADATA = None
    DEFAULT_FETCH_RESULT_REFS = True
    DEFAULT_SASL_MECH = None
    DEFAULT_SASL_FATAL_DOWNGRADE_CHECK = True

    # spec constants
    NO_ATTRS = '1.1'
    ALL_USER_ATTRS = '*'

    # logging config
    LOG_FORMAT = '[%(asctime)s] %(name)s %(levelname)s : %(message)s'

    @staticmethod
    def enableLogging(level=logging.DEBUG):
        stderrHandler = logging.StreamHandler()
        stderrHandler.setFormatter(logging.Formatter(LDAP.LOG_FORMAT))
        stderrHandler.setLevel(level)
        logger.addHandler(stderrHandler)

    def __enter__(self):
        return self

    def __exit__(self, etype, e, trace):
        self.close()

    def __init__(self, connectTo, baseDN=None,
        reuseConnection=None,
        connectTimeout=None,
        searchTimeout=None,
        derefAliases=None,
        strictModify=None,
        sslVerify=None,
        sslCAFile=None,
        sslCAPath=None,
        sslCAData=None,
        fetchResultRefs=None,
        saslMech=None,
        saslFatalDowngradeCheck=None,
        ):

        # setup
        if reuseConnection is None:
            reuseConnection = LDAP.DEFAULT_REUSE_CONNECTION
        if connectTimeout is None:
            connectTimeout = LDAP.DEFAULT_CONNECT_TIMEOUT
        if searchTimeout is None:
            searchTimeout = LDAP.DEFAULT_SEARCH_TIMEOUT
        if derefAliases is None:
            derefAliases = LDAP.DEFAULT_DEREF_ALIASES
        if strictModify is None:
            strictModify = LDAP.DEFAULT_STRICT_MODIFY
        if sslVerify is None:
            sslVerify = LDAP.DEFAULT_SSL_VERIFY
        if sslCAFile is None:
            sslCAFile = LDAP.DEFAULT_SSL_CAFILE
        if sslCAPath is None:
            sslCAPath = LDAP.DEFAULT_SSL_CAPATH
        if sslCAData is None:
            sslCAData = LDAP.DEFAULT_SSL_CADATA
        if fetchResultRefs is None:
            fetchResultRefs = LDAP.DEFAULT_FETCH_RESULT_REFS
        if saslMech is None:
            saslMech = LDAP.DEFAULT_SASL_MECH
        if saslFatalDowngradeCheck is None:
            saslFatalDowngradeCheck = LDAP.DEFAULT_SASL_FATAL_DOWNGRADE_CHECK

        self.defaultSearchTimeout = searchTimeout
        self.defaultDerefAliases = derefAliases
        self.defaultFetchResultRefs = fetchResultRefs
        self.defaultSaslMech = saslMech
        self.strictModify = strictModify
        self.saslFatalDowngradeCheck = saslFatalDowngradeCheck

        self._taggedObjects = {}
        self._saslMechs = None

        self.sockParams = (connectTimeout, sslVerify, sslCAFile, sslCAPath, sslCAData)

        # connect
        if isinstance(connectTo, six.string_types):
            self.hostURI = connectTo
            if reuseConnection:
                if self.hostURI not in _sockets:
                    logger.info('Opening new socket connection to {0}'.format(self.hostURI))
                    _sockets[self.hostURI] = LDAPSocket(self.hostURI, *self.sockParams)
                self.sock = _sockets[self.hostURI]
            else:
                logger.info('Opening exclusive socket connection to {0}'.format(self.hostURI))
                self.sock = LDAPSocket(self.hostURI, *self.sockParams)
            logger.info('Connected to {0} (#{1})'.format(self.hostURI, self.sock.ID))
            if baseDN is not None:
                self.baseDN = baseDN
            else:
                logger.debug('Querying server to find baseDN')
                o = self.get('', ['namingContexts', 'defaultNamingContext'])
                if 'defaultNamingContext' in o:
                    self.baseDN = o['defaultNamingContext'][0]
                else:
                    ncs = o.getAttr('namingContexts')
                    n = len(ncs)
                    if n == 0:
                        raise LDAPError('Server did not supply any namingContexts, baseDN must '
                            'be provided')
                    elif n == 1:
                        self.baseDN = ncs[0]
                    else:
                        raise LDAPError('Server supplied multiple namingContexts, baseDN must be'
                            ' provided')
        elif isinstance(connectTo, LDAP):
            self.hostURI = connectTo.hostURI
            if reuseConnection:
                self.sock = connectTo.sock
                logger.info('Connected to {0} (#{1}) from existing object'.format(
                    self.hostURI, self.sock.ID))
            else:
                logger.info('Opening new exclusive socket connection to {0}'.format(self.hostURI))
                self.sockParams = connectTo.sockParams
                self.sock = LDAPSocket(self.hostURI, *self.sockParams)
                logger.info('Connected to {0} (#{1})'.format(self.hostURI, self.sock.ID))
            if baseDN is None:
                self.baseDN = connectTo.baseDN
            else:
                self.baseDN = baseDN
        else:
            raise TypeError('Must supply URI string or LDAP instance for connectTo')
        self.sock.refcount += 1

        if self.defaultSaslMech is None and self.hostURI.startswith('ldapi:'):
            self.defaultSaslMech = 'EXTERNAL'

        logger.debug('Creating base object for {0}'.format(self.baseDN))
        self.base = self.obj(self.baseDN, relativeSearchScope=Scope.SUBTREE)

    def _successResult(self, messageID, operation):
        """Receive an object from the socket and raise an LDAPError if its not a success result"""
        mID, obj = _unpack(operation, self.sock.recvOne(messageID))
        res = obj.getComponentByName('resultCode')
        if res == RESULT_success:
            logger.debug('LDAP operation (ID {0}) was successful'.format(mID))
            return True
        else:
            raise LDAPError('Got {0} for {1} (ID {2})'.format(repr(res), operation, mID))

    def simpleBind(self, username='', password=''):
        """Performs a simple bind operation

         Leave arguments as their default (empty strings) to attempt an anonymous simple bind
        """
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.sock.bound:
            raise ConnectionAlreadyBound()

        br = BindRequest()
        br.setComponentByName('version', V3)
        br.setComponentByName('name', LDAPDN(username))
        ac = AuthenticationChoice()
        ac.setComponentByName('simple', SimpleCreds(password))
        br.setComponentByName('authentication', ac)

        mID = self.sock.sendMessage('bindRequest', br)
        logger.debug('Sent bind request (ID {0}) on connection #{1} for {2}'.format(mID,
            self.sock.ID, username))
        ret = self._successResult(mID, 'bindResponse')
        self.sock.bound = ret
        logger.info('Simple bind successful')
        return ret

    def getSASLMechs(self):
        """Query root DSE for supported SASL mechanisms"""

        if self._saslMechs is None:
            logger.debug('Querying server to find supported SASL mechs')
            o = self.get('', ['supportedSASLMechanisms'])
            self._saslMechs = o.getAttr('supportedSASLMechanisms')
            logger.debug('Server supported SASL mechs = {0}'.format(','.join(self._saslMechs)))
        return self._saslMechs

    def recheckSASLMechs(self):
        """Query the root DSE again after performing a SASL bind to check for a downgrade attack"""

        if self._saslMechs is None:
            raise LDAPError('SASL mechs have not yet been queried')
        else:
            origMechs = set(self._saslMechs)
            self._saslMechs = None
            self.getSASLMechs()
            if origMechs != set(self._saslMechs):
                msg = 'Supported SASL mechs differ on recheck, possible downgrade attack'
                if self.saslFatalDowngradeCheck:
                    raise LDAPError(msg)
                else:
                    warn(msg)
            else:
                logger.debug('No evidence of downgrade attack')

    def saslBind(self, mech=None, **props):
        """Perform a SASL bind operation

         Specify a single standard mechanism string for mech, or leave it as None to negotiate the
         best mutually supported mechanism. Required keyword args are dependent on the mechanism
         chosen.
        """
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.sock.bound:
            raise ConnectionAlreadyBound()

        mechs = self.getSASLMechs()
        if mech is None:
            mech = self.defaultSaslMech
        if mech is not None:
            if mech not in mechs:
                raise LDAPError('SASL mech "{0}" is not supported by the server'.format(mech))
            else:
                mechs = [mech]
        self.sock.saslInit(mechs, **props)
        logger.debug('Selected SASL mech = {0}'.format(self.sock.saslMech))

        challengeResponse = None
        while True:
            br = BindRequest()
            br.setComponentByName('version', V3)
            br.setComponentByName('name', EMPTY_DN)
            ac = AuthenticationChoice()
            sasl = SaslCredentials()
            sasl.setComponentByName('mechanism', six.text_type(self.sock.saslMech))
            if challengeResponse is not None:
                sasl.setComponentByName('credentials', challengeResponse)
                challengeReponse = None
            ac.setComponentByName('sasl', sasl)
            br.setComponentByName('authentication', ac)

            mID = self.sock.sendMessage('bindRequest', br)
            logger.debug('Sent SASL bind request (ID {0}) on connection #{1}'.format(mID,
                self.sock.ID))

            mID, res = _unpack('bindResponse', self.sock.recvOne(mID))
            status = res.getComponentByName('resultCode')
            if status == RESULT_saslBindInProgress:
                challengeResponse = self.sock.saslProcessAuthChallenge(
                    six.text_type(res.getComponentByName('serverSaslCreds'))
                )
                continue
            elif status == RESULT_success:
                logger.info('SASL bind successful')
                logger.debug('Negotiated SASL QoP = {0}'.format(self.sock.saslQoP))
                self.sock.bound = True
                self.recheckSASLMechs()
                return True
            else:
                raise LDAPError('Got {0} during SASL bind'.format(repr(status)))
        raise LDAPError('Programming error - reached end of saslBind')

    def unbind(self, force=False):
        """Send an unbind request and close the socket"""
        if self.sock.unbound:
            raise ConnectionUnbound()

        self.sock.refcount -= 1
        if force or self.sock.refcount == 0:
            self.sock.sendMessage('unbindRequest', UnbindRequest())
            self.sock.close()
            self.sock.unbound = True
            logger.info('Unbound on {0} (#{1})'.format(self.sock.URI, self.sock.ID))
            try:
                del _sockets[self.sock.URI]
            except KeyError:
                pass
        else:
            logger.debug('Socket still in use')

    close = unbind

    def tag(self, tag):
        """Get a tagged object"""
        try:
            return self._taggedObjects[tag]
        except KeyError:
            raise TagError('tag {0} does not exist'.format(tag))

    def obj(self, DN, attrs=None, tag=None, *args, **kwds):
        """Factory for LDAPObjects bound to this connection"""
        if attrs is None:
            attrs = {}
        obj = LDAPObject(DN, attrs=attrs, ldapConn=self, *args, **kwds)
        if tag is not None:
            if tag in self._taggedObjects:
                raise TagError('tag {0} already exists'.format(tag))
            else:
                self._taggedObjects[tag] = obj
        return obj

    def get(self, DN, attrs=None, **objKwds):
        """Get a specific object by DN"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        results = list(self.search(DN, Scope.BASE, attrs=attrs, limit=2, **objKwds))
        n = len(results)
        if n == 0:
            raise NoSearchResults()
        elif n > 1:
            raise MultipleSearchResults()
        else:
            return results[0]

    def exists(self, DN):
        """Simply check if a DN exists"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        try:
            self.get(DN, [])
            return True
        except NoSearchResults:
            return False
        except MultipleSearchResults:
            return True

    def search(self, baseDN, scope=Scope.SUBTREE, filter=None, attrs=None, searchTimeout=None,
        limit=0, derefAliases=None, attrsOnly=False, fetchResultRefs=None, **objKwds):
        """Send search and iterate results until we get a SearchResultDone

         Yields instances of LDAPObject and possibly SearchReferenceHandle, if any result
         references are returned from the server, and the fetchResultRefs keyword arg is False.
        """
        if self.sock.unbound:
            raise ConnectionUnbound()

        if filter is None:
            filter = LDAP.DEFAULT_FILTER
        if searchTimeout is None:
            searchTimeout = self.defaultSearchTimeout
        if derefAliases is None:
            derefAliases = self.defaultDerefAliases
        if fetchResultRefs is None:
            fetchResultRefs = self.defaultFetchResultRefs
        req = SearchRequest()
        req.setComponentByName('baseObject', LDAPDN(baseDN))
        req.setComponentByName('scope', scope)
        req.setComponentByName('derefAliases', derefAliases)
        req.setComponentByName('sizeLimit', NonNegativeInteger(limit))
        req.setComponentByName('timeLimit', NonNegativeInteger(searchTimeout))
        req.setComponentByName('typesOnly', TypesOnly(attrsOnly))
        req.setComponentByName('filter', parseFilter(filter))

        _attrs = AttributeSelection()
        i = 0
        if attrs is None:
            attrs = [LDAP.ALL_USER_ATTRS]
        if not isinstance(attrs, list):
            attrs = [attrs]
        for desc in attrs:
            _attrs.setComponentByPosition(i, LDAPString(desc))
            i += 1
        req.setComponentByName('attributes', _attrs)

        mID = self.sock.sendMessage('searchRequest', req)
        logger.info('Sent search request (ID {0}): baseDN={1}, scope={2}, filter={3}'.format(
            mID, baseDN, scope, filter
        ))
        return SearchResultHandle(self, mID, fetchResultRefs, objKwds)

    def compare(self, DN, attr, value):
        """Perform a compare operation, returning boolean"""
        if self.sock.unbound:
            raise ConnectionUnbound()

        cr = CompareRequest()
        cr.setComponentByName('entry', LDAPDN(six.text_type(DN)))
        ava = AttributeValueAssertion()
        ava.setComponentByName('attributeDesc', AttributeDescription(six.text_type(attr)))
        ava.setComponentByName('assertionValue', AssertionValue(six.text_type(value)))
        cr.setComponentByName('ava', ava)

        messageID = self.sock.sendMessage('compareRequest', cr)
        logger.info('Sent compare request (ID {0}): {1} ({2} = {3})'.format(
            messageID, DN, attr, value
        ))
        msg = self.sock.recvOne(messageID)
        mID, res = _unpack('compareResponse', msg)
        res = res.getComponentByName('resultCode')
        if res == RESULT_compareTrue:
            logger.debug('Compared True (ID {0})'.format(mID))
            return True
        elif res == RESULT_compareFalse:
            logger.debug('Compared False (ID {0})'.format(mID))
            return False
        else:
            raise LDAPError('Got compare result {0} (ID {1})'.format(repr(res), mID))

    def add(self, DN, attrsDict, **objKwds):
        """Add new object and return corresponding LDAPObject on success"""
        if self.sock.unbound:
            raise ConnectionUnbound()

        if not isinstance(DN, six.string_types):
            raise TypeError('DN must be string type')
        if not isinstance(attrsDict, dict):
            raise TypeError('attrsDict must be dict')

        ar = AddRequest()
        ar.setComponentByName('entry', LDAPDN(DN))
        al = AttributeList()
        i = 0
        for attrType, attrVals in six.iteritems(attrsDict):
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
        logger.info('Sent add request (ID {0}) for DN {1}'.format(mID, DN))
        self._successResult(mID, 'addResponse')
        return self.obj(DN, attrsDict, **objKwds)

    ## search+add patterns

    def addOrModAddIfExists(self, DN, attrsDict):
        """Add object if it doesn't exist, otherwise addAttrs

         * If the object at DN exists, perform an add modification using the attrs dictionary.
           Otherwise, create the object using the attrs dictionary.
         * This ensures that, for the attributes mentioned in attrs, AT LEAST those values will
           exist on the given DN, regardless of prior state of the DB.
         * Always returns an LDAPObject corresponding to the final state of the DB
        """
        try:
            cur = self.get(DN)
            cur.addAttrs(attrsDict)
            return cur
        except NoSearchResults:
            return self.add(DN, attrsDict)

    def addOrModReplaceIfExists(self, DN, attrsDict):
        """Add object if it doesn't exist, otherwise replaceAttrs

         * If the object at DN exists, perform a replace modification using the attrs dictionary
           Otherwise, create the object using the attrs dictionary
         * This ensures that, for the attributes mentioned in attrs, ONLY those values will exist on
           the given DN regardless of prior state of the DB.
         * Always returns an LDAPObject corresponding to the final state of the DB
        """
        try:
            cur = self.get(DN)
            cur.replaceAttrs(attrsDict)
            return cur
        except NoSearchResults:
            return self.add(DN, attrsDict)

    def addIfNotExists(self, DN, attrsDict):
        """Add object if it doesn't exist

         * Gets and returns the object at DN if it exists, otherwise create the object using the
           attrs dictionary
         * Always returns an LDAPObject corresponding to the final state of the DB
        """
        try:
            cur = self.get(DN)
            logger.debug('Object {0} already exists on addIfNotExists'.format(DN))
            return cur
        except NoSearchResults:
            return self.add(DN, attrsDict)

    ## delete an object

    def delete(self, DN):
        """Delete an object"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        mID = self.sock.sendMessage('delRequest', DelRequest(DN))
        logger.info('Sent delete request (ID {0}) for DN {1}'.format(mID, DN))
        return self._successResult(mID, 'delResponse')

    ## change object DN

    def modDN(self, DN, newRDN, cleanAttr=True, newParent=None):
        """Exposes all options of the protocol-level ModifyDNRequest"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        mdr = ModifyDNRequest()
        mdr.setComponentByName('entry', LDAPDN(DN))
        mdr.setComponentByName('newrdn', RelativeLDAPDN(newRDN))
        mdr.setComponentByName('deleteoldrdn', cleanAttr)
        if newParent is not None:
            mdr.setComponentByName('newSuperior', NewSuperior(newParent))
        mID = self.sock.sendMessage('modDNRequest', mdr)
        logger.info('Sent modDN request (ID {0}) for DN {1} newRDN="{2}" newParent="{3}"'.format(
            mID, DN, newRDN, newParent))
        return self._successResult(mID, 'modDNResponse')

    def rename(self, DN, newRDN, cleanAttr=True):
        """Specify a new RDN for an object without changing its location in the tree"""
        return self.modDN(DN, newRDN, cleanAttr)

    def move(self, DN, newDN, cleanAttr=True):
        """Specify a new absolute DN for an object"""
        rdn, parent = newDN.split(',', 1)
        return self.modDN(DN, rdn, cleanAttr, parent)

    ## change attributes on an object

    def modify(self, DN, modlist):
        """Perform a series of modify operations on an object

         modlist must be a list of laurelin.ldap.modify.Mod instances
        """
        if len(modlist) > 0:
            if self.sock.unbound:
                raise ConnectionUnbound()
            mr = ModifyRequest()
            mr.setComponentByName('object', LDAPDN(DN))
            cl = Changes()
            i = 0
            logger.debug('Modifying DN {0}'.format(DN))
            for mod in modlist:
                logger.debug('> {0}'.format(mod))

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
            logger.info('Sent modify request (ID {0}) for DN {1}'.format(mID, DN))
            return self._successResult(mID, 'modifyResponse')
        else:
            logger.debug('Not sending 0-length modlist for DN {0}'.format(DN))
            return True

    def addAttrs(self, DN, attrsDict, current=None):
        """Add new attribute values to existing object"""
        if current is not None:
            modlist = AddModlist(current, attrsDict)
        elif not self.strictModify:
            current = self.get(DN, list(attrsDict.keys()))
            modlist = AddModlist(current, attrsDict)
        else:
            modlist = Modlist(Mod.ADD, attrsDict)
        return self.modify(DN, modlist)

    def deleteAttrs(self, DN, attrsDict, current=None):
        """Delete specific attribute values from dictionary

         Specifying a 0-length entry will delete all values
        """
        if current is not None:
            modlist = DeleteModlist(current, attrsDict)
        elif not self.strictModify:
            current = self.get(DN, list(attrsDict.keys()))
            modlist = DeleteModlist(current, attrsDict)
        else:
            modlist = Modlist(Mod.DELETE, attrsDict)
        return self.modify(DN, modlist)

    def replaceAttrs(self, DN, attrsDict):
        """Replace all values on given attributes with the passed values

         * Attributes not mentioned in attrsDict are not touched
         * Attributes will be created if they do not exist
         * Specifying a 0-length entry will delete all values for that attribute
        """
        return self.modify(DN, Modlist(Mod.REPLACE, attrsDict))

    def processLDIF(self, ldifStr):
        """Process a basic LDIF

         TODO: full RFC 2849 implementation
        """
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


class SearchResultHandle(object):
    def __init__(self, ldapConn, messageID, fetchResultRefs, objKwds):
        self.ldapConn = ldapConn
        self.sock = ldapConn.sock
        self.messageID = messageID
        self.fetchResultRefs = fetchResultRefs
        self.objKwds = objKwds
        self.done = False
        self.abandoned = False

    def __iter__(self):
        if self.abandoned:
            logger.debug('ID={0} has been abandoned'.format(self.messageID))
            raise StopIteration()
        for msg in self.sock.recvMessages(self.messageID):
            if self.abandoned:
                logger.debug('ID={0} abandoned while receiving search results'.format(
                    self.messageID))
                raise StopIteration()
            try:
                mID, entry = _unpack('searchResEntry', msg)
                DN = six.text_type(entry.getComponentByName('objectName'))
                attrs = {}
                _attrs = entry.getComponentByName('attributes')
                for i in range(0, len(_attrs)):
                    _attr = _attrs.getComponentByPosition(i)
                    attrType = six.text_type(_attr.getComponentByName('type'))
                    _vals = _attr.getComponentByName('vals')
                    vals = []
                    for j in range(0, len(_vals)):
                        vals.append(six.text_type(_vals.getComponentByPosition(j)))
                    attrs[attrType] = vals
                logger.debug('Got search result entry (ID {0}) {1}'.format(mID, DN))
                yield self.ldapConn.obj(DN, attrs, **self.objKwds)
            except UnexpectedResponseType:
                try:
                    mID, resobj = _unpack('searchResDone', msg)
                    self.done = True
                    res = resobj.getComponentByName('resultCode')
                    if res == RESULT_success or res == RESULT_noSuchObject:
                        logger.debug('Got all search results for ID {0}, result is {1}'.format(
                            mID, repr(res)
                        ))
                        raise StopIteration()
                    else:
                        raise LDAPError('Got {0} for search results (ID {1})'.format(
                            repr(res), mID
                        ))
                except UnexpectedResponseType:
                    mID, resref = _unpack('searchResRef', ldapMessage)
                    URIs = []
                    for i in range(0, len(resref)):
                        URIs.append(six.text_type(resref.getComponentByPosition(i)))
                    logger.debug('Got search result reference (ID {0}) to: {1}'.format(
                        mID, ' | '.join(URIs)
                    ))
                    ref = SearchReferenceHandle(URIs, self.objKwds)
                    if self.fetchResultRefs:
                        for obj in ref.fetch():
                            yield obj
                    else:
                        yield ref

    def __enter__(self):
        return self

    def __exit__(self, etype, e, trace):
        if not self.done:
            self.abandon()
        if etype == Abandon:
            return True

    def abandon(self):
        """Request to abandon an operation in progress"""
        if not self.abandoned:
            logger.info('Abandoning search ID={0}'.format(self.messageID))
            self.sock.sendMessage('abandonRequest', AbandonRequest(self.messageID))
            self.abandoned = True
            self.sock.abandonedMIDs.append(self.messageID)
        else:
            logger.debug('ID={0} already abandoned'.format(self.messageID))


class AttrsDict(dict):
    """Stores attributes and provides utility methods without any server or object affinity

     Dict keys are attribute names, and dict values are a list of attribute values
    """

    def getAttr(self, attr):
        return self.get(attr, [])

    def iterattrs(self):
        for attr, vals in six.iteritems(self):
            for val in vals:
                yield (attr, val)

    def deepcopy(self):
        """return a native dict copy of self"""
        ret = {}
        for attr, vals in six.iteritems(self):
            ret[attr] = []
            for val in vals:
                ret[attr].append(val)
        return ret

    ## local modify methods
    ## accept same input as online versions, but only update the local attributes dictionary

    def modify_local(self, modlist):
        for mod in modlist:
            if mod.op == Mod.ADD:
                self.addAttrs_local({mod.attr: mod.vals})
            elif mod.op == Mod.REPLACE:
                self.replaceAttrs_local({mod.attr: mod.vals})
            elif mod.op == Mod.DELETE:
                self.deleteAttrs_local({mod.attr: mod.vals})
            else:
                raise ValueError('Invalid mod op')

    addAttrs_local = dictModAdd
    replaceAttrs_local = dictModReplace
    deleteAttrs_local = dictModDelete

    ## dict overrides for enforcing types

    def __init__(self, attrsDict=None):
        if attrsDict is not None:
            AttrsDict.validate(attrsDict)
            dict.__init__(self, attrsDict)

    def __contains__(self, attr):
        if dict.__contains__(self, attr):
            return (len(self[attr]) > 0)
        else:
            return False

    def __setitem__(self, attr, values):
        AttrsDict.validateValues(values)
        dict.__setitem__(self, attr, values)

    def setdefault(self, attr, default=None):
        if not isinstance(attr, six.string_types):
            raise TypeError('attribute name must be string')
        if default is None:
            default = []
        try:
            AttrsDict.validateValues(default)
            return dict.setdefault(self, attr, default)
        except TypeError as e:
            raise TypeError('invalid default - {0}'.format(e.message))

    def update(self, attrsDict):
        AttrsDict.validate(attrsDict)
        dict.update(self, attrsDict)

    @staticmethod
    def validate(attrsDict):
        if isinstance(attrsDict, AttrsDict):
            return
        if not isinstance(attrsDict, dict):
            raise TypeError('must be dict')
        for attr in attrsDict:
            if not isinstance(attr, six.string_types):
                raise TypeError('attribute name must be string')
            AttrsDict.validateValues(attrsDict[attr])

    @staticmethod
    def validateValues(attrValList):
        if not isinstance(attrValList, list):
            raise TypeError('must be list')
        for val in attrValList:
            # TODO binary data support throughout...
            if not isinstance(val, six.string_types):
                raise TypeError('attribute values must be string')


class LDAPObject(AttrsDict, Extensible):
    """Represents a single object with optional server affinity

     Many methods will raise an exception if used without a server connection. To instantiate an
     LDAPObject bound to a server connection, use LDAP.obj()

     Attributes and values are stored using the mapping interface inherited from AttrsDict.
    """

    def __init__(self, dn,
        attrs=None,
        ldapConn=None,
        relativeSearchScope=Scope.SUBTREE,
        rdnAttr=None
        ):

        self.dn = dn
        self.ldapConn = ldapConn
        self.relativeSearchScope = relativeSearchScope
        self.rdnAttr = rdnAttr
        self._unstructuredDesc = set()
        AttrsDict.__init__(self, attrs)

    def __repr__(self):
        return "LDAPObject(dn='{0}', attrs={1})".format(self.dn, AttrsDict.__repr__(self))

    def __eq__(self, other):
        if not isinstance(other, LDAPObject):
            return False
        elif self.dn != other.dn:
            return False
        else:
            return AttrsDict.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def _requireLDAP(self):
        if not isinstance(self.ldapConn, LDAP):
            raise RuntimeError('No LDAP instance')

    ## relative methods

    def RDN(self, rdn):
        if '=' not in rdn:
            if self.rdnAttr is not None:
                rdn = '{0}={1}'.format(self.rdnAttr, rdn)
            else:
                raise ValueError('No rdnAttr specified, must supply full RDN attr=val')
        return '{0},{1}'.format(rdn, self.dn)

    def _setObjKwdDefaults(self, objKwds):
        """set inherited attributes on keywords dictionary, to make its way into new LDAPObjects"""
        objKwds.setdefault('relativeSearchScope', self.relativeSearchScope)
        objKwds.setdefault('rdnAttr', self.rdnAttr)

    def obj(self, rdn, tag=None, *args, **kwds):
        self._setObjKwdDefaults(kwds)
        if isinstance(self.ldapConn, LDAP):
            return self.ldapConn.obj(self.RDN(rdn), tag=tag, *args, **kwds)
        else:
            if tag is not None:
                raise LDAPError('tagging requires LDAP instance')
            return LDAPObject(self.RDN(rdn), *args, **kwds)

    def getChild(self, rdn, attrs=None, **objKwds):
        self._requireLDAP()
        self._setObjKwdDefaults(objKwds)
        return self.ldapConn.get(self.RDN(rdn), attrs, **objKwds)

    def addChild(self, rdn, attrsDict, **objKwds):
        self._requireLDAP()
        self._setObjKwdDefaults(objKwds)
        return self.ldapConn.add(self.RDN(rdn), attrsDict, **objKwds)

    def search(self, filter=None, attrs=None, *args, **kwds):
        self._requireLDAP()
        self._setObjKwdDefaults(kwds)
        return self.ldapConn.search(self.dn, self.relativeSearchScope, filter, attrs,
            *args, **kwds)

    ## object-specific methods

    def formatLDIF(self):
        lines = ['dn: {0}'.format(self.dn)]
        for attr, val in self.iterattrs():
            lines.append('{0}: {1}'.format(attr, val))
        lines.append('')
        return '\n'.join(lines)

    def hasObjectClass(self, objectClass):
        self.refreshMissing(['objectClass'])
        return (objectClass in self['objectClass'])

    def refresh(self, attrs=None):
        self._requireLDAP()
        self.update(self.ldapConn.get(self.dn, attrs))

    def refreshMissing(self, attrs):
        missingAttrs = []
        for attr in attrs:
            if attr not in self:
                missingAttrs.append(attr)
        if len(missingAttrs) > 0:
            self.refresh(missingAttrs)

    def commit(self):
        """update the server with the local attributes dictionary"""
        self._requireLDAP()
        self.ldapConn.replaceAttrs(self.dn, self)
        self._removeEmptyAttrs()

    def compare(self, attr, value):
        if attr in self:
            logger.debug('Doing local compare for {0} ({1} = {2})'.format(self.dn, attr, value))
            return (value in self.getAttr(attr))
        elif isinstance(self.ldapConn, LDAP):
            return self.ldapConn.compare(self.dn, attr, value)
        else:
            raise RuntimeError('No LDAP object')

    def _removeEmptyAttrs(self):
        """clean any 0-length attributes from the local dictionary so as to match the server
         called automatically after writing to the server
        """
        for attr in self.keys():
            if len(self[attr]) == 0:
                del self[attr]

    ## online modify methods
    ## these call the LDAP methods of the same name, passing the object's DN as the first
    ## argument, then call the matching local modify method after a successful request to the
    ## server

    def modify(self, modlist):
        self._requireLDAP()
        self.ldapConn.modify(self.dn, modlist)
        self.modify_local(modlist)
        self._removeEmptyAttrs()

    def addAttrs(self, attrsDict):
        self._requireLDAP()
        if not self.ldapConn.strictModify:
            self.refreshMissing(list(attrsDict.keys()))
        self.ldapConn.addAttrs(self.dn, attrsDict, current=self)
        self.addAttrs_local(attrsDict)

    def replaceAttrs(self, attrsDict):
        self._requireLDAP()
        self.ldapConn.replaceAttrs(self.dn, attrsDict)
        self.replaceAttrs_local(attrsDict)
        self._removeEmptyAttrs()

    def deleteAttrs(self, attrsDict):
        self._requireLDAP()
        if not self.ldapConn.strictModify:
            self.refreshMissing(list(attrsDict.keys()))
        self.ldapConn.deleteAttrs(self.dn, attrsDict, current=self)
        self.deleteAttrs_local(attrsDict)
        self._removeEmptyAttrs()

    ## online-only object-level methods

    def delete(self):
        """delete the entire object from the server, and render this instance useless"""
        self._requireLDAP()
        self.ldapConn.delete(self.dn)
        self.clear()
        self.dn = None
        self.ldapConn = None

    def modDN(self, newRDN, cleanAttr=True, newParent=None):
        """change the object DN, and possibly its location in the tree"""
        self._requireLDAP()
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
                self._removeEmptyAttrs()
            except Exception:
                pass
        rdnAttr, rdnVal = newRDN.split('=', 1)
        if rdnAttr not in self:
            self[rdnAttr] = [rdnVal]
        elif rdnVal not in self[rdnAttr]:
            self[rdnAttr].append(rdnVal)
        self.dn = '{0},{1}'.format(newRDN, parent)

    def rename(self, newRDN, cleanAttr=True):
        return self.modDN(newRDN, cleanAttr)

    def move(self, newDN, cleanAttr=True):
        newRDN, newParent = newDN.split(',', 1)
        return self.modDN(newRDN, cleanAttr, newParent)

    ## structured description field methods
    ## these implement the common pattern of storing arbitrary key=value data in description fields

    def descAttrs(self):
        self.refreshMissing(['description'])
        ret = AttrsDict()
        self._unstructuredDesc = set()
        for desc in self.getAttr('description'):
            if DESC_ATTR_DELIM in desc:
                key, value = desc.split(DESC_ATTR_DELIM, 1)
                vals = ret.setdefault(key, [])
                vals.append(value)
            else:
                self._unstructuredDesc.add(desc)
        return ret

    def _modifyDescAttrs(self, method, attrsDict):
        self._requireLDAP()
        descDict = self.descAttrs()
        method(descDict, attrsDict)
        descStrings = []
        for key, values in six.iteritems(descDict):
            for value in values:
                descStrings.append(key + DESC_ATTR_DELIM + value)
        self.replaceAttrs({'description':descStrings + list(self._unstructuredDesc)})

    def addDescAttrs(self, attrsDict):
        self._modifyDescAttrs(dictModAdd, attrsDict)

    def replaceDescAttrs(self, attrsDict):
        self._modifyDescAttrs(dictModReplace, attrsDict)

    def deleteDescAttrs(self, attrsDict):
        self._modifyDescAttrs(dictModDelete, attrsDict)


class LDAPURI(object):
    """Represents a parsed LDAP URI as specified in RFC4516

     Attributes:
     * scheme   - urlparse standard
     * netloc   - urlparse standard
     * hostURI  - scheme://netloc for use with LDAPSocket
     * DN       - string
     * attrs    - list
     * scope    - one of the Scope.* constants
     * filter   - string
     * Extensions not yet implemented
    """
    def __init__(self, uri):
        self._orig = uri
        parsedURI = urlparse(uri)
        self.scheme = parsedURI.scheme
        self.netloc = parsedURI.netloc
        self.hostURI = '{0}://{1}'.format(self.scheme, self.netloc)
        self.DN = parsedURI.path
        params = parsedURI.query.split('?')
        nparams = len(params)
        if (nparams > 0) and (len(params[0]) > 0):
            self.attrs = params[0].split(',')
        else:
            self.attrs = [LDAP.ALL_USER_ATTRS]
        if (nparams > 1) and (len(params[1]) > 0):
            self.scope = Scope.string(params[1])
        else:
            self.scope = Scope.BASE
        if (nparams > 2) and (len(params[2]) > 0):
            self.filter = params[2]
        else:
            self.filter = LDAP.DEFAULT_FILTER
        if (nparams > 3) and (len(params[3]) > 0):
            raise LDAPError('Extensions for LDAPURI not yet implemented')

    def search(self, **objKwds):
        """Perform the search operation described by the parsed URI

         First opens a new connection with connection reuse disabled, then performs the search, and
         unbinds the connection. Server must allow anonymous read.
        """
        ldap = LDAP(self.hostURI, reuseConnection=False)
        ret = ldap.search(self.DN, self.scope, filter=self.filter, attrs=self.attrs, **objKwds)
        ldap.unbind()
        return ret

    def __str__(self):
        return self._orig

    def __repr__(self):
        return "LDAPURI('{0}')".format(self._orig)


class SearchReferenceHandle(object):
    """Returned when the server returns a SearchResultReference"""
    def __init__(self, URIs, objKwds):
        self.URIs = []
        self.objKwds = objKwds
        for uri in URIs:
            self.URIs.append(LDAPURI(uri))

    def fetch(self):
        """Perform the reference search and return an iterator over results"""

        # If multiple URIs are present, the client assumes that any supported URI
        # may be used to progress the operation. ~ RFC4511 sec 4.5.3 p28
        for uri in self.URIs:
            try:
                return uri.search(**self.objKwds)
            except LDAPConnectionError as e:
                warn('Error connecting to URI {0} ({1})'.format(uri, e.message))
        raise LDAPError('Could not complete reference URI search with any supplied URIs')
