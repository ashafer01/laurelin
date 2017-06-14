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
    Controls,
    Control as _Control,
    LDAPOID,
    Criticality,
    ControlValue,
    ExtendedRequest,
    RequestName,
    RequestValue,
)
from .constants import Scope, DerefAliases
from .filter import parse as parseFilter
from .errors import *
from .extensible import Extensible
from .ldapobject import LDAPObject
from .modify import (
    Mod,
    Modlist,
    AddModlist,
    DeleteModlist,
)
from .net import LDAPSocket
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
RESULT_referral = ResultCode('referral')

def _unpack(op, ldapMessage):
    """Unpack an object from an LDAPMessage envelope"""
    mID = ldapMessage.getComponentByName('messageID')
    po = ldapMessage.getComponentByName('protocolOp')
    ret = po.getComponentByName(op)
    if ret is not None:
        return mID, ret
    else:
        raise UnexpectedResponseType()

def _seqToList(seq):
    ret = []
    for i in range(len(seq)):
        ret.append(six.text_type(seq.getComponentByPosition(i)))
    return ret

# for storing reusable sockets
_sockets = {}

class LDAP(Extensible):
    """Provides the connection to the LDAP DB"""

    # global defaults
    DEFAULT_SERVER = 'ldap://localhost'
    DEFAULT_BASEDN = None
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
    DEFAULT_FOLLOW_REFERRALS = True
    DEFAULT_SASL_MECH = None
    DEFAULT_SASL_FATAL_DOWNGRADE_CHECK = True
    DEFAULT_CRITICALITY = False

    # spec constants
    NO_ATTRS = '1.1'
    ALL_USER_ATTRS = '*'

    # logging config
    LOG_FORMAT = '[%(asctime)s] %(name)s %(levelname)s : %(message)s'

    # OIDs
    OID_WHOAMI   = '1.3.6.1.4.1.4203.1.11.3'
    OID_STARTTLS = '1.3.6.1.4.1.1466.20037'

    @staticmethod
    def enableLogging(level=logging.DEBUG):
        stderrHandler = logging.StreamHandler()
        stderrHandler.setFormatter(logging.Formatter(LDAP.LOG_FORMAT))
        stderrHandler.setLevel(level)
        logger.addHandler(stderrHandler)
        return stderrHandler

    _reservedKwds = set()
    _controls = {}

    @classmethod
    def REGISTER_CONTROL(cls, ctrl):
        if len(cls._reservedKwds) == 0:
            from inspect import getargspec
            # functions that either call sendMessage or have kwds passed through into them
            reserveFrom = [
                LDAPObject.__init__,
                LDAP.obj,
                LDAP.simpleBind,
                LDAP.saslBind,
                LDAP.search,
                LDAP.compare,
                LDAP.add,
                LDAP.delete,
                LDAP.modify,
                LDAP.modDN,
                LDAP.sendExtendedRequest,
                ExtendedResponseHandle.__init__,
            ]
            for f in reserveFrom:
                cls._reservedKwds.update(getargspec(f).args)
        if not isinstance(ctrl, Control):
            raise TypeError('must be Control instance')
        if ctrl.keyword in cls._reservedKwds:
            raise LDAPExtensionError('Control keyword "{0}" is reserved'.format(ctrl.keyword))
        if ctrl.keyword in cls._controls:
            raise LDAPExtensionError('Control keyword "{0}" is already defined'.format(
                ctrl.keyword))
        cls._controls[ctrl.keyword] = ctrl

    def __enter__(self):
        return self

    def __exit__(self, etype, e, trace):
        self.close()

    def __init__(self, connectTo=None, baseDN=None, reuseConnection=None, connectTimeout=None,
        searchTimeout=None, derefAliases=None, strictModify=None, sslVerify=None, sslCAFile=None,
        sslCAPath=None, sslCAData=None, fetchResultRefs=None, saslMech=None,
        saslFatalDowngradeCheck=None, defaultCriticality=None, followReferrals=None):

        # setup
        if connectTo is None:
            connectTo = LDAP.DEFAULT_SERVER
        if baseDN is None:
            baseDN = LDAP.DEFAULT_BASEDN
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
        if defaultCriticality is None:
            defaultCriticality = LDAP.DEFAULT_CRITICALITY
        if followReferrals is None:
            followReferrals = LDAP.DEFAULT_FOLLOW_REFERRALS

        self.defaultSearchTimeout = searchTimeout
        self.defaultDerefAliases = derefAliases
        self.defaultFetchResultRefs = fetchResultRefs
        self.defaultFollowReferrals = followReferrals
        self.defaultSaslMech = saslMech
        self.defaultCriticality = defaultCriticality

        self.strictModify = strictModify
        self.saslFatalDowngradeCheck = saslFatalDowngradeCheck

        self._taggedObjects = {}
        self._saslMechs = None

        self.sockParams = (connectTimeout, sslVerify, sslCAFile, sslCAPath, sslCAData)
        self.sslVerify = sslVerify
        self.sslCAFile = sslCAFile
        self.sslCAPath = sslCAPath
        self.sslCAData = sslCAData

        # connect
        if isinstance(connectTo, six.string_types):
            self.hostURI = connectTo
            if reuseConnection:
                if self.hostURI not in _sockets:
                    _sockets[self.hostURI] = LDAPSocket(self.hostURI, *self.sockParams)
                self.sock = _sockets[self.hostURI]
            else:
                self.sock = LDAPSocket(self.hostURI, *self.sockParams)
            logger.info('Connected to {0} (#{1})'.format(self.hostURI, self.sock.ID))
        elif isinstance(connectTo, LDAP):
            self.hostURI = connectTo.hostURI
            if reuseConnection:
                self.sock = connectTo.sock
                self.sockParams = connectTo.sockParams
                logger.info('Connected to {0} (#{1}) from existing object'.format(
                    self.hostURI, self.sock.ID))
            else:
                self.sock = LDAPSocket(self.hostURI, *self.sockParams)
                logger.info('Connected to {0} (#{1})'.format(self.hostURI, self.sock.ID))
            if baseDN is None:
                baseDN = connectTo.baseDN
        else:
            raise TypeError('Must supply URI string or LDAP instance for connectTo')
        self.sock.refcount += 1

        self.refreshRootDSE()
        if baseDN is None:
            if 'defaultNamingContext' in self.rootDSE:
                baseDN = self.rootDSE['defaultNamingContext'][0]
            else:
                ncs = self.rootDSE.getAttr('namingContexts')
                n = len(ncs)
                if n == 0:
                    raise LDAPError('baseDN must be provided - no namingContexts')
                elif n == 1:
                    baseDN = ncs[0]
                else:
                    raise LDAPError('baseDN must be provided - multiple namingContexts')
        self.baseDN = baseDN

        if self.defaultSaslMech is None and self.hostURI.startswith('ldapi:'):
            self.defaultSaslMech = 'EXTERNAL'

        logger.debug('Creating base object for {0}'.format(self.baseDN))
        self.base = self.obj(self.baseDN, relativeSearchScope=Scope.SUBTREE)

    def refreshRootDSE(self):
        self.rootDSE = self.get('', ['*', '+'])
        self._saslMechs = self.rootDSE.getAttr('supportedSASLMechanisms')

    def _successResult(self, messageID, operation):
        """Receive an object from the socket and raise an LDAPError if its not a success result"""
        mID, obj = _unpack(operation, self.sock.recvOne(messageID))
        res = obj.getComponentByName('resultCode')
        if res == RESULT_success:
            logger.debug('LDAP operation (ID {0}) was successful'.format(mID))
            return True
        else:
            raise LDAPError('Got {0} for {1} (ID {2})'.format(repr(res), operation, mID))

    def _processCtrlKwds(self, method, kwds, final=False):
        """Process keyword arguments for registered controls, returning a protocol-level Controls

         Removes entries from kwds as they are used, allowing the same dictionary to be passed on
         to another function which may have statically defined arguments. If final is True, then a
         TypeError will be raised if all kwds are not exhausted.
        """
        i = 0
        ctrls = Controls()
        for kwd in list(kwds.keys()):
            if kwd in self._controls:
                ctrl = self._controls[kwd]
                if ctrl.method != method:
                    raise LDAPError('Control keyword {0} not allowed for method "{1}"'.format(kwd, method))
                ctrlValue = kwds.pop(kwd)
                if isinstance(ctrlValue, critical):
                    criticality = True
                    ctrlValue = ctrlValue.value
                elif isinstance(ctrlValue, optional):
                    criticality = False
                    ctrlValue = ctrlValue.value
                else:
                    criticality = self.defaultCriticality
                if criticality and (ctrl.OID not in self.rootDSE.getAttr('supportedControl')):
                    raise LDAPSupportError('Control keyword {0} is not supported by the server'.format(kwd))
                ctrls.setComponentByPosition(i, ctrl.prepare(ctrlValue, criticality))
                i += 1
        if final and (len(kwds) > 0):
            raise TypeError('Unhandled keyword arguments: {0}'.format(', '.join(kwds.keys())))
        if i > 0:
            return ctrls
        else:
            return None

    def simpleBind(self, username='', password='', **ctrlKwds):
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

        controls = self._processCtrlKwds('bind', ctrlKwds, final=True)

        mID = self.sock.sendMessage('bindRequest', br, controls)
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

        controls = self._processCtrlKwds('bind', props)

        mechs = self.getSASLMechs()
        if mech is None:
            mech = self.defaultSaslMech
        if mech is not None:
            if mech not in mechs:
                raise LDAPSupportError('SASL mech "{0}" is not supported by the server'.format(mech))
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
                challengeResponse = None
            ac.setComponentByName('sasl', sasl)
            br.setComponentByName('authentication', ac)

            mID = self.sock.sendMessage('bindRequest', br, controls)
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

    def obj(self, DN, attrsDict=None, tag=None, *args, **kwds):
        """Factory for LDAPObjects bound to this connection"""
        obj = LDAPObject(DN, attrsDict=attrsDict, ldapConn=self, *args, **kwds)
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
        limit=0, derefAliases=None, attrsOnly=False, fetchResultRefs=None, followReferrals=None,
        **kwds):
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
        if followReferrals is None:
            followReferrals = self.defaultFollowReferrals
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

        controls = self._processCtrlKwds('search', kwds)

        mID = self.sock.sendMessage('searchRequest', req, controls)
        logger.info('Sent search request (ID {0}): baseDN={1}, scope={2}, filter={3}'.format(
            mID, baseDN, scope, filter))
        return SearchResultHandle(self, mID, fetchResultRefs, followReferrals, kwds)

    def compare(self, DN, attr, value, **ctrlKwds):
        """Perform a compare operation, returning boolean"""
        if self.sock.unbound:
            raise ConnectionUnbound()

        cr = CompareRequest()
        cr.setComponentByName('entry', LDAPDN(six.text_type(DN)))
        ava = AttributeValueAssertion()
        ava.setComponentByName('attributeDesc', AttributeDescription(six.text_type(attr)))
        ava.setComponentByName('assertionValue', AssertionValue(six.text_type(value)))
        cr.setComponentByName('ava', ava)

        controls = self._processCtrlKwds('compare', ctrlKwds, final=True)

        messageID = self.sock.sendMessage('compareRequest', cr, controls)
        logger.info('Sent compare request (ID {0}): {1} ({2} = {3})'.format(
            messageID, DN, attr, value))
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

    def add(self, DN, attrsDict, **kwds):
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

        controls = self._processCtrlKwds('add', kwds)

        mID = self.sock.sendMessage('addRequest', ar, controls)
        logger.info('Sent add request (ID {0}) for DN {1}'.format(mID, DN))
        self._successResult(mID, 'addResponse')
        return self.obj(DN, attrsDict, **kwds)

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

    def delete(self, DN, **ctrlKwds):
        """Delete an object"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        controls = self._processCtrlKwds('delete', ctrlKwds, final=True)
        mID = self.sock.sendMessage('delRequest', DelRequest(DN), controls)
        logger.info('Sent delete request (ID {0}) for DN {1}'.format(mID, DN))
        return self._successResult(mID, 'delResponse')

    ## change object DN

    def modDN(self, DN, newRDN, cleanAttr=True, newParent=None, **ctrlKwds):
        """Exposes all options of the protocol-level ModifyDNRequest"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        mdr = ModifyDNRequest()
        mdr.setComponentByName('entry', LDAPDN(DN))
        mdr.setComponentByName('newrdn', RelativeLDAPDN(newRDN))
        mdr.setComponentByName('deleteoldrdn', cleanAttr)
        if newParent is not None:
            mdr.setComponentByName('newSuperior', NewSuperior(newParent))
        controls = self._processCtrlKwds('modDN', ctrlKwds, final=True)
        mID = self.sock.sendMessage('modDNRequest', mdr, controls)
        logger.info('Sent modDN request (ID {0}) for DN {1} newRDN="{2}" newParent="{3}"'.format(
            mID, DN, newRDN, newParent))
        return self._successResult(mID, 'modDNResponse')

    def rename(self, DN, newRDN, cleanAttr=True, **ctrlKwds):
        """Specify a new RDN for an object without changing its location in the tree"""
        return self.modDN(DN, newRDN, cleanAttr, **ctrlKwds)

    def move(self, DN, newDN, cleanAttr=True, **ctrlKwds):
        """Specify a new absolute DN for an object"""
        rdn, parent = newDN.split(',', 1)
        return self.modDN(DN, rdn, cleanAttr, parent, **ctrlKwds)

    ## change attributes on an object

    def modify(self, DN, modlist, **ctrlKwds):
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
            controls = self._processCtrlKwds('modify', ctrlKwds, final=True)
            mID = self.sock.sendMessage('modifyRequest', mr, controls)
            logger.info('Sent modify request (ID {0}) for DN {1}'.format(mID, DN))
            return self._successResult(mID, 'modifyResponse')
        else:
            logger.debug('Not sending 0-length modlist for DN {0}'.format(DN))
            return True

    def addAttrs(self, DN, attrsDict, current=None, **ctrlKwds):
        """Add new attribute values to existing object"""
        if current is not None:
            modlist = AddModlist(current, attrsDict)
        elif not self.strictModify:
            current = self.get(DN, list(attrsDict.keys()))
            modlist = AddModlist(current, attrsDict)
        else:
            modlist = Modlist(Mod.ADD, attrsDict)
        return self.modify(DN, modlist, **ctrlKwds)

    def deleteAttrs(self, DN, attrsDict, current=None, **ctrlKwds):
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
        return self.modify(DN, modlist, **ctrlKwds)

    def replaceAttrs(self, DN, attrsDict, **ctrlKwds):
        """Replace all values on given attributes with the passed values

         * Attributes not mentioned in attrsDict are not touched
         * Attributes will be created if they do not exist
         * Specifying a 0-length entry will delete all values for that attribute
        """
        return self.modify(DN, Modlist(Mod.REPLACE, attrsDict), **ctrlKwds)

    ## Extension methods

    def sendExtendedRequest(self, OID, value=None, **kwds):
        """Send an extended request, returns instance of ExtendedResponseHandle

         This is mainly meant to be called by other built-in methods and client extensions. Requires
         handling of raw pyasn1 protocol objects
        """
        if OID not in self.rootDSE.getAttr('supportedExtension'):
            raise LDAPSupportError('Extended operation is not supported by the server')
        xr = ExtendedRequest()
        xr.setComponentByName('requestName', RequestName(OID))
        if value is not None:
            if not isinstance(value, six.string_types):
                raise TypeError('extendedRequest value must be string')
            xr.setComponentByName('requestValue', RequestValue(value))
        controls = self._processCtrlKwds('ext', kwds)
        mID = self.sock.sendMessage('extendedReq', xr, controls)
        logger.info('Sent extended request ID={0} OID={1}'.format(mID, OID))
        return ExtendedResponseHandle(ldapConn=self, mID=mID, **kwds)

    def whoAmI(self, **ctrlKwds):
        handle = self.sendExtendedRequest(LDAP.OID_WHOAMI, requireSuccess=True, **ctrlKwds)
        xr = handle.recvResponse()
        return six.text_type(xr.getComponentByName('responseValue'))

    def startTLS(self, verify=None, caFile=None, caPath=None, caData=None):
        if self.sock.startedTLS:
            raise LDAPError('TLS layer already installed')
        if verify is None:
            verify = self.sslVerify
        if caFile is None:
            caFile = self.sslCAFile
        if caPath is None:
            caPath = self.sslCAPath
        if caData is None:
            caData = self.sslCAData
        handle = self.sendExtendedRequest(LDAP.OID_STARTTLS, requireSuccess=True)
        xr = handle.recvResponse()
        self.sock._startTLS(verify, caFile, caPath, caData)
        self.refreshRootDSE()
        logger.info('StartTLS complete')

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


class ResponseHandle(object):
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
            logger.info('Abandoning ID={0}'.format(self.messageID))
            self.ldapConn.sock.sendMessage('abandonRequest', AbandonRequest(self.messageID))
            self.abandoned = True
            self.ldapConn.sock.abandonedMIDs.append(self.messageID)
        else:
            logger.debug('ID={0} already abandoned'.format(self.messageID))


class SearchResultHandle(ResponseHandle):
    def __init__(self, ldapConn, messageID, fetchResultRefs, followReferrals, objKwds):
        self.ldapConn = ldapConn
        self.messageID = messageID
        self.fetchResultRefs = fetchResultRefs
        self.followReferrals = followReferrals
        self.objKwds = objKwds
        self.done = False
        self.abandoned = False

    def __iter__(self):
        if self.abandoned:
            logger.debug('ID={0} has been abandoned'.format(self.messageID))
            raise StopIteration()
        for msg in self.ldapConn.sock.recvMessages(self.messageID):
            try:
                mID, entry = _unpack('searchResEntry', msg)
                DN = six.text_type(entry.getComponentByName('objectName'))
                attrs = {}
                _attrs = entry.getComponentByName('attributes')
                for i in range(0, len(_attrs)):
                    _attr = _attrs.getComponentByPosition(i)
                    attrType = six.text_type(_attr.getComponentByName('type'))
                    vals = _attr.getComponentByName('vals')
                    attrs[attrType] = _seqToList(vals)
                logger.debug('Got search result entry (ID {0}) {1}'.format(mID, DN))
                yield self.ldapConn.obj(DN, attrs, **self.objKwds)
            except UnexpectedResponseType:
                try:
                    mID, resobj = _unpack('searchResDone', msg)
                    self.done = True
                    res = resobj.getComponentByName('resultCode')
                    if res == RESULT_success or res == RESULT_noSuchObject:
                        logger.debug('Got all search results for ID={0}, result is {1}'.format(
                            mID, repr(res)
                        ))
                        raise StopIteration()
                    elif res == RESULT_referral:
                        if self.followReferrals:
                            logger.info('Following referral for ID={0}'.format(mID))
                            ref = resobj.getComponentByName('referral')
                            URIs = _seqToList(ref)
                            for obj in SearchReferenceHandle(URIs, self.objKwds).fetch():
                                yield obj
                        else:
                            logger.debug('Ignoring referral for ID={0}'.format(mID))
                            raise StopIteration()
                    else:
                        raise LDAPError('Got {0} for search results (ID {1})'.format(
                            repr(res), mID
                        ))
                except UnexpectedResponseType:
                    mID, resref = _unpack('searchResRef', ldapMessage)
                    URIs = _seqToList(resref)
                    logger.debug('Got search result reference (ID {0}) to: {1}'.format(
                        mID, ' | '.join(URIs)
                    ))
                    ref = SearchReferenceHandle(URIs, self.objKwds)
                    if self.fetchResultRefs:
                        for obj in ref.fetch():
                            yield obj
                    else:
                        yield ref


class ExtendedResponseHandle(ResponseHandle):
    """Obtains rfc4511.ExtendedResponse or rfc4511.IntermediateResponse instances from the server
     for a particular message ID
    """

    def __init__(self, mID, ldapConn, requireSuccess=False):
        self.messageID = mID
        self.ldapConn = ldapConn
        self.requireSuccess = requireSuccess
        self._recvr = ldapConn.sock.recvMessages(mID)
        self.done = False
        self.abandoned = False

    def _handleMsg(self, lm):
        try:
            mID, ir = _unpack('intermediateResponse', lm)
            resName = ir.getComponentByName('responseName')
            logger.debug('Got name={0} intermediate response for ID={1}'.format(resName, mID))
            return ir
        except UnexpectedResponseType:
            mID, xr = _unpack('extendedResp', lm)
            self.done = True
            resName = xr.getComponentByName('responseName')
            logger.debug('Got name={0} extended response for ID={1}'.format(resName, mID))
            if self.requireSuccess:
                res = xr.getComponentByName('resultCode')
                if res != RESULT_success:
                    raise LDAPError('Got {0} for ID={1}'.format(repr(res), mID))
            return xr

    def __iter__(self):
        for lm in self._recvr:
            yield self._handleMsg(lm)
            if self.done:
                break

    def recvResponse(self):
        return self._handleMsg(next(self._recvr))


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
        if self.scheme == '':
            self.scheme = 'ldap'
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

    def search(self, **kwds):
        """Perform the search operation described by the parsed URI

         First opens a new connection with connection reuse disabled, then performs the search, and
         unbinds the connection. Server must allow anonymous read.
        """
        ldap = LDAP(self.hostURI, reuseConnection=False)
        ret = ldap.search(self.DN, self.scope, filter=self.filter, attrs=self.attrs, **kwds)
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


class Control(object):
    # Controls are exposed by allowing additional keyword arguments on particular methods
    method = ''  # name of the method which this control is used with
    keyword = '' # keyword argument name
    OID = ''     # OID of the control

    def prepare(self, ctrlValue, criticality):
        """Accepts string controlValue and returns an rfc4511.Control instance"""
        c = _Control()
        c.setComponentByName('controlType', LDAPOID(self.OID))
        c.setComponentByName('criticality', Criticality(criticality))
        if not isinstance(ctrlValue, six.string_types):
            raise TypeError('Control value must be string')
        if len(ctrlValue) > 0:
            c.setComponentByName('controlValue', ControlValue(ctrlValue))
        return c

    @staticmethod
    def REGISTER_GENERIC(method, keyword, OID):
        """Call this to define a simple control that only needs a string controlValue"""
        c = Control()
        c.method = method
        c.keyword = keyword
        c.OID = OID
        LDAP.REGISTER_CONTROL(c)

    @staticmethod
    def REGISTER(cls):
        """If extending the Control class (to accept complex controlValues), use this as a class
         decorator
        """
        if issubclass(cls, Control):
            if not cls.method:
                raise ValueError('no method set on class {0}'.format(cls.__name__))
            if not cls.keyword:
                raise ValueError('no keyword set on class {0}'.format(cls.__name__))
            if not cls.OID:
                raise ValueError('no OID set on class {0}'.format(cls.__name__))
            LDAP.REGISTER_CONTROL(cls())
            return cls
        else:
            raise TypeError('class {0} must be subclass of Control'.format(cls.__name__))


class critical(object):
    """used to mark controls with criticality"""
    def __init__(self, value):
        self.value = value


class optional(object):
    """used to mark controls as not having criticality"""
    def __init__(self, value):
        self.value = value
