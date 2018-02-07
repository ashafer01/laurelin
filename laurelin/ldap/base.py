"""Contains base classes for laurelin.ldap"""
from __future__ import absolute_import

from . import controls
from . import rfc4511
from .constants import Scope, DerefAliases
from .exceptions import *
from .extensible import Extensible
from .filter import parse as parse_filter
from .ldapobject import LDAPObject
from .modify import (
    Mod,
    Modlist,
    AddModlist,
    DeleteModlist,
)
from .net import LDAPSocket
from .protoutils import (
    V3,
    EMPTY_DN,
    RESULT_saslBindInProgress,
    RESULT_success,
    RESULT_noSuchObject,
    RESULT_compareTrue,
    RESULT_compareFalse,
    RESULT_referral,
    unpack,
    seq_to_list,
    getStringComponent,
)
from .validation import getValidators

import logging
import re
import six
import warnings
from six.moves import range
from six.moves.urllib.parse import urlparse
from warnings import warn

logger = logging.getLogger('laurelin.ldap')
logger.addHandler(logging.NullHandler())
logger.setLevel(logging.DEBUG)  # set to DEBUG to allow handler levels full discretion


_showwarning_default = warnings.showwarning


def _showwarning_disabled(message, category, filename, lineno, file=None, line=None):
    if not issubclass(category, LDAPWarning):
        _showwarning_default(message, category, filename, lineno, file, line)


def _showwarning_log(message, category, filename, lineno, file=None, line=None):
    if issubclass(category, LDAPWarning):
        logger.warning('{0}: {1}'.format(category.__name__, message))
    else:
        _showwarning_default(message, category, filename, lineno, file, line)


# for storing reusable sockets
_sockets = {}


class LDAP(Extensible):
    """Provides the connection to the LDAP DB"""

    # global defaults
    DEFAULT_SERVER = 'ldap://localhost'
    DEFAULT_BASE_DN = None
    DEFAULT_FILTER = '(objectClass=*)'
    DEFAULT_DEREF_ALIASES = DerefAliases.ALWAYS
    DEFAULT_SEARCH_TIMEOUT = 0
    DEFAULT_CONNECT_TIMEOUT = 5
    DEFAULT_STRICT_MODIFY = False
    DEFAULT_REUSE_CONNECTION = True
    DEFAULT_SSL_VERIFY = True
    DEFAULT_SSL_CA_FILE = None
    DEFAULT_SSL_CA_PATH = None
    DEFAULT_SSL_CA_DATA = None
    DEFAULT_FETCH_RESULT_REFS = True
    DEFAULT_FOLLOW_REFERRALS = True
    DEFAULT_SASL_MECH = None
    DEFAULT_SASL_FATAL_DOWNGRADE_CHECK = True
    DEFAULT_CRITICALITY = False
    DEFAULT_SKIP_VALIDATION = False
    DEFAULT_SKIP_VALIDATORS = []

    # spec constants
    NO_ATTRS = '1.1'

    # logging config
    LOG_FORMAT = '[%(asctime)s] %(name)s %(levelname)s : %(message)s'

    # OIDs
    OID_WHOAMI   = '1.3.6.1.4.1.4203.1.11.3'
    OID_STARTTLS = '1.3.6.1.4.1.1466.20037'

    ## logging and warning controls

    @staticmethod
    def enable_logging(level=logging.DEBUG):
        """Enable logging output to stderr"""
        stderr_handler = logging.StreamHandler()
        stderr_handler.setFormatter(logging.Formatter(LDAP.LOG_FORMAT))
        stderr_handler.setLevel(level)
        logger.addHandler(stderr_handler)
        return stderr_handler

    @staticmethod
    def disable_warnings():
        """Prevent all LDAP warnings from being shown - default action for others"""
        warnings.showwarning = _showwarning_disabled

    @staticmethod
    def log_warnings():
        """Log all LDAP warnings rather than showing them - default action for others"""
        warnings.showwarning = _showwarning_log

    @staticmethod
    def default_warnings():
        """Always take the default action for warnings"""
        warnings.showwarning = _showwarning_default

    ## basic methods

    def __enter__(self):
        return self

    def __exit__(self, etype, e, trace):
        self.close()

    def __init__(self, server=None, base_dn=None, reuse_connection=None, connect_timeout=None, search_timeout=None,
                 deref_aliases=None, strict_modify=None, ssl_verify=None, ssl_ca_file=None, ssl_ca_path=None,
                 ssl_ca_data=None, fetch_result_refs=None, default_sasl_mech=None, sasl_fatal_downgrade_check=None,
                 default_criticality=None, follow_referrals=None, skip_validation=None, skip_validators=None):

        # setup
        if server is None:
            server = LDAP.DEFAULT_SERVER
        if base_dn is None:
            base_dn = LDAP.DEFAULT_BASE_DN
        if reuse_connection is None:
            reuse_connection = LDAP.DEFAULT_REUSE_CONNECTION
        if connect_timeout is None:
            connect_timeout = LDAP.DEFAULT_CONNECT_TIMEOUT
        if search_timeout is None:
            search_timeout = LDAP.DEFAULT_SEARCH_TIMEOUT
        if deref_aliases is None:
            deref_aliases = LDAP.DEFAULT_DEREF_ALIASES
        if strict_modify is None:
            strict_modify = LDAP.DEFAULT_STRICT_MODIFY
        if ssl_verify is None:
            ssl_verify = LDAP.DEFAULT_SSL_VERIFY
        if ssl_ca_file is None:
            ssl_ca_file = LDAP.DEFAULT_SSL_CA_FILE
        if ssl_ca_path is None:
            ssl_ca_path = LDAP.DEFAULT_SSL_CA_PATH
        if ssl_ca_data is None:
            ssl_ca_data = LDAP.DEFAULT_SSL_CA_DATA
        if fetch_result_refs is None:
            fetch_result_refs = LDAP.DEFAULT_FETCH_RESULT_REFS
        if default_sasl_mech is None:
            default_sasl_mech = LDAP.DEFAULT_SASL_MECH
        if sasl_fatal_downgrade_check is None:
            sasl_fatal_downgrade_check = LDAP.DEFAULT_SASL_FATAL_DOWNGRADE_CHECK
        if default_criticality is None:
            default_criticality = LDAP.DEFAULT_CRITICALITY
        if follow_referrals is None:
            follow_referrals = LDAP.DEFAULT_FOLLOW_REFERRALS
        if skip_validation is None:
            skip_validation = LDAP.DEFAULT_SKIP_VALIDATION
        if skip_validators is None:
            skip_validators = LDAP.DEFAULT_SKIP_VALIDATORS

        self.default_search_timeout = search_timeout
        self.default_deref_aliases = deref_aliases
        self.default_fetch_result_refs = fetch_result_refs
        self.default_follow_referrals = follow_referrals
        self.default_sasl_mech = default_sasl_mech
        self.default_criticality = default_criticality

        self.strict_modify = strict_modify
        self.sasl_fatal_downgrade_check = sasl_fatal_downgrade_check

        self._tagged_objects = {}
        self._sasl_mechs = None

        self.sock_params = (connect_timeout, ssl_verify, ssl_ca_file, ssl_ca_path, ssl_ca_data)
        self.ssl_verify = ssl_verify
        self.ssl_ca_file = ssl_ca_file
        self.ssl_ca_path = ssl_ca_path
        self.ssl_ca_data = ssl_ca_data

        # connect
        if isinstance(server, six.string_types):
            self.host_uri = server
            if reuse_connection:
                if self.host_uri not in _sockets:
                    _sockets[self.host_uri] = LDAPSocket(self.host_uri, *self.sock_params)
                self.sock = _sockets[self.host_uri]
            else:
                self.sock = LDAPSocket(self.host_uri, *self.sock_params)
            logger.info('Connected to {0} (#{1})'.format(self.host_uri, self.sock.ID))
        elif isinstance(server, LDAPSocket):
            self.sock = server
            self.host_uri = server.uri
            logger.info('Using existing socket {0} (#{1})'.format(self.host_uri, self.sock.ID))
        else:
            raise TypeError('Must supply URI string or LDAPSocket for server')
        self.sock.refcount += 1

        self.refresh_root_dse()
        if base_dn is None:
            if 'defaultNamingContext' in self.root_dse:
                base_dn = self.root_dse['defaultNamingContext'][0]
            else:
                ncs = self.root_dse.getAttr('namingContexts')
                n = len(ncs)
                if n == 0:
                    raise LDAPError('base_dn must be provided - no namingContexts')
                elif n == 1:
                    base_dn = ncs[0]
                else:
                    raise LDAPError('base_dn must be provided - multiple namingContexts')
        self.base_dn = base_dn

        if self.default_sasl_mech is None and self.host_uri.startswith('ldapi:'):
            self.default_sasl_mech = 'EXTERNAL'

        logger.debug('Creating base object for {0}'.format(self.base_dn))
        self.base = self.obj(self.base_dn, relative_search_scope=Scope.SUBTREE)

        # Validation setup
        self.validators = []
        if not skip_validation:
            for validator in getValidators():
                skip = False
                for validatorSpec in skip_validators:
                    if isinstance(validatorSpec, six.string_types):
                        if validator.__class__.__name__ == validatorSpec:
                            skip = True
                            break
                    else:
                        if isinstance(validator, validatorSpec):
                            skip = True
                            break
                if not skip:
                    self.validators.append(validator)

    def refresh_root_dse(self):
        self.root_dse = self.get('', ['*', '+'])
        self._sasl_mechs = self.root_dse.getAttr('supportedSASLMechanisms')

    def _process_ctrl_kwds(self, method, kwds, final=False):
        supported_ctrls = self.root_dse.getAttr('supportedControl')
        default_crit = self.default_criticality
        return controls.processKwds(method, kwds, supported_ctrls, default_crit, final)

    def _success_result(self, message_id, operation):
        """Receive an object from the socket and raise an LDAPError if its not a success result"""
        mid, obj, res_ctrls = unpack(operation, self.sock.recv_one(message_id))
        res = obj.getComponentByName('resultCode')
        if res == RESULT_success:
            logger.debug('LDAP operation (ID {0}) was successful'.format(mid))
            ret = LDAPResponse()
            controls.handleResponse(ret, res_ctrls)
            return ret
        else:
            msg = obj.getComponentByName('diagnosticMessage')
            raise LDAPError('Got {0} for {1} (ID {2}) ({3})'.format(repr(res), operation, mid, msg))

    def simple_bind(self, username='', password='', **ctrl_kwds):
        """Performs a simple bind operation

         Leave arguments as their default (empty strings) to attempt an anonymous simple bind
        """
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.sock.bound:
            raise ConnectionAlreadyBound()

        br = rfc4511.BindRequest()
        br.setComponentByName('version', V3)
        br.setComponentByName('name', rfc4511.LDAPDN(username))
        ac = rfc4511.AuthenticationChoice()
        ac.setComponentByName('simple', rfc4511.Simple(password))
        br.setComponentByName('authentication', ac)

        req_ctrls = self._process_ctrl_kwds('bind', ctrl_kwds, final=True)

        mid = self.sock.send_message('bindRequest', br, req_ctrls)
        logger.debug('Sent bind request (ID {0}) on connection #{1} for {2}'.format(mid, self.sock.ID, username))
        ret = self._success_result(mid, 'bindResponse')
        self.sock.bound = True
        logger.info('Simple bind successful')
        return ret

    def get_sasl_mechs(self):
        """Query root DSE for supported SASL mechanisms"""

        if self._sasl_mechs is None:
            logger.debug('Querying server to find supported SASL mechs')
            o = self.get('', ['supportedSASLMechanisms'])
            self._sasl_mechs = o.getAttr('supportedSASLMechanisms')
            logger.debug('Server supported SASL mechs = {0}'.format(','.join(self._sasl_mechs)))
        return self._sasl_mechs

    def recheck_sasl_mechs(self):
        """Query the root DSE again after performing a SASL bind to check for a downgrade attack"""

        if self._sasl_mechs is None:
            raise LDAPError('SASL mechs have not yet been queried')
        else:
            orig_mechs = set(self._sasl_mechs)
            self._sasl_mechs = None
            self.get_sasl_mechs()
            if orig_mechs != set(self._sasl_mechs):
                msg = 'Supported SASL mechs differ on recheck, possible downgrade attack'
                if self.sasl_fatal_downgrade_check:
                    raise LDAPError(msg)
                else:
                    warn(msg, LDAPWarning)
            else:
                logger.debug('No evidence of downgrade attack')

    def sasl_bind(self, mech=None, **props):
        """Perform a SASL bind operation

         Specify a single standard mechanism string for mech, or leave it as None to negotiate the
         best mutually supported mechanism. Required keyword args are dependent on the mechanism
         chosen.
        """
        if self.sock.unbound:
            raise ConnectionUnbound()
        if self.sock.bound:
            raise ConnectionAlreadyBound()

        req_ctrls = self._process_ctrl_kwds('bind', props)

        mechs = self.get_sasl_mechs()
        if mech is None:
            mech = self.default_sasl_mech
        if mech is not None:
            if mech not in mechs:
                raise LDAPSupportError('SASL mech "{0}" is not supported by the server'.format(mech))
            else:
                mechs = [mech]
        self.sock.sasl_init(mechs, **props)
        logger.debug('Selected SASL mech = {0}'.format(self.sock.sasl_mech))

        challenge_response = None
        while True:
            br = rfc4511.BindRequest()
            br.setComponentByName('version', V3)
            br.setComponentByName('name', EMPTY_DN)
            ac = rfc4511.AuthenticationChoice()
            sasl = rfc4511.SaslCredentials()
            sasl.setComponentByName('mechanism', six.text_type(self.sock.sasl_mech))
            if challenge_response is not None:
                sasl.setComponentByName('credentials', challenge_response)
                challenge_response = None
            ac.setComponentByName('sasl', sasl)
            br.setComponentByName('authentication', ac)

            mid = self.sock.send_message('bindRequest', br, req_ctrls)
            logger.debug('Sent SASL bind request (ID {0}) on connection #{1}'.format(mid, self.sock.ID))

            mid, res, res_ctrls = unpack('bindResponse', self.sock.recv_one(mid))
            status = res.getComponentByName('resultCode')
            if status == RESULT_saslBindInProgress:
                challenge_response = self.sock.sasl_process_auth_challenge(
                    six.text_type(res.getComponentByName('serverSaslCreds')))
                continue
            elif status == RESULT_success:
                logger.info('SASL bind successful')
                logger.debug('Negotiated SASL QoP = {0}'.format(self.sock.sasl_qop))
                self.sock.bound = True
                self.recheck_sasl_mechs()

                ret = LDAPResponse()
                controls.handleResponse(ret, res_ctrls)
                return ret
            else:
                msg = res.getComponentByName('diagnosticMessage')
                raise LDAPError('Got {0} during SASL bind ({1})'.format(repr(status), msg))
        raise LDAPError('Programming error - reached end of saslBind')

    def unbind(self, force=False):
        """Send an unbind request and close the socket"""
        if self.sock.unbound:
            raise ConnectionUnbound()

        self.sock.refcount -= 1
        if force or self.sock.refcount == 0:
            self.sock.send_message('unbindRequest', rfc4511.UnbindRequest())
            self.sock.close()
            self.sock.unbound = True
            logger.info('Unbound on {0} (#{1})'.format(self.sock.uri, self.sock.ID))
            try:
                del _sockets[self.sock.uri]
            except KeyError:
                pass
        else:
            logger.debug('Socket still in use')

    close = unbind

    def tag(self, tag):
        """Get a tagged object"""
        try:
            return self._tagged_objects[tag]
        except KeyError:
            raise TagError('tag {0} does not exist'.format(tag))

    def obj(self, dn, attrs_dict=None, tag=None, *args, **kwds):
        """Factory for LDAPObjects bound to this connection"""
        obj = LDAPObject(dn, attrs_dict=attrs_dict, ldap_conn=self, *args, **kwds)
        if tag is not None:
            if tag in self._tagged_objects:
                raise TagError('tag {0} already exists'.format(tag))
            else:
                self._tagged_objects[tag] = obj
        return obj

    def get(self, dn, attrs=None, **obj_kwds):
        """Get a specific object by DN"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        results = list(self.search(dn, Scope.BASE, attrs=attrs, limit=2, **obj_kwds))
        n = len(results)
        if n == 0:
            raise NoSearchResults()
        elif n > 1:
            raise MultipleSearchResults()
        else:
            return results[0]

    def exists(self, dn):
        """Simply check if a DN exists"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        try:
            self.get(dn, [])
            return True
        except NoSearchResults:
            return False
        except MultipleSearchResults:
            return True

    def search(self, base_dn, scope=Scope.SUBTREE, filter=None, attrs=None, search_timeout=None, limit=0,
               deref_aliases=None, attrs_only=False, fetch_result_refs=None, follow_referrals=None, **kwds):
        """Send search and iterate results until we get a SearchResultDone

         Yields instances of LDAPObject and possibly SearchReferenceHandle, if any result
         references are returned from the server, and the fetch_result_refs keyword arg is False.
        """
        if self.sock.unbound:
            raise ConnectionUnbound()

        if filter is None:
            filter = LDAP.DEFAULT_FILTER
        if search_timeout is None:
            search_timeout = self.default_search_timeout
        if deref_aliases is None:
            deref_aliases = self.default_deref_aliases
        if fetch_result_refs is None:
            fetch_result_refs = self.default_fetch_result_refs
        if follow_referrals is None:
            follow_referrals = self.default_follow_referrals
        req = rfc4511.SearchRequest()
        req.setComponentByName('baseObject', rfc4511.LDAPDN(base_dn))
        req.setComponentByName('scope', scope)
        req.setComponentByName('derefAliases', deref_aliases)
        req.setComponentByName('sizeLimit', rfc4511.Integer0ToMax(limit))
        req.setComponentByName('timeLimit', rfc4511.Integer0ToMax(search_timeout))
        req.setComponentByName('typesOnly', rfc4511.TypesOnly(attrs_only))
        req.setComponentByName('filter', parse_filter(filter))

        _attrs = rfc4511.AttributeSelection()
        i = 0
        if attrs is None:
            attrs = ['*']
        if not isinstance(attrs, list):
            attrs = [attrs]
        for desc in attrs:
            _attrs.setComponentByPosition(i, rfc4511.LDAPString(desc))
            i += 1
        req.setComponentByName('attributes', _attrs)

        # check here because we need to do a search to get the root DSE, which is required by
        # _processCtrlKwds, other methods don't need to check
        if kwds:
            ctrls = self._process_ctrl_kwds('search', kwds)
        else:
            ctrls = None

        mid = self.sock.send_message('searchRequest', req, ctrls)
        logger.info('Sent search request (ID {0}): base_dn={1}, scope={2}, filter={3}'.format(
                    mid, base_dn, scope, filter))
        return SearchResultHandle(self, mid, fetch_result_refs, follow_referrals, kwds)

    def compare(self, dn, attr, value, **ctrl_kwds):
        """Perform a compare operation, returning boolean"""
        if self.sock.unbound:
            raise ConnectionUnbound()

        cr = rfc4511.CompareRequest()
        cr.setComponentByName('entry', rfc4511.LDAPDN(six.text_type(dn)))
        ava = rfc4511.AttributeValueAssertion()
        ava.setComponentByName('attributeDesc', rfc4511.AttributeDescription(six.text_type(attr)))
        ava.setComponentByName('assertionValue', rfc4511.AssertionValue(six.text_type(value)))
        cr.setComponentByName('ava', ava)

        req_ctrls = self._process_ctrl_kwds('compare', ctrl_kwds, final=True)

        message_id = self.sock.send_message('compareRequest', cr, req_ctrls)
        logger.info('Sent compare request (ID {0}): {1} ({2} = {3})'.format(message_id, dn, attr, value))
        msg = self.sock.recv_one(message_id)
        mid, res, res_ctrls = unpack('compareResponse', msg)
        res = res.getComponentByName('resultCode')
        if res == RESULT_compareTrue:
            logger.debug('Compared True (ID {0})'.format(mid))
            compare_result = True
        elif res == RESULT_compareFalse:
            logger.debug('Compared False (ID {0})'.format(mid))
            compare_result = False
        else:
            raise LDAPError('Got compare result {0} (ID {1})'.format(repr(res), mid))
        ret = CompareResponse(compare_result)
        controls.handleResponse(ret, res_ctrls)
        return ret

    def add(self, dn, attrs_dict, **kwds):
        """Add new object and return corresponding LDAPObject on success"""
        if self.sock.unbound:
            raise ConnectionUnbound()

        if not isinstance(dn, six.string_types):
            raise TypeError('DN must be string type')
        if not isinstance(attrs_dict, dict):
            raise TypeError('attrs_dict must be dict')

        obj = self.obj(dn, attrs_dict, **kwds)

        self.validate_object(obj)

        ar = rfc4511.AddRequest()
        ar.setComponentByName('entry', rfc4511.LDAPDN(dn))
        al = rfc4511.AttributeList()
        i = 0
        for attr_type, attr_vals in six.iteritems(attrs_dict):
            attr = rfc4511.Attribute()
            attr.setComponentByName('type', rfc4511.AttributeDescription(attr_type))
            vals = rfc4511.Vals()
            j = 0
            for val in attr_vals:
                vals.setComponentByPosition(j, rfc4511.AttributeValue(val))
                j += 1
            attr.setComponentByName('vals', vals)
            al.setComponentByPosition(i, attr)
            i += 1
        ar.setComponentByName('attributes', al)

        req_ctrls = self._process_ctrl_kwds('add', kwds)

        mid = self.sock.send_message('addRequest', ar, req_ctrls)
        logger.info('Sent add request (ID {0}) for DN {1}'.format(mid, dn))

        lm = self.sock.recv_one(mid)
        mid, res, res_ctrls = unpack('addResponse', lm)
        res = res.getComponentByName('resultCode')
        if res == RESULT_success:
            logger.debug('LDAP operation (ID {0}) was successful'.format(mid))
            controls.handleResponse(obj, res_ctrls)
            return obj
        else:
            raise LDAPError('Got {0} for add (ID {1})'.format(repr(res), mid))

    ## search+add patterns

    def add_or_mod_add_if_exists(self, dn, attrs_dict):
        """Add object if it doesn't exist, otherwise addAttrs

         * If the object at DN exists, perform an add modification using the attrs dictionary.
           Otherwise, create the object using the attrs dictionary.
         * This ensures that, for the attributes mentioned in attrs, AT LEAST those values will
           exist on the given DN, regardless of prior state of the DB.
         * Always returns an LDAPObject corresponding to the final state of the DB
        """
        try:
            cur = self.get(dn)
            cur.add_attrs(attrs_dict, )
            return cur
        except NoSearchResults:
            return self.add(dn, attrs_dict)

    def add_or_mod_replace_if_exists(self, dn, attrs_dict):
        """Add object if it doesn't exist, otherwise replaceAttrs

         * If the object at DN exists, perform a replace modification using the attrs dictionary
           Otherwise, create the object using the attrs dictionary
         * This ensures that, for the attributes mentioned in attrs, ONLY those values will exist on
           the given DN regardless of prior state of the DB.
         * Always returns an LDAPObject corresponding to the final state of the DB
        """
        try:
            cur = self.get(dn)
            cur.replace_attrs(attrs_dict, )
            return cur
        except NoSearchResults:
            return self.add(dn, attrs_dict)

    def add_if_not_exists(self, dn, attrs_dict):
        """Add object if it doesn't exist

         * Gets and returns the object at DN if it exists, otherwise create the object using the
           attrs dictionary
         * Always returns an LDAPObject corresponding to the final state of the DB
        """
        try:
            cur = self.get(dn)
            logger.debug('Object {0} already exists on addIfNotExists'.format(dn))
            return cur
        except NoSearchResults:
            return self.add(dn, attrs_dict)

    ## delete an object

    def delete(self, dn, **ctrl_kwds):
        """Delete an object"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        controls = self._process_ctrl_kwds('delete', ctrl_kwds, final=True)
        mid = self.sock.send_message('delRequest', rfc4511.DelRequest(dn), controls)
        logger.info('Sent delete request (ID {0}) for DN {1}'.format(mid, dn))
        return self._success_result(mid, 'delResponse')

    ## change object DN

    def mod_dn(self, dn, new_rdn, clean_attr=True, new_parent=None, **ctrl_kwds):
        """Exposes all options of the protocol-level rfc4511.ModifyDNRequest"""
        if self.sock.unbound:
            raise ConnectionUnbound()
        mdr = rfc4511.ModifyDNRequest()
        mdr.setComponentByName('entry', rfc4511.LDAPDN(dn))
        mdr.setComponentByName('newrdn', rfc4511.RelativeLDAPDN(new_rdn))
        mdr.setComponentByName('deleteoldrdn', clean_attr)
        if new_parent is not None:
            mdr.setComponentByName('newSuperior', rfc4511.NewSuperior(new_parent))
        controls = self._process_ctrl_kwds('modDN', ctrl_kwds, final=True)
        mid = self.sock.send_message('modDNRequest', mdr, controls)
        logger.info('Sent modDN request (ID {0}) for DN {1} newRDN="{2}" newParent="{3}"'.format(
                    mid, dn, new_rdn, new_parent))
        return self._success_result(mid, 'modDNResponse')

    def rename(self, dn, new_rdn, clean_attr=True, **ctrl_kwds):
        """Specify a new RDN for an object without changing its location in the tree"""
        return self.mod_dn(dn, new_rdn, clean_attr, **ctrl_kwds)

    def move(self, dn, new_dn, clean_attr=True, **ctrl_kwds):
        """Specify a new absolute DN for an object"""
        rdn, parent = re.split(r'(?<!\\),', new_dn, 1)
        return self.mod_dn(dn, rdn, clean_attr, parent, **ctrl_kwds)

    ## change attributes on an object

    def modify(self, dn, modlist, current=None, **ctrl_kwds):
        """Perform a series of modify operations on an object

         modlist must be a list of laurelin.ldap.modify.Mod instances
        """
        if len(modlist) > 0:
            if self.sock.unbound:
                raise ConnectionUnbound()

            self.validate_modify(dn, modlist, current)

            mr = rfc4511.ModifyRequest()
            mr.setComponentByName('object', rfc4511.LDAPDN(dn))
            cl = rfc4511.Changes()
            i = 0
            logger.debug('Modifying DN {0}'.format(dn))
            for mod in modlist:
                logger.debug('> {0}'.format(mod))

                c = rfc4511.Change()
                c.setComponentByName('operation', mod.op)
                pa = rfc4511.PartialAttribute()
                pa.setComponentByName('type', rfc4511.AttributeDescription(mod.attr))
                vals = rfc4511.Vals()
                j = 0
                for v in mod.vals:
                    vals.setComponentByPosition(j, rfc4511.AttributeValue(v))
                    j += 1
                pa.setComponentByName('vals', vals)
                c.setComponentByName('modification', pa)

                cl.setComponentByPosition(i, c)
                i += 1
            mr.setComponentByName('changes', cl)
            controls = self._process_ctrl_kwds('modify', ctrl_kwds, final=True)
            mid = self.sock.send_message('modifyRequest', mr, controls)
            logger.info('Sent modify request (ID {0}) for DN {1}'.format(mid, dn))
            return self._success_result(mid, 'modifyResponse')
        else:
            logger.debug('Not sending 0-length modlist for DN {0}'.format(dn))
            return LDAPResponse()

    def add_attrs(self, dn, attrs_dict, current=None, **ctrl_kwds):
        """Add new attribute values to existing object"""
        if current is not None:
            modlist = AddModlist(current, attrs_dict)
        elif not self.strict_modify:
            current = self.get(dn, list(attrs_dict.keys()))
            modlist = AddModlist(current, attrs_dict)
        else:
            modlist = Modlist(Mod.ADD, attrs_dict)
        return self.modify(dn, modlist, current, **ctrl_kwds)

    def delete_attrs(self, dn, attrs_dict, current=None, **ctrl_kwds):
        """Delete specific attribute values from dictionary

         Specifying a 0-length entry will delete all values
        """
        if current is not None:
            modlist = DeleteModlist(current, attrs_dict)
        elif not self.strict_modify:
            current = self.get(dn, list(attrs_dict.keys()))
            modlist = DeleteModlist(current, attrs_dict)
        else:
            modlist = Modlist(Mod.DELETE, attrs_dict)
        return self.modify(dn, modlist, current, **ctrl_kwds)

    def replace_attrs(self, dn, attrs_dict, current=None, **ctrl_kwds):
        """Replace all values on given attributes with the passed values

         * Attributes not mentioned in attrsDict are not touched
         * Attributes will be created if they do not exist
         * Specifying a 0-length entry will delete all values for that attribute
        """

        # Only query for the current object if there are validators present and
        # strict modify is disabled
        if current is None and self.validators and not self.strict_modify:
            current = self.get(dn, list(attrs_dict.keys()))

        return self.modify(dn, Modlist(Mod.REPLACE, attrs_dict), current, **ctrl_kwds)

    ## Extension methods

    def send_extended_request(self, oid, value=None, **kwds):
        """Send an extended request, returns instance of ExtendedResponseHandle

         This is mainly meant to be called by other built-in methods and client extensions. Requires
         handling of raw pyasn1 protocol objects
        """
        if oid not in self.root_dse.getAttr('supportedExtension'):
            raise LDAPSupportError('Extended operation is not supported by the server')
        xr = rfc4511.ExtendedRequest()
        xr.setComponentByName('requestName', rfc4511.RequestName(oid))
        if value is not None:
            if not isinstance(value, six.string_types):
                raise TypeError('extendedRequest value must be string')
            xr.setComponentByName('requestValue', rfc4511.RequestValue(value))
        req_ctrls = self._process_ctrl_kwds('ext', kwds)
        mid = self.sock.send_message('extendedReq', xr, req_ctrls)
        logger.info('Sent extended request ID={0} OID={1}'.format(mid, oid))
        return ExtendedResponseHandle(mid=mid, ldap_conn=self)

    def who_am_i(self, **ctrl_kwds):
        handle = self.send_extended_request(LDAP.OID_WHOAMI, requireSuccess=True, **ctrl_kwds)
        xr, res_ctrls = handle.recv_response()
        return six.text_type(xr.getComponentByName('responseValue'))

    def start_tls(self, verify=None, ca_file=None, ca_path=None, ca_data=None):
        if self.sock.started_tls:
            raise LDAPError('TLS layer already installed')
        if verify is None:
            verify = self.ssl_verify
        if ca_file is None:
            ca_file = self.ssl_ca_file
        if ca_path is None:
            ca_path = self.ssl_ca_path
        if ca_data is None:
            ca_data = self.ssl_ca_data
        handle = self.send_extended_request(LDAP.OID_STARTTLS, requireSuccess=True)
        handle.recv_response()
        self.sock.start_tls(verify, ca_file, ca_path, ca_data)
        self.refresh_root_dse()
        logger.info('StartTLS complete')

    ## validation methods

    def _run_validation(self, method, *args):
        for validator in self.validators:
            try:
                getattr(validator, method)(*args)
            except AttributeError:
                pass

    def validate_object(self, obj, write=True):
        self._run_validation('validateObject', obj, write)

    def validate_modify(self, dn, modlist, current=None):
        self._run_validation('validateModify', dn, modlist, current)

    ## misc

    def process_ldif(self, ldif_str):
        """Process a basic LDIF

         TODO: full RFC 2849 implementation
        """
        ldif_lines = ldif_str.splitlines()
        if not ldif_lines[0].startswith('dn:'):
            raise ValueError('Missing dn')
        dn = ldif_lines[0][3:].strip()
        if not ldif_lines[1].startswith('changetype:'):
            raise ValueError('Missing changetype')
        changetype = ldif_lines[1][11:].strip()

        if changetype == 'add':
            attrs = {}
            for line in ldif_lines[2:]:
                attr, val = line.split(':', 1)
                if attr not in attrs:
                    attrs[attr] = []
                attrs[attr].append(val)
            return self.add(dn, attrs)
        elif changetype == 'delete':
            return self.delete(dn)
        elif changetype == 'modify':
            mod_op = None
            mod_attr = None
            vals = []
            modlist = []
            for line in ldif_lines[2:]:
                if mod_op is None:
                    _mod_op, _mod_attr = line.split(':')
                    mod_op = Mod.string(_mod_op)
                    mod_attr = _mod_attr.strip()
                    vals = []
                elif line == '-':
                    if mod_op == 'add' and len(vals) == 0:
                        raise ValueError('no attribute values to add')
                    modlist += Modlist(mod_op, {mod_attr: vals})
                else:
                    if line.startswith(mod_attr):
                        vals.append(line[len(mod_attr)+1:].strip())
                    else:
                        raise ValueError('Unexpected attribute')
            return self.modify(dn, modlist)
        else:
            raise ValueError('changetype {0} unknown/not yet implemented'.format(changetype))


class LDAPResponse(object):
    """Empty object for storing response control values"""
    pass


class CompareResponse(LDAPResponse):
    def __init__(self, compare_result):
        self.compare_result = compare_result

    def __bool__(self):
        return self.compare_result


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
            logger.info('Abandoning ID={0}'.format(self.message_id))
            self.ldap_conn.sock.send_message('abandonRequest', rfc4511.AbandonRequest(self.message_id))
            self.abandoned = True
            self.ldap_conn.sock.abandonedMIDs.append(self.message_id)
        else:
            logger.debug('ID={0} already abandoned'.format(self.message_id))


class SearchResultHandle(ResponseHandle):
    def __init__(self, ldap_conn, message_id, fetch_result_refs, follow_referrals, obj_kwds):
        self.ldap_conn = ldap_conn
        self.message_id = message_id
        self.fetch_result_refs = fetch_result_refs
        self.follow_referrals = follow_referrals
        self.obj_kwds = obj_kwds
        self.done = False
        self.abandoned = False

    def __iter__(self):
        if self.abandoned:
            logger.debug('ID={0} has been abandoned'.format(self.message_id))
            raise StopIteration()
        for msg in self.ldap_conn.sock.recv_messages(self.message_id):
            try:
                mid, entry, res_ctrls = unpack('searchResEntry', msg)
                dn = getStringComponent(entry, 'objectName')
                attrs = {}
                _attrs = entry.getComponentByName('attributes')
                for i in range(0, len(_attrs)):
                    _attr = _attrs.getComponentByPosition(i)
                    attr_type = six.text_type(_attr.getComponentByName('type'))
                    vals = _attr.getComponentByName('vals')
                    attrs[attr_type] = seq_to_list(vals)
                logger.debug('Got search result entry (ID {0}) {1}'.format(mid, dn))
                ret = self.ldap_conn.obj(dn, attrs, **self.obj_kwds)
                controls.handleResponse(ret, res_ctrls)
                yield ret
            except UnexpectedResponseType:
                try:
                    mid, resobj, res_ctrls = unpack('searchResDone', msg)
                    self.done = True
                    res = resobj.getComponentByName('resultCode')
                    if res == RESULT_success or res == RESULT_noSuchObject:
                        logger.debug('Got all search results for ID={0}, result is {1}'.format(
                            mid, repr(res)
                        ))
                        controls.handleResponse(self, res_ctrls)
                        raise StopIteration()
                    elif res == RESULT_referral:
                        if self.follow_referrals:
                            logger.info('Following referral for ID={0}'.format(mid))
                            ref = resobj.getComponentByName('referral')
                            uris = seq_to_list(ref)
                            for obj in SearchReferenceHandle(uris, self.obj_kwds).fetch():
                                yield obj
                        else:
                            logger.debug('Ignoring referral for ID={0}'.format(mid))
                            raise StopIteration()
                    else:
                        raise LDAPError('Got {0} for search results (ID {1})'.format(repr(res), mid))
                except UnexpectedResponseType:
                    mid, resref, res_ctrls = unpack('searchResRef', msg)
                    s = seq_to_list(resref)
                    logger.debug('Got search result reference (ID {0}) to: {1}'.format(mid, ' | '.join(s)))
                    ref = SearchReferenceHandle(s, self.obj_kwds)
                    if self.fetch_result_refs:
                        if res_ctrls:
                            warn('Unhandled response controls on searchResRef message', LDAPWarning)
                        for obj in ref.fetch():
                            yield obj
                    else:
                        controls.handleResponse(ref, res_ctrls)
                        yield ref


class ExtendedResponseHandle(ResponseHandle):
    """Obtains rfc4511.ExtendedResponse or rfc4511.IntermediateResponse instances from the server
     for a particular message ID
    """

    def __init__(self, mid, ldap_conn, require_success=False):
        self.message_id = mid
        self.ldap_conn = ldap_conn
        self.require_success = require_success
        self._recvr = ldap_conn.sock.recv_messages(mid)
        self.done = False
        self.abandoned = False

    def _handle_msg(self, lm):
        try:
            mid, ir, res_ctrls = unpack('intermediateResponse', lm)
            res_name = ir.getComponentByName('responseName')
            logger.debug('Got name={0} intermediate response for ID={1}'.format(res_name, mid))
            return ir, res_ctrls
        except UnexpectedResponseType:
            mid, xr, res_ctrls = unpack('extendedResp', lm)
            self.done = True
            res_name = getStringComponent(xr, 'responseName')
            logger.debug('Got name={0} extended response for ID={1}'.format(res_name, mid))
            if self.require_success:
                res = xr.getComponentByName('resultCode')
                if res != RESULT_success:
                    raise LDAPError('Got {0} for ID={1}'.format(repr(res), mid))
            return xr, res_ctrls

    def __iter__(self):
        for lm in self._recvr:
            yield self._handle_msg(lm)
            if self.done:
                break

    def recv_response(self):
        return self._handle_msg(next(self._recvr))


class LDAPURI(object):
    """Represents a parsed LDAP URI as specified in RFC4516

     Attributes:
     * scheme   - urlparse standard
     * netloc   - urlparse standard
     * host_uri  - scheme://netloc for use with LDAPSocket
     * dn       - string
     * attrs    - list
     * scope    - one of the Scope.* constants
     * filter   - string
     * starttls - bool

     Supported extensions:
     * "StartTLS"
    """
    def __init__(self, uri):
        self._orig = uri
        parsed_uri = urlparse(uri)
        self.scheme = parsed_uri.scheme
        if self.scheme == '':
            self.scheme = 'ldap'
        self.netloc = parsed_uri.netloc
        self.host_uri = '{0}://{1}'.format(self.scheme, self.netloc)
        self.dn = parsed_uri.path
        params = parsed_uri.query.split('?')
        nparams = len(params)
        if (nparams > 0) and (len(params[0]) > 0):
            self.attrs = params[0].split(',')
        else:
            self.attrs = ['*']
        if (nparams > 1) and (len(params[1]) > 0):
            self.scope = Scope.string(params[1])
        else:
            self.scope = Scope.BASE
        if (nparams > 2) and (len(params[2]) > 0):
            self.filter = params[2]
        else:
            self.filter = LDAP.DEFAULT_FILTER
        if (nparams > 3) and (len(params[3]) > 0):
            extensions = params[3].split(',')
            for ext in extensions:
                if ext.startswith('!'):
                    critical = True
                    ext = ext[1:]
                else:
                    critical = False
                if ext == 'StartTLS':
                    self.starttls = True
                else:
                    if critical:
                        raise LDAPError('Unsupported critical URI extension {0}'.format(ext))
                    else:
                        warn('Unsupported URI extension {0}'.format(ext), LDAPWarning)
        else:
            self.starttls = False

    def search(self, **kwds):
        """Perform the search operation described by the parsed URI

         First opens a new connection with connection reuse disabled, then performs the search, and
         unbinds the connection. Server must allow anonymous read.
        """
        ldap = LDAP(self.host_uri, reuse_connection=False)
        if self.starttls:
            ldap.start_tls()
        ret = ldap.search(self.dn, self.scope, filter=self.filter, attrs=self.attrs, **kwds)
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
                warn('Error connecting to URI {0} ({1})'.format(uri, e.message), LDAPWarning)
        raise LDAPError('Could not complete reference URI search with any supplied URIs')
