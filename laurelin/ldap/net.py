"""Provides protocol-level interface for low-level sockets"""

from __future__ import absolute_import
import ssl
import logging
from glob import glob
from socket import create_connection, socket, AF_UNIX, error as SocketError
from six.moves.urllib.parse import unquote
from collections import deque
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.error import SubstrateUnderrunError
from puresasl.client import SASLClient

from .rfc4511 import LDAPMessage, MessageID, ProtocolOp
from .exceptions import LDAPError, LDAPSASLError, LDAPConnectionError

_next_sock_id = 0
logger = logging.getLogger(__name__)


class LDAPSocket(object):
    """Holds a connection to an LDAP server"""

    RECV_BUFFER = 4096

    # For ldapi:/// try to connect to these socket files in order
    # Globs must match exactly one result
    LDAPI_SOCKET_PATHS = ['/var/run/ldapi', '/var/run/slapd/ldapi', '/var/run/slapd-*.socket']

    def __init__(self, host_uri, connect_timeout=5, ssl_verify=True, ssl_ca_file=None, ssl_ca_path=None,
                 ssl_ca_data=None):

        self._prop_init(connect_timeout)
        self._uri_connect(host_uri, ssl_verify, ssl_ca_file, ssl_ca_path, ssl_ca_data)

    def _prop_init(self, connect_timeout=5):
        # get socket ID number
        global _next_sock_id
        self.ID = _next_sock_id
        _next_sock_id += 1

        # misc init
        self._message_queues = {}
        self._next_message_id = 1
        self._sasl_client = None

        self.refcount = 0
        self.bound = False
        self.unbound = False
        self.abandoned_mids = []
        self.started_tls = False
        self.connect_timeout = connect_timeout

    def _parse_uri(self, host_uri):
        # parse host_uri
        parts = host_uri.split('://')
        if len(parts) == 1:
            netloc = unquote(parts[0])
            if netloc[0] == '/':
                scheme = 'ldapi'
            else:
                scheme = 'ldap'
        elif len(parts) == 2:
            scheme = parts[0]
            netloc = unquote(parts[1])
        else:
            raise LDAPError('Invalid host_uri')
        self.uri = '{0}://{1}'.format(scheme, netloc)
        return scheme, netloc

    def _uri_connect(self, host_uri, ssl_verify, ssl_ca_file, ssl_ca_path, ssl_ca_data):
        # connect
        scheme, netloc = self._parse_uri(host_uri)
        logger.info('Connecting to {0} on #{1}'.format(self.uri, self.ID))
        if scheme == 'ldap':
            self._inet_connect(netloc, 389)
        elif scheme == 'ldaps':
            self._inet_connect(netloc, 636)
            self._start_tls(ssl_verify, ssl_ca_file, ssl_ca_path, ssl_ca_data)
            logger.info('Connected with TLS on #{0}'.format(self.ID))
        elif scheme == 'ldapi':
            self.sockPath = None
            self._sock = socket(AF_UNIX)
            self.host = 'localhost'

            if netloc == '/':
                for sockGlob in LDAPSocket.LDAPI_SOCKET_PATHS:
                    fn = glob(sockGlob)
                    if not fn:
                        continue
                    if len(fn) > 1:
                        logger.debug('Multiple results for glob {0}'.format(sockGlob))
                        continue
                    fn = fn[0]
                    try:
                        self._connect(fn)
                        self.sockPath = fn
                        break
                    except SocketError:
                        continue
                if self.sockPath is None:
                    raise LDAPConnectionError('Could not find any local LDAPI unix socket - full '
                                              'socket path must be supplied in URI')
            else:
                try:
                    self._connect(netloc)
                    self.sockPath = netloc
                except SocketError as e:
                    raise LDAPConnectionError('failed connect to unix socket {0} - {1} ({2})'.format(
                        netloc, e.strerror, e.errno
                    ))

            logger.debug('Connected to unix socket {0} on #{1}'.format(self.sockPath, self.ID))
        else:
            raise LDAPError('Unsupported scheme "{0}"'.format(scheme))

    def _connect(self, addr):
        self._sock.settimeout(self.connect_timeout)
        self._sock.connect(addr)
        self._sock.settimeout(None)

    def _inet_connect(self, netloc, default_port):
        ap = netloc.rsplit(':', 1)
        self.host = ap[0]
        if len(ap) == 1:
            port = default_port
        else:
            port = int(ap[1])
        try:
            self._sock = create_connection((self.host, port), self.connect_timeout)
            logger.debug('Connected to {0}:{1} on #{2}'.format(self.host, port, self.ID))
        except SocketError as e:
            raise LDAPConnectionError('failed connect to {0}:{1} - {2} ({3})'.format(
                self.host, port, e.strerror, e.errno
            ))

    def _start_tls(self, verify=True, ca_file=None, ca_path=None, ca_data=None):
        if self.started_tls:
            raise LDAPError('TLS layer already installed')

        if verify:
            verify_mode = ssl.CERT_REQUIRED
        else:
            verify_mode = ssl.CERT_NONE

        try:
            proto = ssl.PROTOCOL_TLS
        except AttributeError:
            proto = ssl.PROTOCOL_SSLv23

        try:
            ctx = ssl.SSLContext(proto)
            ctx.verify_mode = verify_mode
            ctx.check_hostname = False # we do this ourselves
            if verify:
                ctx.load_default_certs()
            if ca_file or ca_path or ca_data:
                ctx.load_verify_locations(cafile=ca_file, capath=ca_path, cadata=ca_data)
            self._sock = ctx.wrap_socket(self._sock)
        except AttributeError:
            # SSLContext wasn't added until 2.7.9
            if ca_path or ca_data:
                raise RuntimeError('python version >= 2.7.9 required for SSL ca_path/ca_data')

            self._sock = ssl.wrap_socket(self._sock, ca_certs=ca_file, cert_reqs=verify_mode, ssl_version=proto)

        if verify:
            # implement a consistent check_hostname according to RFC 4513 sec 3.1.3
            cert = self._sock.getpeercert()
            cert_cn = dict([e[0] for e in cert['subject']])['commonName']
            if self.host == cert_cn:
                logger.debug('Matched server identity to cert commonName')
            else:
                valid = False
                tried = [cert_cn]
                for type, value in cert.get('subjectAltName', []):
                    if type == 'DNS' and value.startswith('*.'):
                        valid = self.host.endswith(value[1:])
                    else:
                        valid = (self.host == value)
                    tried.append(value)
                    if valid:
                        logger.debug('Matched server identity to cert {0} subjectAltName'.format(type))
                        break
                if not valid:
                    raise LDAPConnectionError('Server identity "{0}" does not match any cert names: {1}'.format(self.host, ', '.join(tried)))
        else:
            logger.debug('Skipping hostname validation')
        self.started_tls = True
        logger.debug('Installed TLS layer on #{0}'.format(self.ID))

    def sasl_init(self, mechs, **props):
        """Initialize a puresasl.client.SASLClient"""
        self._sasl_client = SASLClient(self.host, 'ldap', **props)
        self._sasl_client.choose_mechanism(mechs)

    def _has_sasl_client(self):
        return self._sasl_client is not None

    def _require_sasl_client(self):
        if not self._has_sasl_client():
            raise LDAPSASLError('SASL init not complete')

    @property
    def sasl_qop(self):
        """Obtain the chosen quality of protection"""
        self._require_sasl_client()
        return self._sasl_client.qop

    @property
    def sasl_mech(self):
        """Obtain the chosen mechanism"""
        self._require_sasl_client()
        mech = self._sasl_client.mechanism
        if mech is None:
            raise LDAPSASLError('SASL init not complete - no mech chosen')
        else:
            return mech

    def sasl_process_auth_challenge(self, challenge):
        """Process an auth challenge and return the correct response"""
        self._require_sasl_client()
        return self._sasl_client.process(challenge)

    def send_message(self, op, obj, controls=None):
        """Create and send an LDAPMessage given an operation name and a corresponding object

         Operation names must be defined as component names in laurelin.ldap.rfc4511.ProtocolOp and
         the object must be of the corresponding type
        """
        mid = self._next_message_id
        lm = LDAPMessage()
        lm.setComponentByName('messageID', MessageID(mid))
        self._next_message_id += 1
        po = ProtocolOp()
        po.setComponentByName(op, obj)
        lm.setComponentByName('protocolOp', po)
        if controls:
            lm.setComponentByName('controls', controls)
        raw = ber_encode(lm)
        if self._has_sasl_client():
            raw = self._sasl_client.wrap(raw)
        self._sock.sendall(raw)
        return mid

    def recv_one(self, want_message_id):
        return next(self.recv_messages(want_message_id))

    def recv_messages(self, want_message_id):
        flush_queue = True
        raw = b''
        while True:
            if flush_queue:
                if want_message_id in self._message_queues:
                    q = self._message_queues[want_message_id]
                    while True:
                        if len(q) == 0:
                            break
                        obj = q.popleft()
                        if len(q) == 0:
                            del self._message_queues[want_message_id]
                        yield obj
            else:
                flush_queue = True
            if want_message_id in self.abandoned_mids:
                raise StopIteration()
            try:
                newraw = self._sock.recv(LDAPSocket.RECV_BUFFER)
                if self._has_sasl_client():
                    newraw = self._sasl_client.unwrap(newraw)
                raw += newraw
                while len(raw) > 0:
                    response, raw = ber_decode(raw, asn1Spec=LDAPMessage())
                    have_message_id = response.getComponentByName('messageID')
                    if want_message_id == have_message_id:
                        yield response
                    elif have_message_id == 0:
                        raise LDAPError('Got message ID 0')
                    else:
                        if have_message_id not in self._message_queues:
                            self._message_queues[have_message_id] = deque()
                        self._message_queues[have_message_id].append(response)
            except SubstrateUnderrunError:
                flush_queue = False
                continue

    def close(self):
        """Close the low-level socket connection"""
        return self._sock.close()
