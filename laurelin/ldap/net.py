"""Provides protocol-level interface for low-level sockets"""

from __future__ import absolute_import
import six
import ssl
import logging
from glob import glob
from socket import create_connection, socket, error as SocketError
from six.moves.urllib.parse import unquote
from collections import deque
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.error import SubstrateUnderrunError
from puresasl.client import SASLClient

from .rfc4511 import LDAPMessage, ResultCode
from .exceptions import LDAPError, LDAPSASLError, LDAPConnectionError, LDAPUnsolicitedMessage, UnexpectedResponseType
from .protoutils import pack, unpack

try:
    from socket import AF_UNIX
    _have_unix_socket = True
except ImportError:
    AF_UNIX = None
    _have_unix_socket = False

_next_sock_id = 0
logger = logging.getLogger(__name__)


class LDAPSocket(object):
    """Holds a connection to an LDAP server.

    :param str host_uri: "scheme://netloc" to connect to
    :param int connect_timeout: Number of seconds to wait for connection to be accepted
    :param bool ssl_verify: Validate the certificate and hostname on an SSL/TLS connection
    :param str ssl_ca_file: Path to PEM-formatted concatenated CA certficates file
    :param str ssl_ca_path: Path to directory with CA certs under hashed file names. See
                            https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_load_verify_locations.html for more
                            information about the format of this directory.
    :param ssl_ca_data: An ASCII string of one or more PEM-encoded certs or a bytes object containing DER-encoded
                        certificates.
    :type ssl_ca_data: str or bytes
    """

    RECV_BUFFER = 4096

    # For ldapi:/// try to connect to these socket files in order
    # Globs must match exactly one result
    LDAPI_SOCKET_PATHS = ['/var/run/ldapi', '/var/run/slapd/ldapi', '/var/run/slapd-*.socket']

    # OIDs of unsolicited messages

    OID_DISCONNECTION_NOTICE = '1.3.6.1.4.1.1466.20036'  # RFC 4511 sec 4.4.1 Notice of Disconnection

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
            self.start_tls(ssl_verify, ssl_ca_file, ssl_ca_path, ssl_ca_data)
            logger.info('Connected with TLS on #{0}'.format(self.ID))
        elif scheme == 'ldapi':
            if not _have_unix_socket:
                raise LDAPError('Unix sockets are not supported on your platform, please choose a protocol other'
                                'than ldapi')
            self.sock_path = None
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
                        self.sock_path = fn
                        break
                    except SocketError:
                        continue
                if self.sock_path is None:
                    raise LDAPConnectionError('Could not find any local LDAPI unix socket - full '
                                              'socket path must be supplied in URI')
            else:
                try:
                    self._connect(netloc)
                    self.sock_path = netloc
                except SocketError as e:
                    raise LDAPConnectionError('failed connect to unix socket {0} - {1} ({2})'.format(
                        netloc, e.strerror, e.errno
                    ))

            logger.debug('Connected to unix socket {0} on #{1}'.format(self.sock_path, self.ID))
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
                                      self.host, port, e.strerror, e.errno))

    def start_tls(self, verify=True, ca_file=None, ca_path=None, ca_data=None):
        """Install TLS layer on this socket connection.

        :param bool verify: Validate the certificate and hostname on an SSL/TLS connection
        :param str ca_file: Path to PEM-formatted concatenated CA certficates file
        :param str ca_path: Path to directory with CA certs under hashed file names. See
                            https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_load_verify_locations.html for more
                            information about the format of this directory.
        :param ca_data: An ASCII string of one or more PEM-encoded certs or a bytes object containing DER-encoded
                        certificates.
        :type ca_data: str or bytes
        """
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
            ctx.check_hostname = False  # we do this ourselves
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
            cert = self._sock.getpeercert()
            cert_cn = dict([e[0] for e in cert['subject']])['commonName']
            self.check_hostname(cert_cn, cert)
        else:
            logger.debug('Skipping hostname validation')
        self.started_tls = True
        logger.debug('Installed TLS layer on #{0}'.format(self.ID))

    def check_hostname(self, cert_cn, cert):
        """SSL check_hostname according to RFC 4513 sec 3.1.3. Compares supplied values against ``self.host`` to
        determine the validity of the cert.

        :param str cert_cn: The common name of the cert
        :param dict cert: A dictionary representing the rest of the cert. Checks key subjectAltNames for a list of
                          (type, value) tuples, where type is 'DNS' or 'IP'. DNS supports leading wildcard.
        :rtype: None
        :raises LDAPConnectionError: if no supplied values match ``self.host``
        """
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
                raise LDAPConnectionError('Server identity "{0}" does not match any cert names: {1}'.format(
                    self.host, ', '.join(tried)))

    def sasl_init(self, mechs, **props):
        """Initialize a :class:`.puresasl.client.SASLClient`"""
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

    def _prep_message(self, op, obj, controls=None):
        """Prepare a message for transmission"""
        mid = self._next_message_id
        self._next_message_id += 1
        lm = pack(mid, op, obj, controls)
        raw = ber_encode(lm)
        if self._has_sasl_client():
            raw = self._sasl_client.wrap(raw)
        return mid, raw

    def send_message(self, op, obj, controls=None):
        """Create and send an LDAPMessage given an operation name and a corresponding object.

        Operation names must be defined as component names in laurelin.ldap.rfc4511.ProtocolOp and
        the object must be of the corresponding type.

        :param str op: The protocol operation name
        :param object obj: The associated protocol object (see :class:`.rfc4511.ProtocolOp` for mapping.
        :param controls: Any request controls for the message
        :type controls: rfc4511.Controls or None
        :return: The message ID for this message
        :rtype: int
        """
        mid, raw = self._prep_message(op, obj, controls)
        self._sock.sendall(raw)
        return mid

    def recv_one(self, want_message_id):
        """Get the next message with ``want_message_id`` being sent by the server

        :param int want_message_id: The desired message ID.
        :return: The LDAP message
        :rtype: rfc4511.LDAPMessage
        """
        return next(self.recv_messages(want_message_id))

    def recv_messages(self, want_message_id):
        """Iterate all messages with ``want_message_id`` being sent by the server.

        :param int want_message_id: The desired message ID.
        :return: An iterator over :class:`.rfc4511.LDAPMessage`.
        """
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
                return
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
                        msg = 'Received unsolicited message (default message - should never be seen)'
                        try:
                            mid, xr, ctrls = unpack('extendedResp', response)
                            res_code = xr.getComponentByName('resultCode')
                            xr_oid = six.text_type(xr.getComponentByName('responseName'))
                            if xr_oid == LDAPSocket.OID_DISCONNECTION_NOTICE:
                                mtype = 'Notice of Disconnection'
                            else:
                                mtype = 'Unhandled ({0})'.format(xr_oid)
                            diag = xr.getComponentByName('diagnosticMessage')
                            msg = 'Got unsolicited message: {0}: {1}: {2}'.format(mtype, res_code, diag)
                            if res_code == ResultCode('protocolError'):
                                msg += (' (This may indicate an incompatability between laurelin-ldap and your server '
                                        'distribution)')
                            elif res_code == ResultCode('strongerAuthRequired'):
                                # this is a direct quote from RFC 4511 sec 4.4.1
                                msg += (' (The server has detected that an established security association between the'
                                        ' client and server has unexpectedly failed or been compromised)')
                        except UnexpectedResponseType:
                            msg = 'Unhandled unsolicited message from server'
                        finally:
                            raise LDAPUnsolicitedMessage(response, msg)
                    else:
                        if have_message_id not in self._message_queues:
                            self._message_queues[have_message_id] = deque()
                        self._message_queues[have_message_id].append(response)
            except SubstrateUnderrunError:
                flush_queue = False
                continue

    def close(self):
        """Close the low-level socket connection."""
        return self._sock.close()
