"""Provides protocol-level interface for low-level sockets"""

from __future__ import absolute_import
import ssl
import logging
from glob import glob
from socket import create_connection, socket, AF_UNIX, error as SocketError
from six.moves.urllib.parse import unquote
from collections import deque
from pyasn1.codec.ber.encoder import encode as berEncode
from pyasn1.codec.ber.decoder import decode as berDecode
from pyasn1.error import SubstrateUnderrunError
from puresasl.client import SASLClient

from .rfc4511 import LDAPMessage, MessageID, ProtocolOp
from .exceptions import LDAPError, LDAPSASLError, LDAPConnectionError

_nextSockID = 0
logger = logging.getLogger(__name__)

class LDAPSocket(object):
    """Holds a connection to an LDAP server"""

    RECV_BUFFER = 4096

    # For ldapi:/// try to connect to these socket files in order
    # Globs must match exactly one result
    LDAPI_SOCKET_PATHS = ['/var/run/ldapi', '/var/run/slapd/ldapi', '/var/run/slapd-*.socket']

    def __init__(self, hostURI, connectTimeout=5, sslVerify=True, sslCAFile=None,
        sslCAPath=None, sslCAData=None):

        # parse hostURI
        parts = hostURI.split('://')
        if len(parts) == 1:
            netloc = unquote(parts[0])
            if netloc[0] == '/':
                scheme == 'ldapi'
            else:
                scheme = 'ldap'
        elif len(parts) == 2:
            scheme = parts[0]
            netloc = unquote(parts[1])
        else:
            raise LDAPError('Invalid hostURI')
        self.URI = '{0}://{1}'.format(scheme, netloc)

        # get socket ID number
        global _nextSockID
        self.ID = _nextSockID
        _nextSockID += 1

        # misc init
        self._messageQueues = {}
        self._nextMessageID = 1
        self._saslClient = None

        self.refcount = 0
        self.bound = False
        self.unbound = False
        self.abandonedMIDs = []
        self.startedTLS = False
        self.connectTimeout = connectTimeout

        # connect
        logger.info('Connecting to {0} on #{1}'.format(self.URI, self.ID))
        if scheme == 'ldap':
            self._inetConnect(netloc, 389)
        elif scheme == 'ldaps':
            self._inetConnect(netloc, 636)
            self._startTLS(sslVerify, sslCAFile, sslCAPath, sslCAData)
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
                        path, e.strerror, e.errno
                    ))

            logger.debug('Connected to unix socket {0} on #{1}'.format(self.sockPath, self.ID))
        else:
            raise LDAPError('Unsupported scheme "{0}"'.format(scheme))

    def _connect(self, addr):
        self._sock.settimeout(self.connectTimeout)
        self._sock.connect(addr)
        self._sock.settimeout(None)

    def _inetConnect(self, netloc, defaultPort):
        ap = netloc.rsplit(':', 1)
        self.host = ap[0]
        if len(ap) == 1:
            port = defaultPort
        else:
            port = int(ap[1])
        try:
            self._sock = create_connection((self.host, port), self.connectTimeout)
            logger.debug('Connected to {0}:{1} on #{2}'.format(self.host, port, self.ID))
        except SocketError as e:
            raise LDAPConnectionError('failed connect to {0}:{1} - {2} ({3})'.format(
                self.host, port, e.strerror, e.errno
            ))

    def _startTLS(self, verify=True, caFile=None, caPath=None, caData=None):
        if self.startedTLS:
            raise LDAPError('TLS layer already installed')

        if verify:
            verifyMode = ssl.CERT_REQUIRED
        else:
            verifyMode = ssl.CERT_NONE

        try:
            proto = ssl.PROTOCOL_TLS
        except AttributeError:
            proto = ssl.PROTOCOL_SSLv23

        try:
            ctx = ssl.SSLContext(proto)
            ctx.verify_mode = verifyMode
            ctx.check_hostname = False # we do this ourselves
            if verify:
                ctx.load_default_certs()
            if caFile or caPath or caData:
                ctx.load_verify_locations(cafile=caFile, capath=caPath, cadata=caData)
            self._sock = ctx.wrap_socket(self._sock)
        except AttributeError:
            # SSLContext wasn't added until 2.7.9
            if caPath or caData:
                raise RuntimeError('python version >= 2.7.9 required for SSL caPath/caData')

            self._sock = ssl.wrap_socket(self._sock, ca_certs=caFile, cert_reqs=verifyMode, ssl_version=proto)

        if verify:
            # implement a consistent check_hostname according to RFC 4513 sec 3.1.3
            cert = self._sock.getpeercert()
            certCN = dict([e[0] for e in cert['subject']])['commonName']
            if self.host == certCN:
                logger.debug('Matched server identity to cert commonName')
            else:
                valid = False
                tried = [certCN]
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
        self.startedTLS = True
        logger.debug('Installed TLS layer on #{0}'.format(self.ID))

    def saslInit(self, mechs, **props):
        """Initialize a puresasl.client.SASLClient"""
        self._saslClient = SASLClient(self.host, 'ldap', **props)
        self._saslClient.choose_mechanism(mechs)

    def _hasSaslClient(self):
        return (self._saslClient is not None)

    def _requireSaslClient(self):
        if not self._hasSaslClient():
            raise LDAPSASLError('SASL init not complete')

    @property
    def saslQoP(self):
        """Obtain the chosen quality of protection"""
        self._requireSaslClient()
        return self._saslClient.qop

    @property
    def saslMech(self):
        """Obtain the chosen mechanism"""
        self._requireSaslClient()
        mech = self._saslClient.mechanism
        if mech is None:
            raise LDAPSASLError('SASL init not complete - no mech chosen')
        else:
            return mech

    def saslProcessAuthChallenge(self, challenge):
        """Process an auth challenge and return the correct response"""
        self._requireSaslClient()
        return self._saslClient.process(challenge)

    def sendMessage(self, op, obj, controls=None):
        """Create and send an LDAPMessage given an operation name and a corresponding object

         Operation names must be defined as component names in laurelin.ldap.rfc4511.ProtocolOp and
         the object must be of the corresponding type
        """
        mID = self._nextMessageID
        lm = LDAPMessage()
        lm.setComponentByName('messageID', MessageID(mID))
        self._nextMessageID += 1
        po = ProtocolOp()
        po.setComponentByName(op, obj)
        lm.setComponentByName('protocolOp', po)
        if controls:
            lm.setComponentByName('controls', controls)
        raw = berEncode(lm)
        if self._hasSaslClient():
            raw = self._saslClient.wrap(raw)
        self._sock.sendall(raw)
        return mID

    def recvOne(self, wantMessageID):
        return next(self.recvMessages(wantMessageID))

    def recvMessages(self, wantMessageID):
        flushQueue = True
        raw = b''
        while True:
            if flushQueue:
                if wantMessageID in self._messageQueues:
                    q = self._messageQueues[wantMessageID]
                    while True:
                        if len(q) == 0:
                            break
                        obj = q.popleft()
                        if len(q) == 0:
                            del self._messageQueues[wantMessageID]
                        yield obj
            else:
                flushQueue = True
            if wantMessageID in self.abandonedMIDs:
                raise StopIteration()
            try:
                newraw = self._sock.recv(LDAPSocket.RECV_BUFFER)
                if self._hasSaslClient():
                    newraw = self._saslClient.unwrap(newraw)
                raw += newraw
                while len(raw) > 0:
                    response, raw = berDecode(raw, asn1Spec=LDAPMessage())
                    haveMessageID = response.getComponentByName('messageID')
                    if wantMessageID == haveMessageID:
                        yield response
                    elif haveMessageID == 0:
                        raise LDAPError('Got message ID 0')
                    else:
                        if haveMessageID not in self._messageQueues:
                            self._messageQueues[haveMessageID] = deque()
                        self._messageQueues[haveMessageID].append(response)
            except SubstrateUnderrunError:
                flushQueue = False
                continue

    def close(self):
        """Close the low-level socket connection"""
        return self._sock.close()
