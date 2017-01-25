"""Provides protocol-level interface for low-level sockets"""

from __future__ import absolute_import
import ssl
from socket import socket, error as SocketError
from six.moves.urllib.parse import urlparse
from collections import deque
from pyasn1.codec.ber.encoder import encode as berEncode
from pyasn1.codec.ber.decoder import decode as berDecode
from pyasn1.error import SubstrateUnderrunError
from puresasl.client import SASLClient

from .rfc4511 import LDAPMessage, MessageID, ProtocolOp
from .errors import LDAPError, LDAPSASLError, LDAPConnectionError

_nextSockID = 0

class LDAPSocket(object):
    """Holds a connection to an LDAP server"""

    RECV_BUFFER = 4096
    SSL_NOVERIFY = ssl.CERT_NONE
    SSL_OPTIONAL = ssl.CERT_OPTIONAL
    SSL_REQUIRED = ssl.CERT_REQUIRED

    def __init__(self, hostURI,
        connectTimeout=5,
        sslVerify=SSL_REQUIRED,
        sslCAFile=None,
        sslCAPath=None,
        sslCAData=None,
        ):

        parsedURI = urlparse(hostURI)
        ap = parsedURI.netloc.split(':', 1)
        self.host = ap[0]

        self._sock = socket()
        if parsedURI.scheme == 'ldap':
            defaultPort = 389
        elif parsedURI.scheme == 'ldaps':
            defaultPort = 636
            # N.B. this is presently the only thing breaking 2.6 support
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.verify_mode = sslVerify
            if sslVerify != LDAPSocket.SSL_NOVERIFY:
                ctx.check_hostname = True
                ctx.load_default_certs()
            if sslCAFile or sslCAPath or sslCAData:
                ctx.load_verify_locations(cafile=sslCAFile, capath=sslCAPath, cadata=sslCAData)
            self._sock = ctx.wrap_socket(self._sock, server_hostname=self.host)
        else:
            raise LDAPError('Unsupported scheme "{0}"'.format(parsedURI.scheme))

        if len(ap) == 1:
            port = defaultPort
        else:
            port = int(ap[1])

        try:
            self._sock.settimeout(connectTimeout)
            self._sock.connect((self.host, port))
            self._sock.settimeout(None)
        except SocketError as e:
            raise LDAPConnectionError('{0} ({1})'.format(e.strerror, e.errno))

        self._messageQueues = {}
        self._nextMessageID = 1
        self._saslClient = None

        global _nextSockID
        self.ID = _nextSockID
        _nextSockID += 1
        self.URI = hostURI
        self.bound = False
        self.unbound = False
        self.abandonedMIDs = []

    def saslInit(self, mechs, **props):
        """Initialize a puresasl.client.SASLClient"""
        self._saslClient = SASLClient(self.host, 'ldap', **props)
        self._saslClient.choose_mechanism(mechs)

    @property
    def saslOK(self):
        """Check if SASL has been initialized and bind marked complete"""
        if self._saslClient is not None:
            return self.bound
        else:
            return False

    @property
    def saslQoP(self):
        """Obtain the chosen quality of protection"""
        if self._saslClient is not None:
            return self._saslClient.qop
        else:
            raise LDAPSASLError('SASL init not complete')

    @property
    def saslMech(self):
        """Obtain the chosen mechanism"""
        if self._saslClient is not None:
            mech = self._saslClient.mechanism
            if mech is None:
                raise LDAPSASLError('SASL init not complete - no mech chosen')
            else:
                return mech
        else:
            raise LDAPSASLError('SASL init not complete')

    def saslProcessAuthChallenge(self, challenge):
        """Process an auth challenge and return the correct response"""
        if self._saslClient is not None:
            return self._saslClient.process(challenge)
        else:
            raise LDAPSASLError('SASL init not complete')

    def sendMessage(self, op, obj):
        """Create and sned an LDAPMessage given an operation name and a corresponding object

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
        raw = berEncode(lm)
        if self.saslOK:
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
                if self.saslOK:
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
