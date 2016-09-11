import ssl
from socket import socket, error as SocketError
from urlparse import urlparse
from collections import deque
from pyasn1.codec.ber.encoder import encode as berEncode
from pyasn1.codec.ber.decoder import decode as berDecode
from pyasn1.error import SubstrateUnderrunError

from rfc4511 import LDAPMessage, MessageID, ProtocolOp
from errors import LDAPError

_nextSockID = 0

class LDAPSocket(object):
    RECV_BUFFER = 4096

    def __init__(self, hostURI,
        connectTimeout=5,
        sslCAFile=None,
        sslCAPath=None,
        sslCAData=None,
        ):

        parsedURI = urlparse(hostURI)
        ap = parsedURI.netloc.split(':', 1)
        address = ap[0]

        self._sock = socket()
        if parsedURI.scheme == 'ldap':
            defaultPort = 389
        elif parsedURI.scheme == 'ldaps':
            defaultPort = 636
            ctx = ssl.create_default_context(cafile=sslCAFile, capath=sslCAPath, cadata=sslCAData)
            self._sock = ctx.wrap_socket(self._sock, server_hostname=address)
        else:
            raise LDAPError('Unsupported scheme "{0}"'.format(parsedURI.scheme))

        if len(ap) == 1:
            port = defaultPort
        else:
            port = int(ap[1])

        try:
            self._sock.settimeout(connectTimeout)
            self._sock.connect((address, port))
            self._sock.settimeout(None)
        except SocketError as e:
            raise LDAPConnectionError('{0} ({1})'.format(e.strerror, e.errno))

        self._messageQueues = {}
        self._nextMessageID = 1

        global _nextSockID
        self.ID = _nextSockID
        _nextSockID += 1
        self.URI = hostURI
        self.bound = False
        self.unbound = False
        self.abandonedMIDs = []

    def sendMessage(self, op, obj):
        mID = self._nextMessageID
        lm = LDAPMessage()
        lm.setComponentByName('messageID', MessageID(mID))
        po = ProtocolOp()
        po.setComponentByName(op, obj)
        lm.setComponentByName('protocolOp', po)
        self._nextMessageID += 1
        self._sock.sendall(berEncode(lm))
        return mID

    def recvOne(self, wantMessageID):
        return next(self.recvIter(wantMessageID))

    def recvAll(self, wantMessageID):
        ret = []
        try:
            self._sock.setblocking(0)
            for obj in self.recvIter(wantMessageID):
                ret.append(obj)
        except SocketError as e:
            pass
        finally:
            self._sock.setblocking(1)
            return ret

    def recvIter(self, wantMessageID):
        flushQueue = True
        raw = ''
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
            try:
                raw += self._sock.recv(LDAPSocket.RECV_BUFFER)
                while len(raw) > 0:
                    response, raw = berDecode(raw, asn1Spec=LDAPMessage())
                    haveMessageID = response.getComponentByName('messageID')
                    if wantMessageID == haveMessageID:
                        yield response
                    else:
                        if haveMessageID not in self._messageQueues:
                            self._messageQueues[haveMessageID] = deque()
                        self._messageQueues[haveMessageID].append(response)
            except SubstrateUnderrunError:
                flushQueue = False
                continue

    def close(self):
        return self._sock.close()

class LDAPConnectionError(LDAPError):
    pass
