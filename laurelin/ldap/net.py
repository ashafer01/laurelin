import ssl
from socket import socket, error as SocketError
from urlparse import urlparse
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

        self._messageQueue = []
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

    def recvResponse(self, wantMessageID=0, raw=''):
        ret = []
        for obj in self._messageQueue:
            if (wantMessageID <= 0) or (obj.getComponentByName('messageID') == wantMessageID):
                ret.append(obj)
                self._messageQueue.remove(obj)
        if len(ret) > 0:
            return ret
        if wantMessageID in self.abandonedMIDs:
            return ret
        try:
            raw += self._sock.recv(LDAPSocket.RECV_BUFFER)
            while len(raw) > 0:
                response, raw = berDecode(raw, asn1Spec=LDAPMessage())
                if wantMessageID > 0:
                    if wantMessageID == response.getComponentByName('messageID'):
                        ret.append(response)
                    else:
                        self._messageQueue.append(response)
                else:
                    ret.append(response)
            return ret
        except SubstrateUnderrunError:
            ret += self.recvResponse(wantMessageID, limit, raw)
            return ret

    def close(self):
        return self._sock.close()

class LDAPConnectionError(LDAPError):
    pass
