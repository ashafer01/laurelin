from socket import create_connection
from urlparse import urlparse
from pyasn1.codec.ber.encoder import encode as berEncode
from pyasn1.codec.ber.decoder import decode as berDecode
from pyasn1.error import SubstrateUnderrunError

from rfc4511 import LDAPMessage, MessageID, ProtocolOp
from base import LDAPError

class LDAPSocket(object):
    RECV_BUFFER = 4096

    def __init__(self, hostURI, connectTimeout=5):
        parsedURI = urlparse(hostURI)
        if parsedURI.scheme == 'ldap':
            ap = parsedURI.netloc.split(':', 1)
            address = ap[0]
            if len(ap) == 1:
                port = 389
            else:
                port = int(ap[1])
        else:
            raise LDAPError('Unsupported scheme "{0}"'.format(parsedURI.scheme))
        self.URI = hostURI
        self.addr = (address, port)
        self.sock = create_connection(self.addr, connectTimeout)
        self.unbound = False
        self.messageID = 1

    def sendMessage(self, op, obj):
        mID = self.messageID
        lm = LDAPMessage()
        lm.setComponentByName('messageID', MessageID(mID))
        po = ProtocolOp()
        po.setComponentByName(op, obj)
        lm.setComponentByName('protocolOp', po)
        self.messageID += 1
        self.sock.sendall(berEncode(lm))
        return mID

    def recvResponse(self, raw=''):
        ret = []
        try:
            raw += self.sock.recv(LDAPSocket.RECV_BUFFER)
            while len(raw) > 0:
                response, raw = berDecode(raw, asn1Spec=LDAPMessage())
                ret.append(response)
            return ret
        except SubstrateUnderrunError:
            ret += self.recvResponse(raw)
            return ret

    def close(self):
        return self.sock.close()
