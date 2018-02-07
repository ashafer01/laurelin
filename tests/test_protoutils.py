from laurelin.ldap import exceptions, rfc4511, protoutils
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.ber.decoder import decode as ber_decode
import unittest


def encode_decode(lm):
    """Simulate transmission over the network"""
    raw = ber_encode(lm)
    response, raw = ber_decode(raw, asn1Spec=rfc4511.LDAPMessage())
    if raw:
        raise Exception('Unexpected leftover bits')
    return response


class TestProtoutils(unittest.TestCase):
    def test_unpack(self):
        message_id = 1
        proto_op = 'compareResponse'

        test_lm = rfc4511.LDAPMessage()
        test_lm.setComponentByName('messageID', rfc4511.MessageID(message_id))
        test_cr = rfc4511.CompareResponse()
        test_cr.setComponentByName('resultCode', protoutils.RESULT_compareTrue)
        test_cr.setComponentByName('matchedDN', rfc4511.LDAPDN('cn=testing,o=foo'))
        test_cr.setComponentByName('diagnosticMessage', rfc4511.LDAPString(''))
        test_po = rfc4511.ProtocolOp()
        test_po.setComponentByName(proto_op, test_cr)
        test_lm.setComponentByName('protocolOp', test_po)

        # simulate network transmission
        test_lm = encode_decode(test_lm)

        # ensure we successfully unpack the message ID and get back a compareResult
        actual_message_id, actual_cr, actual_controls = protoutils.unpack(proto_op, test_lm)

        self.assertEqual(actual_message_id, message_id)
        self.assertEqual(actual_cr.getComponentByName('resultCode'), protoutils.RESULT_compareTrue)

        # handling of optional controls varies by pyasn1 version
        # should either be None or length 0
        if actual_controls is not None:
            self.assertEqual(len(actual_controls), 0)

        # ensure unpacking another type raises an exception
        with self.assertRaises(exceptions.UnexpectedResponseType):
            protoutils.unpack('bindResponse', test_lm)
