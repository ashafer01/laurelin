from __future__ import absolute_import
from laurelin.ldap import rfc4511, protoutils
from laurelin.ldap.net import LDAPSocket

from collections import deque
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.ber.decoder import decode as ber_decode
from warnings import warn


class MockLDAPSocket(LDAPSocket):
    def __init__(self):
        self._prop_init()
        self._outgoing_queue = deque()
        self._sock = None
        self._incoming_queue = deque()
        self.uri = 'mock:///'
        self._next_add_message_id = self._next_message_id

    def add_message(self, lm):
        """Add a new response message to be received"""
        raw = ber_encode(lm)
        self._outgoing_queue.append(raw)

    def add_search_res_entry(self, dn, attrs_dict, controls=None):
        """Create a searchResEntry LDAPMessage"""
        sre = rfc4511.SearchResultEntry()
        sre.setComponentByName('objectName', rfc4511.LDAPDN(dn))

        attrs = rfc4511.PartialAttributeList()
        i = 0
        for attr, values in attrs_dict.items():
            _attr = rfc4511.PartialAttribute()
            _attr.setComponentByName('type', rfc4511.AttributeDescription(attr))
            _vals = rfc4511.Vals()
            for j, val in enumerate(values):
                _vals.setComponentByPosition(j, rfc4511.AttributeValue(val))
            _attr.setComponentByName('vals', _vals)
            attrs.setComponentByPosition(i, _attr)
            i += 1

        sre.setComponentByName('attributes', attrs, controls)

        self.add_message(protoutils.pack(self._next_add_message_id, 'searchResEntry', sre))

    def add_search_res_ref(self, uris, controls=None):
        """Generate a searchResultRef LDAPMessage"""
        srr = rfc4511.SearchResultReference()
        for i, uri in enumerate(uris):
            srr.setComponentByPosition(i, uri)
        self.add_message(protoutils.pack(self._next_add_message_id, 'searchResRef', srr, controls))

    def add_search_res_done(self, dn, result_code=protoutils.RESULT_success, controls=None, referral=None):
        """Create a searchResDone LDAPMessage"""
        self.add_ldap_result(rfc4511.SearchResultDone,
                             'searchResDone',
                             dn=dn,
                             result_code=result_code,
                             msg='THIS IS A TEST OBJECT',
                             controls=controls,
                             referral=referral)

    def add_ldap_result(self, cls, op, result_code=protoutils.RESULT_success, dn='', msg='', controls=None,
                        referral=None):
        mid = self._next_add_message_id
        self._next_add_message_id += 1
        res = cls()
        if referral:
            result_code = protoutils.RESULT_referral
            _referral = rfc4511.Referral()
            for i, uri in enumerate(referral):
                _referral.setComponentByPosition(i, rfc4511.URI(uri))
            res.setComponentByName('referral', _referral)
        res.setComponentByName('resultCode', result_code)
        res.setComponentByName('matchedDN', rfc4511.LDAPDN(dn))
        res.setComponentByName('diagnosticMessage', rfc4511.LDAPString(msg))
        self.add_message(protoutils.pack(mid, op, res, controls))

    def add_root_dse(self):
        """Add a response to the mock socket for root DSE query"""
        self.add_search_res_entry('', {
            'namingContexts': ['o=testing']
        }),
        self.add_search_res_done('')

    def send_message(self, op, obj, controls=None):
        """Pack and send a message"""
        mid, raw = self._prep_message(op, obj, controls)
        self._incoming_queue.append(raw)
        return mid

    def read_sent(self):
        """Read the first sent message in the queue"""
        lm, raw = ber_decode(self._incoming_queue.popleft(), asn1Spec=rfc4511.LDAPMessage())
        if raw:
            raise Exception('unexpected leftover bits')
        return lm

    def clear_sent(self):
        """Clear all sent messages"""
        self._incoming_queue.clear()

    def num_sent(self):
        """Obtain the number of sent messages"""
        return len(self._incoming_queue)

    def recv_messages(self, want_message_id):
        while self._outgoing_queue:
            raw = self._outgoing_queue.popleft()
            lm, raw = ber_decode(raw, asn1Spec=rfc4511.LDAPMessage())
            if raw:
                raise Exception('Unexpected leftover bits')
            have_message_id = lm.getComponentByName('messageID')
            if have_message_id != want_message_id:
                raise Exception('Unexpected message ID in mock queue (have={0} want={1})'.format(
                                have_message_id, want_message_id))
            yield lm
        raise Exception('No messages in mock queue')

    def close(self):
        pass

    def start_tls(self, verify=True, ca_file=None, ca_path=None, ca_data=None):
        warn('start_tls not possible with mock socket')
