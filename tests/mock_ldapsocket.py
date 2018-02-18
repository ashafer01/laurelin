from __future__ import absolute_import
from laurelin.ldap import rfc4511
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

    def add_messages(self, lm_list):
        """Add new messages to be received"""
        for lm in lm_list:
            raw = ber_encode(lm)
            self._outgoing_queue.append(raw)

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
