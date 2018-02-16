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
        self.incoming_queue = deque()
        self.uri = 'mock:///'

    def add_messages(self, lm_list):
        """Add new messages to be received"""
        for lm in lm_list:
            raw = ber_encode(lm)
            self._outgoing_queue.append(raw)

    def send_message(self, op, obj, controls=None):
        mid, raw = self._prep_message(op, obj, controls)
        self.incoming_queue.append(raw)
        return mid

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

    def clear_outgoing(self):
        self._outgoing_queue.clear()
