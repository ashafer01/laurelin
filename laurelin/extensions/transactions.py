"""Implementation of RFC5805 Transactions"""

from __future__ import absolute_import
from laurelin.ldap import rfc4511
from laurelin.ldap.base import LDAP
from laurelin.ldap.controls import Control, critical
from laurelin.ldap.exceptions import Abandon, LDAPError
from laurelin.ldap.protoutils import get_string_component
from laurelin.ldap.protoutils import RESULT_success
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.type.namedtype import (
    NamedTypes,
    NamedType,
    OptionalNamedType,
)
from pyasn1.type.univ import Sequence, SequenceOf, OctetString, Boolean


OID_START_TRANS_REQ = '1.3.6.1.1.21.1'
OID_END_TRANS_REQ = '1.3.6.1.1.21.3'
OID_TRANS_CTRL = '1.3.6.1.1.21.2'


## ASN.1 objects


class Commit(Boolean):
    defaultValue = True


class TxnEndReq(Sequence):
    # txnEndReq ::= SEQUENCE {
    #     commit         BOOLEAN DEFAULT TRUE,
    #     identifier     OCTET STRING }
    componentType = NamedTypes(
        NamedType('commit', Commit()),
        NamedType('identifier', OctetString()),
    )


class UpdateControls(Sequence):
    componentType = NamedTypes(
        NamedType('messageID', rfc4511.MessageID()),
        NamedType('controls', rfc4511.Controls()),
    )


class UpdatesControls(SequenceOf):
    componentType = UpdateControls()


class TxnEndRes(Sequence):
    # txnEndRes ::= SEQUENCE {
    #     messageID MessageID OPTIONAL,
    #       -- msgid associated with non-success resultCode
    #     updatesControls SEQUENCE OF updateControls SEQUENCE {
    #         messageID MessageID,
    #             -- msgid associated with controls
    #         controls  Controls
    #     } OPTIONAL
    # }
    componentType = NamedTypes(
        OptionalNamedType('messageID', rfc4511.MessageID()),
        OptionalNamedType('updatesControls', UpdatesControls()),
    )


## Transaction context manager object


class LDAPTransaction(object):
    def __init__(self, ldap, txn_id):
        self._ldap = ldap
        self._txn_id = txn_id
        self._in_progress = False

    def __getattr__(self, name):
        return getattr(self._ldap, name)

    def __enter__(self):
        return self

    def __exit__(self, etype, e, trace):
        if self._in_progress:
            self.abandon()
        if etype == Abandon:
            return True

    def _txn_op(self, ctrl_kwds):
        ctrl_kwds['txn_id'] = critical(self._txn_id)
        self._in_progress = True

    def add(self, dn, attrs_dict, **ctrl_kwds):
        self._txn_op(ctrl_kwds)
        return self._ldap.add(dn, attrs_dict, **ctrl_kwds)

    def delete(self, dn, **ctrl_kwds):
        self._txn_op(ctrl_kwds)
        return self._ldap.delete(dn, **ctrl_kwds)

    def mod_dn(self, dn, new_rdn, clean_attr=True, new_parent=None, **ctrl_kwds):
        self._txn_op(ctrl_kwds)
        return self._ldap.mod_dn(dn, new_rdn, clean_attr, new_parent, **ctrl_kwds)

    def modify(self, dn, modlist, current=None, **ctrl_kwds):
        self._txn_op(ctrl_kwds)
        return self._ldap.modify(dn, modlist, current, **ctrl_kwds)

    def _end_transaction(self, commit):
        txn_end_req = TxnEndReq()
        txn_end_req.setComponentByName('commit', Commit(commit))
        txn_end_req.setComponentByName('identifier', self._txn_id)
        handle = self._ldap.send_extended_request(OID_END_TRANS_REQ, ber_encode(txn_end_req))
        self._in_progress = False
        xr, res_ctrls = handle.recv_response()
        res = xr.getComponentByName('resultCode')
        response_value = xr.getComponentByName('responseValue')
        if response_value:
            txn_end_res = ber_decode(response_value, asn1Spec=TxnEndRes())
            if res != RESULT_success:
                fail_mid = txn_end_res.getComponentByName('messageID')
                raise LDAPError('Transaction failed with {0} at #{1}'.format(repr(res), fail_mid))

    def commit(self):
        self._end_transaction(True)

    def abandon(self):
        self._end_transaction(False)

    def begin_transaction(self):
        raise LDAPError('Transactions cannot be nested')


## Transaction control


class Transaction(Control):
    keyword = 'txn_id'
    method = ('add', 'delete', 'modify', 'mod_dn')
    REQUEST_OID = OID_TRANS_CTRL

## Extension method


def begin_transaction(self):
    handle = self.send_extended_request(OID_START_TRANS_REQ, require_success=True)
    xr, res_ctrls = handle.recvResponse()
    txn_id = get_string_component(xr, 'responseValue')
    return LDAPTransaction(self, txn_id)


## Extension activation method


def activate_extension():
    LDAP.EXTEND([begin_transaction])
