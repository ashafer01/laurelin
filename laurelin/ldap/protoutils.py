from __future__ import absolute_import
from .rfc4511 import (
    LDAPDN,
    ResultCode,
    Version,
)
from .errors import UnexpectedResponseType
import six
from six.moves import range

# Commonly reused protocol objects
V3 = Version(3)
EMPTY_DN = LDAPDN('')
RESULT_saslBindInProgress = ResultCode('saslBindInProgress')
RESULT_success = ResultCode('success')
RESULT_noSuchObject = ResultCode('noSuchObject')
RESULT_compareTrue = ResultCode('compareTrue')
RESULT_compareFalse = ResultCode('compareFalse')
RESULT_referral = ResultCode('referral')

def _unpack(op, ldapMessage):
    """Unpack an object from an LDAPMessage envelope"""
    mID = ldapMessage.getComponentByName('messageID')
    po = ldapMessage.getComponentByName('protocolOp')
    ret = po.getComponentByName(op)
    if ret is not None:
        return mID, ret
    else:
        raise UnexpectedResponseType()

def _seqToList(seq):
    ret = []
    for i in range(len(seq)):
        ret.append(six.text_type(seq.getComponentByPosition(i)))
    return ret
