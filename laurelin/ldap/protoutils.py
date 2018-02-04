from __future__ import absolute_import
from .rfc4511 import (
    LDAPDN,
    ResultCode,
    Version,
)
from .exceptions import UnexpectedResponseType
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


def unpack(op, ldapMessage):
    """Unpack an object from an LDAPMessage envelope"""
    mID = ldapMessage.getComponentByName('messageID')
    po = ldapMessage.getComponentByName('protocolOp')
    controls = ldapMessage.getComponentByName('controls')
    ret = po.getComponentByName(op)
    if ret:
        return mID, ret, controls
    else:
        raise UnexpectedResponseType()


def _seqToList(seq):
    """Convert a pyasn1 sequence to a list of strings"""
    ret = []
    for i in range(len(seq)):
        ret.append(six.text_type(seq.getComponentByPosition(i)))
    return ret


def parseQdescrs(spec):
    """Parse an rfc4512.qdescrs to a tuple"""
    if spec is None:
        return ()
    return tuple(qdescr.strip("'") for qdescr in spec.strip('( )').split(' '))
