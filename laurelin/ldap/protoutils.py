from __future__ import absolute_import
from .rfc4511 import (
    LDAPDN,
    ResultCode,
    Version,
)
from .exceptions import UnexpectedResponseType
from pyasn1.error import PyAsn1Error
import logging
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

logger = logging.getLogger(__name__)


def unpack(op, ldapMessage):
    """Unpack an object from an LDAPMessage envelope"""
    mID = ldapMessage.getComponentByName('messageID')
    po = ldapMessage.getComponentByName('protocolOp')
    controls = ldapMessage.getComponentByName('controls')
    if po.getName() == op:
        ret = po.getComponent()
        if ret.isValue:
            return mID, ret, controls
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


def getStringComponent(obj, name):
    """Try to get a string component from a PyASN1 object, or an empty string on error"""
    try:
        comp = obj.getComponentByName(name)
        return six.text_type(comp)
    except PyAsn1Error:
        logger.debug("Returning empty string for {0} due to PyAsn1Error".format(name))
        return ''
