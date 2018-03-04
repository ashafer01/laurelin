from __future__ import absolute_import
from . import rfc4511
from .exceptions import UnexpectedResponseType
from pyasn1.error import PyAsn1Error
import logging
import six
from six.moves import range

# Commonly reused protocol objects
V3 = rfc4511.Version(3)
EMPTY_DN = rfc4511.LDAPDN('')
RESULT_saslBindInProgress = rfc4511.ResultCode('saslBindInProgress')
RESULT_success = rfc4511.ResultCode('success')
RESULT_noSuchObject = rfc4511.ResultCode('noSuchObject')
RESULT_compareTrue = rfc4511.ResultCode('compareTrue')
RESULT_compareFalse = rfc4511.ResultCode('compareFalse')
RESULT_referral = rfc4511.ResultCode('referral')

logger = logging.getLogger(__name__)


def pack(mid, op, obj, controls=None):
    """Pack an object into an LDAPMessage envelope"""
    lm = rfc4511.LDAPMessage()
    lm.setComponentByName('messageID', rfc4511.MessageID(mid))
    po = rfc4511.ProtocolOp()
    po.setComponentByName(op, obj)
    lm.setComponentByName('protocolOp', po)
    if controls:
        lm.setComponentByName('controls', controls)
    return lm


def unpack(op, ldap_message):
    """Unpack an object from an LDAPMessage envelope"""
    mid = ldap_message.getComponentByName('messageID')
    po = ldap_message.getComponentByName('protocolOp')
    controls = ldap_message.getComponentByName('controls')
    got_op = po.getName()
    if got_op == op:
        ret = po.getComponent()
        if ret.isValue:
            return mid, ret, controls
    raise UnexpectedResponseType('Got {0} but expected {1}'.format(got_op, op))


def seq_to_list(seq):
    """Convert a pyasn1 sequence to a list of strings"""
    ret = []
    for i in range(len(seq)):
        try:
            ret.append(six.text_type(seq.getComponentByPosition(i)))
        except UnicodeDecodeError:
            ret.append(six.binary_type(seq.getComponentByPosition(i)))
    return ret


def parse_qdescrs(spec):
    """Parse an rfc4512.qdescrs to a tuple"""
    if spec is None:
        return ()
    return tuple(qdescr.strip("'") for qdescr in spec.strip('( )').split(' '))


def get_string_component(obj, name):
    """Try to get a string component from a PyASN1 object, or an empty string on error"""
    try:
        comp = obj.getComponentByName(name)
        return six.text_type(comp)
    except PyAsn1Error:
        logger.debug("Returning empty string for {0} due to PyAsn1Error".format(name))
        return ''
