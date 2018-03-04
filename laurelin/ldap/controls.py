from __future__ import absolute_import
from .exceptions import LDAPError, LDAPExtensionError, LDAPSupportError
from .rfc4511 import (
    LDAPOID,
    Criticality,
    Control as _Control,
    Controls,
    ControlValue,
)
import six
from six.moves import range

_request_controls = {}
_request_controls_oid = {}
_response_controls = {}

# this gets automatically generated by the reserve_kwds.py script
_reserved_kwds = set(['attr', 'attrs', 'attrs_dict', 'attrs_only', 'base_dn', 'clean_attr', 'current', 'deref_aliases', 'dn', 'fetch_result_refs', 'filter', 'follow_referrals', 'ldap_conn', 'limit', 'mech', 'mid', 'modlist', 'new_parent', 'new_rdn', 'oid', 'password', 'rdn_attr', 'relative_search_scope', 'require_success', 'scope', 'search_timeout', 'self', 'tag', 'username', 'value'])


def get_control(oid):
    return _request_controls_oid[oid]


def process_kwds(method, kwds, supported_ctrls, default_criticality, final=False):
    """Process keyword arguments for registered controls, returning a protocol-level Controls

    Removes entries from kwds as they are used, allowing the same dictionary to be passed on
    to another function which may have statically defined arguments. If final is True, then a
    TypeError will be raised if all kwds are not exhausted.
    """
    i = 0
    ctrls = Controls()
    for kwd in list(kwds.keys()):
        if kwd in _request_controls:
            ctrl = _request_controls[kwd]
            if method not in ctrl.method:
                raise LDAPError('Control keyword {0} not allowed for method "{1}"'.format(kwd, method))
            ctrl_value = kwds.pop(kwd)
            if isinstance(ctrl_value, critical):
                criticality = True
                ctrl_value = ctrl_value.value
            elif isinstance(ctrl_value, optional):
                criticality = False
                ctrl_value = ctrl_value.value
            else:
                criticality = default_criticality
            if criticality and (ctrl.REQUEST_OID not in supported_ctrls):
                raise LDAPSupportError('Critical control keyword {0} is not supported by the server'.format(kwd))
            ctrls.setComponentByPosition(i, ctrl.prepare(ctrl_value, criticality))
            i += 1
    if final and (len(kwds) > 0):
        raise TypeError('Unhandled keyword arguments: {0}'.format(', '.join(kwds.keys())))
    if i > 0:
        return ctrls
    else:
        return None


def handle_response(obj, controls):
    """Handle response control values and set attributes on the given object.

     Accepts any object to set attributes on, and an rfc4511.Controls instance
     from a server response.
    """

    # controls may be None or zero-length depending on pyasn1 version
    if controls:
        for i in range(len(controls)):
            control = controls.getComponentByPosition(i)
            ctrl_oid = six.text_type(control.getComponentByName('controlType'))
            try:
                ctrl = _response_controls[ctrl_oid]
            except KeyError:
                raise LDAPExtensionError('No response control defined for {0}'.format(ctrl_oid))
            value = ctrl.handle(control.getComponentByName('controlValue'))
            if not hasattr(obj, ctrl.response_attr):
                setattr(obj, ctrl.response_attr, value)
            else:
                raise LDAPExtensionError('Response control attribute "{0}" is already defined on the object'.format(
                                         ctrl.response_attr))


class MetaControl(type):
    """Metaclass which registers instances of subclasses"""
    def __new__(meta, name, bases, dct):
        cls = type.__new__(meta, name, bases, dct)
        instance = cls()
        if cls.REQUEST_OID:
            if not cls.method:
                raise ValueError('no method set on control {0}'.format(name))
            if not cls.keyword:
                raise ValueError('no keyword set on control {0}'.format(name))
            if cls.keyword in _reserved_kwds:
                raise LDAPExtensionError('Control keyword "{0}" is reserved'.format(cls.keyword))
            if cls.keyword in _request_controls:
                raise LDAPExtensionError('Control keyword "{0}" is already defined'.format(cls.keyword))
            if cls.REQUEST_OID in _request_controls_oid:
                raise LDAPExtensionError('Control {0} is already defined'.format(cls.REQUEST_OID))
            _request_controls[cls.keyword] = instance
            _request_controls_oid[cls.REQUEST_OID] = instance

        if cls.RESPONSE_OID:
            if not cls.response_attr:
                raise ValueError('Missing response_attr on control {0}'.format(name))
            if cls.RESPONSE_OID in _response_controls:
                raise LDAPExtensionError('Response control OID {0} is already defined'.format(cls.RESPONSE_OID))
            _response_controls[cls.RESPONSE_OID] = instance

        return cls


@six.add_metaclass(MetaControl)
class Control(object):
    """
     Request controls are exposed by allowing an additional keyword argument on
     a set of methods. The prepare() method takes the value passed in as a
     keyword argument and returns an rfc4511.Control.

     Response controls are returned by setting an additional attribute on
     whichever object is returned by the called method. The raw response
     controlValue is passed to the handle() method, and any appropriate value
     may be returned.

     Leave the RESPONSE_OID and response_attr attributes as a False value if
     there is no response control specified.
    """

    method = ()
    """name(s) of the method which this control is used with"""

    keyword = ''
    """keyword argument name"""

    response_attr = ''
    """Name of the attribute where return of handle() will be stored"""

    REQUEST_OID = ''
    """Request OID of the control"""

    RESPONSE_OID = ''
    """Response OID of the control (may be equal to REQUEST_OID; may be left empty)"""

    def prepare(self, ctrl_value, criticality):
        """Accepts string controlValue and returns an rfc4511.Control instance

        When overriding this function, you must always call and return this base function.

        :param ctrl_value: The string request control value to send to the server
        :type ctrl_value: str or bytes
        :param bool criticality: True if the control has criticality. This is indicated by wrapping the keyword
                                 argument in :class:`critical` or :class:`optional`, and by the `default_criticality`
                                 keyword passed to the :class:`LDAP` constructor, and global default
                                 :attr:`LDAP.DEFAULT_CRITICALITY`.
        :return: The protocol-level control object ready for transmission to the server
        :rtype: rfc4511.Control
        """
        c = _Control()
        c.setComponentByName('controlType', LDAPOID(self.REQUEST_OID))
        c.setComponentByName('criticality', Criticality(criticality))
        if ctrl_value:
            c.setComponentByName('controlValue', ControlValue(ctrl_value))
        return c

    def handle(self, ctrl_value):
        """Accepts raw response ctrl_value and may return any useful value.

        There is no need to call this base function when overriding.

        :param str ctrl_value: The string response control value received from the server.
        :return: The string `ctrl_value` unchanged by default. May be overridden to return any relevant
                 value/type/structure.
        """
        return six.text_type(ctrl_value)


class critical(object):
    """used to mark controls with criticality"""
    def __init__(self, value):
        self.value = value


class optional(object):
    """used to mark controls as not having criticality"""
    def __init__(self, value):
        self.value = value
