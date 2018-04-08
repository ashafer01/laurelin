"""Extension adding support for POSIX users/groups to laurelin

Includes schema definitions from RFC 2307.

You should begin by tagging base objects for users and groups::

    from laurelin.ldap import LDAP, Scope
    posix = LDAP.activate_extension('laurelin.extensions.posix')

    with LDAP() as ldap:
        users = ldap.base.obj('ou=People',
                              tag=posix.USERS_BASE_TAG,
                              relative_search_scope=Scope.ONE,
                              rdn_attr='uid')
        groups = ldap.base.obj('ou=Groups',
                               tag=posix.GROUPS_BASE_TAG,
                               relative_search_scope=Scope.ONE,
                               rdn_attr='cn')

"""
from __future__ import absolute_import
from laurelin.ldap import LDAP, LDAPObject, LDAPError
from laurelin.ldap.attributetype import AttributeType
from laurelin.ldap.objectclass import ObjectClass, get_object_class
from laurelin.ldap.utils import CaseIgnoreDict


USERS_BASE_TAG = 'posix_users_base'
GROUPS_BASE_TAG = 'posix_groups_base'


def tag_flat_placement(tag):
    """Create a placement function putting objects below the specified tag"""
    def flat_placement(ldap, **kwds):
        """Place all objects directly below the user base"""
        return ldap.tag(tag).dn
    return flat_placement()


_user_placement_func = tag_flat_placement(USERS_BASE_TAG)
_group_placement_func = tag_flat_placement(GROUPS_BASE_TAG)


def set_user_placement_func(func):
    global _user_placement_func
    _user_placement_func = func


def set_group_placement_func(func):
    global _group_placement_func
    _group_placement_func = func


# RFC 2307 Schema elements for POSIX/shadow objects
# Modified from spec to be strictly conforming with RFC 4512
# nisSchema = 1.3.6.1.1.1

_posix_account = ObjectClass('''
        ( 1.3.6.1.1.1.2.0 NAME 'posixAccount'
          DESC 'Abstraction of an account with POSIX attributes'
          SUP top AUXILIARY
          MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory )
          MAY ( userPassword $ loginShell $ gecos $ description ) )
''')

ObjectClass('''
        ( 1.3.6.1.1.1.2.1 NAME 'shadowAccount'
          DESC 'Additional attributes for shadow passwords'
          SUP top AUXILIARY
          MUST uid
          MAY ( userPassword $ shadowLastChange $ shadowMin $
                shadowMax $ shadowWarning $ shadowInactive $
                shadowExpire $ shadowFlag $ description ) )
''')

_posix_group = ObjectClass('''
        ( 1.3.6.1.1.1.2.2 NAME 'posixGroup'
          DESC 'Abstraction of a group of accounts'
          SUP top STRUCTURAL
          MUST ( cn $ gidNumber )
          MAY ( userPassword $ memberUid $ description ) )
''')

# Attribute types

AttributeType('''
        ( 1.3.6.1.1.1.1.0 NAME 'uidNumber'
          DESC 'An integer uniquely identifying a user in an
                administrative domain'
          EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.1 NAME 'gidNumber'
          DESC 'An integer uniquely identifying a group in an
                administrative domain'
          EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.2 NAME 'gecos'
          DESC 'The GECOS field; the common name'
          EQUALITY caseIgnoreIA5Match
          SUBSTR caseIgnoreIA5SubstringsMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.3 NAME 'homeDirectory'
          DESC 'The absolute path to the home directory'
          EQUALITY caseExactIA5Match
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.4 NAME 'loginShell'
          DESC 'The path to the login shell'
          EQUALITY caseExactIA5Match
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.5 NAME 'shadowLastChange'
          EQUALITY integerMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.6 NAME 'shadowMin'
          EQUALITY integerMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.7 NAME 'shadowMax'
          EQUALITY integerMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.8 NAME 'shadowWarning'
          EQUALITY integerMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.9 NAME 'shadowInactive'
          EQUALITY integerMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.10 NAME 'shadowExpire'
          EQUALITY integerMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.11 NAME 'shadowFlag'
          EQUALITY integerMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
''')

AttributeType('''
        ( 1.3.6.1.1.1.1.12 NAME 'memberUid'
          EQUALITY caseExactIA5Match
          SUBSTR caseExactIA5SubstringsMatch
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
''')

USER_OBJECT_CLASS = _posix_account.names[0]
GROUP_OBJECT_CLASS = _posix_group.names[0]

USER_FILTER = '(objectClass={0})'.format(USER_OBJECT_CLASS)
GROUP_FILTER = '(objectClass={0})'.format(GROUP_OBJECT_CLASS)

USER_ATTRS = set(_posix_account.must)
USER_ATTRS.update(_posix_account.may)

GROUP_ATTRS = set(_posix_group.must)
GROUP_ATTRS.update(_posix_group.may)

DEFAULT_USER_RDN_ATTR = 'uid'
DEFAULT_GROUP_RDN_ATTR = 'cn'

USER_AUTO_CLASSES = ['shadowAccount', 'inetOrgPerson', 'organizationalPerson', 'person']
"""These classes will be searched in order to automatically add objectClasses when adding accounts. posixAccount is
always included."""

_LDAP_methods = []


def get_user(self, rdn, attrs=None):
    """get_user(rdn, attrs=None)

    Find a user

    :param str rdn: The username or an RDN
    :param attrs: List of attribute names to request. Defaults to all attributes.
    :type attrs: list[str] or None
    :return: The user account object
    :rtype: LDAPObject
    """
    return self.tag(USERS_BASE_TAG).find(rdn, attrs=attrs)


_LDAP_methods.append(get_user)


def get_group(self, rdn, attrs=None):
    """get_group(rdn, attrs=GROUP_ATTRS)

    Find a group

    :param str rdn: The group name or an RDN
    :param attrs: List of attribute names to request. Defaults to all group attributes.
    :type attrs: list[str] or None
    :return: The group object
    :rtype: LDAPObject
    """
    if attrs is None:
        attrs = list(GROUP_ATTRS)
    return self.tag(GROUPS_BASE_TAG).find(rdn, attrs=attrs)


_LDAP_methods.append(get_group)


def _place_user(self, **kwds):
    parent_dn = _user_placement_func(self, **kwds)
    return '{0}={1},{2}'.format(DEFAULT_USER_RDN_ATTR, kwds[DEFAULT_USER_RDN_ATTR], parent_dn)


_LDAP_methods.append(_place_user)


def _get_user_object_classes(attrs):
    """Find a minimal list of objectClass attributes to support the given list of attribute names"""
    attrs = set(attrs)
    object_classes = set((USER_OBJECT_CLASS,))
    for attr in USER_ATTRS:
        try:
            attrs.remove(attr)
        except KeyError:
            pass
    for oc_name in USER_AUTO_CLASSES:
        oc = get_object_class(oc_name)
        oc_attrs = set(oc.must)
        oc_attrs.update(oc.may)
        for attr in attrs:
            if attr in oc_attrs:
                object_classes.add(oc_name)
                attrs.remove(attr)
                oc_attrs.remove(attr)
                if not oc_attrs:
                    break
    if attrs:
        raise LDAPPOSIXError('Could not find objectClass for attributes: ' + ','.join(attrs))
    return list(object_classes)


def add_user(self, **kwds):
    kwds = CaseIgnoreDict(kwds)
    if 'objectClass' not in kwds:
        kwds['objectClass'] = _get_user_object_classes(list(kwds.keys()))
    for attr in kwds:
        if not isinstance(kwds[attr], list):
            kwds[attr] = list(kwds[attr])
    dn = self._place_user(**kwds)
    return self.add(dn, kwds)


_LDAP_methods.append(add_user)


def _place_group(self, **kwds):
    parent_dn = _group_placement_func(self, **kwds)
    return '{0}={1},{2}'.format(DEFAULT_GROUP_RDN_ATTR, kwds[DEFAULT_GROUP_RDN_ATTR], parent_dn)


_LDAP_methods.append(_place_group)


def add_group(self, **kwds):
    kwds = CaseIgnoreDict(kwds)
    if 'objectClass' not in kwds:
        kwds['objectClass'] = [GROUP_OBJECT_CLASS]
    for attr in kwds:
        if not isinstance(kwds[attr], list):
            kwds[attr] = list(kwds[attr])
    dn = self._place_group(**kwds)
    return self.add(dn, kwds)


_LDAP_methods.append(add_group)


def activate_extension():
    LDAP.EXTEND(_LDAP_methods)


class LDAPPOSIXError(LDAPError):
    pass
