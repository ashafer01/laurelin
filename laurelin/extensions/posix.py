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

Adding Users and Groups
^^^^^^^^^^^^^^^^^^^^^^^

The :meth:`LDAP.add_user` and :meth:`LDAP.add_group` methods work by taking attribute names as keyword arguments.
Since many user and group attributes have the single-value constraint, passing a list of values is optional.

The extension will also automatically attempt to fill missing required attributes. This includes ``objectClass`` for
both users and groups, ``uidNumber``, ``gidNumber``, ``cn``, ``homeDirectory``, for users, and ``gidNumber`` for groups.

For both users and groups, the DN will be automatically constructed (if not specified with the ``dn`` keyword) by using
a *placement function*. There is both a user and group placement function. It takes in the attribute keywords passed to
the add function, and returns a new **parent** DN. The RDN is generated using the configured default RDN attribute. See
the reference below for how to specify placement functions.

By default any gaps will be filled in your uid/gid number range. You can turn this feature off, and automatically
increment the highest number by passing ``fill_gaps=False``. You can also set the module level attribute
:attr:`.posix.DEFAULT_FILL_GAPS` to change the default setting.

Configuration Reference
^^^^^^^^^^^^^^^^^^^^^^^

:attr:`.posix.MIN_AUTO_UID_NUMBER`
    Default ``1000``. The minimum uidNumber that will be automatically filled when missing from a new user creation.

:attr:`.posix.MIN_AUTO_GID_NUMBER`
    Default ``1000``. The minimum gidNumber that will be automatically filled when missing from a new group creation.

:attr:`.posix.DEFAULT_GIDNUMBER`
    Default ``1000``. The default gidNumber that will be automatically filled when missing from a new user creation.

:attr:`.posix.DEFAULT_USER_RDN_ATTR`
    Default ``'uid'``. The default RDN attribute to use when creating new users. If ``rdn_attr`` was specified on the
    tagged base object, this will not be used.

:attr:`.posix.DEFAULT_GROUP_RDN_ATTR`
    Default ``'cn'``. The default RDN attribute to use when creating new groups. If ``rdn_attr`` was specified on the
    tagged base object, this will not be used.

:attr:`.posix.HOMEDIR_FORMAT`
    Default ``'/home/{uid}'``. Gets string formatted with the attribute keywords before getting used as the default
    ``homeDirectory`` attribute.

:attr:`.posix.DEFAULT_FILL_GAPS`
    Default ``True``. When generating uidNumber or gidNumber, fill gaps in the range. Set ``False`` to use the highest
    known id number incremented by default.

:func:`.posix.UserPlacement.select`
    Pass this a new function that accepts an :class:`LDAP` instance as well as all of the attribute keywords passed to
    :meth:`LDAP.add_user`. It should return a new parent DN string for the user object. The RDN will be automatically
    generated seperately.

:func:`.posix.GroupPlacement.select`
    Pass this a new function that accepts an :class:`LDAP` instance as well as all of the attribute keywords passed to
    :meth:`LDAP.add_group`. It should return a new parent DN string for the group object. The RDN will be
    automatically generated seperately.


"""
from __future__ import absolute_import
from laurelin.ldap import LDAP, LDAPObject, LDAPError, NoSearchResults
from laurelin.ldap.attributetype import AttributeType
from laurelin.ldap.objectclass import ObjectClass, get_object_class
from laurelin.ldap.utils import CaseIgnoreDict, get_one_result

from datetime import datetime

# needed?
import laurelin.ldap.schema


USERS_BASE_TAG = 'posix_users_base'
GROUPS_BASE_TAG = 'posix_groups_base'

# settings

MIN_AUTO_UID_NUMBER = 1000
MIN_AUTO_GID_NUMBER = 1000

HOMEDIR_FORMAT = '/home/{uid}'

DEFAULT_USER_RDN_ATTR = 'uid'
DEFAULT_GROUP_RDN_ATTR = 'cn'
DEFAULT_GIDNUMBER = '1000'
DEFAULT_FILL_GAPS = True


# placement stuff


def _tag_flat_placement(tag):
    """Create a placement function putting objects below the specified tag"""
    def flat_placement(ldap, **kwds):
        """Place all objects directly below the tagged base object"""
        return ldap.tag(tag).dn
    return flat_placement


def _tag_year_placement(tag):
    """Create a placement function for organizing users/groups by creation year"""
    def year_placement(ldap, **kwds):
        """Place new users/groups under an OU for the current year. Creates OU if necessary"""
        year = datetime.utcnow().year
        year_obj = _add_or_get_child_ou(ldap, tag, year)
        return year_obj.dn
    return year_placement


def _alpha_placement(tag, default_rdn_attr):
    """Create a placement function for organizing users/groups by first character of RDN value"""
    def alpha_placement(ldap, **kwds):
        """Place new users/groups under an OU for the first characters of their RDN value. Creates OU if necessary"""
        rdn_attr = ldap._get_rdn_attr(tag, default_rdn_attr)
        rdn_value = _get_kwd_attr(kwds, rdn_attr)
        char = rdn_value[0].upper()
        char_obj = _add_or_get_child_ou(ldap, tag, char)
        return char_obj.dn
    return alpha_placement


def _idnumber_range_placement(tag, idnumber_attr, range_size):
    """Create a placement function for organizing users/groups by uid/gid number range"""
    def idnumber_range_placement(ldap, **kwds):
        """Place new users/groups under an OU based on ID number range. Creates OU if necessary."""
        idnumber = int(_get_kwd_attr(kwds, idnumber_attr))
        idnumber_range = idnumber - (idnumber % range_size)
        range_ou = _add_or_get_child_ou(ldap, tag, idnumber_range)
        return range_ou.dn
    return idnumber_range_placement


class PlacementDomain(object):
    _selected = None

    @classmethod
    def select(cls, method):
        cls._selected = method

    @classmethod
    def run(cls, ldap_conn, **kwds):
        return cls._selected(ldap_conn, **kwds)


class UserPlacement(PlacementDomain):
    """These are pre-defined user placement functions. :meth:`UserPlacement.FLAT` is selected by default. Pass your
    chosen function (it doesn't have to be one of these) to ``UserPlacement.select()`` to use it with
    :meth:`LDAP.add_user`.

    Example::

        from laurelin.ldap import LDAP, Scope
        posix = LDAP.activate_extension('laurelin.extensions.posix')
        posix.UserPlacement.select(posix.UserPlacement.UID_100S)
        with LDAP() as ldap:
            ldap.base.obj('ou=people',
                          tag=posix.USERS_BASE_TAG,
                          rdn_attr='uid',
                          relative_search_scope=Scope.SUBTREE)
            ldap.add_user(uid='testuser1', uidNumber=4567)
            ldap.add_user(uid='testuser2', uidNumber=5678)

        # Produces the following tree structure:
        # dc=example,dc=org
        #   ou=people
        #     ou=4500
        #       uid=testuser1
        #     ou=5600
        #       uid=testuser2
    """

    FLAT = staticmethod(_tag_flat_placement(USERS_BASE_TAG))
    YEAR = staticmethod(_tag_year_placement(USERS_BASE_TAG))
    ALPHA = staticmethod(_alpha_placement(USERS_BASE_TAG, DEFAULT_USER_RDN_ATTR))
    UID_100S = staticmethod(_idnumber_range_placement(USERS_BASE_TAG, 'uidNumber', 100))
    UID_1000S = staticmethod(_idnumber_range_placement(USERS_BASE_TAG, 'uidNumber', 1000))

    @staticmethod
    def PRIMARY_GROUP(ldap, **kwds):
        """Place new users below the primary group object. Error if group does not exist.

        Note that if using this placement function, you would need to have the same object tagged as user and group
        base. The group base object would probably have a search scope of ``onelevel``, and the user base would have
        ``subtree``.
        """
        group = ldap.find_group(gidNumber=_get_kwd_attr(kwds, 'gidNumber'))
        return group.dn

    _selected = FLAT


class GroupPlacement(PlacementDomain):
    """These are pre-defined group placement functions. :meth:`GroupPlacement.FLAT` is selected by default. Pass your
    chosen function (it doesn't have to be one of these) to ``GroupPlacement.select()`` to use it with
    :meth:`LDAP.add_group`."""
    FLAT = staticmethod(_tag_flat_placement(GROUPS_BASE_TAG))
    YEAR = staticmethod(_tag_year_placement(GROUPS_BASE_TAG))
    ALPHA = staticmethod(_alpha_placement(GROUPS_BASE_TAG, DEFAULT_GROUP_RDN_ATTR))
    GID_100S = staticmethod(_idnumber_range_placement(GROUPS_BASE_TAG, 'gidNumber', 100))
    GID_1000S = staticmethod(_idnumber_range_placement(GROUPS_BASE_TAG, 'gidNumber', 1000))

    _selected = FLAT


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

_shadow_account = ObjectClass('''
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

# utility stuff

USER_OBJECT_CLASS = _posix_account.names[0]
GROUP_OBJECT_CLASS = _posix_group.names[0]

USER_ATTRS = set(_posix_account.must)
USER_ATTRS.update(_posix_account.may)

GROUP_ATTRS = set(_posix_group.must)
GROUP_ATTRS.update(_posix_group.may)

# LDAP extension methods

_LDAP_methods = []


def find_user(self, **kwds):
    """find_user(**kwds)

    Find a user object based on attributes other than the RDN.

    Give attributes to search with as keywords. Wrapping single-value attributes in a list is OPTIONAL.

    You can specify the ``attrs`` keyword to limit attributes retrieved from the server.
    """
    attrs = kwds.pop('attrs', None)
    filter = _kwds_to_filter(kwds)
    res = list(self.tag(USERS_BASE_TAG).search(filter=filter, attrs=attrs, limit=2))
    return get_one_result(res)


_LDAP_methods.append(find_user)


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


def find_group(self, **kwds):
    """find_group(**kwds)

    Find a group object based on attributes other than the RDN.

    Give attributes to search with as keywords. Wrapping single-value attributes in a list is OPTIONAL.
    """
    attrs = kwds.pop('attrs', None)
    filter = _kwds_to_filter(kwds)
    res = list(self.tag(GROUPS_BASE_TAG).search(filter=filter, attrs=attrs, limit=2))
    return get_one_result(res)


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


def _get_rdn_attr(self, tag, default):
    rdn_attr = self.tag(tag).rdn_attr
    if rdn_attr:
        return rdn_attr
    else:
        return default


_LDAP_methods.append(_get_rdn_attr)


def _place_user(self, **kwds):
    parent_dn = UserPlacement.run(self, **kwds)
    rdn_attr = self._get_rdn_attr(USERS_BASE_TAG, DEFAULT_USER_RDN_ATTR)
    return '{0}={1},{2}'.format(rdn_attr, _get_kwd_attr(kwds, rdn_attr), parent_dn)


_LDAP_methods.append(_place_user)


def _get_uid_numbers(self):
    uid_numbers = []
    with self.tag(USERS_BASE_TAG).search(filter='(uidNumber=*)', attrs=['uidNumber']) as search:
        for user in search:
            uid_number = int(user['uidNumber'][0])
            if uid_number >= MIN_AUTO_UID_NUMBER:
                uid_numbers.append(uid_number)
    return uid_numbers


_LDAP_methods.append(_get_uid_numbers)


def add_user(self, **kwds):
    """add_user(**kwds)

    Add a new user. Pass attributes as keywords. Single-value attributes DO NOT need to be wrapped in a list.

    If the ``dn`` keyword is not passed, the DN will be automatically generated using the user placement function and
    the passed attribute keywords. The default placement function puts all objects directly below the tagged base user
    object.

    ``uid`` is required by this function as well as the object class.

    ``objectClass`` will be automatically filled based on attributes used. You can use any posixAccount attributes, as
    well as those in ``shadowAccount``, ``person``, ``organizationalPerson`` and ``inetOrgPerson``. You can also specify
    the ``objectClass`` yourself.

    ``uidNumber`` is required by the object class. If not supplied, performs a search for all uidNumbers below the
    tagged user base to find an available id number. Respects the ``fill_gaps`` keyword argument which defaults True,
    and determines whether or not to fill gaps in the id number range, or to always increment the highest id number.

    ``gidNumber``, or the user's primary group, is required by the spec. If not specified, defaults to
    :attr:`.posix.DEFAULT_GIDNUMBER`.

    ``cn`` is required by the object class and if not specified, defaults to ``uid``.

    ``homeDirectory`` is required by the object class, and defaults to using :attr:`.posix.HOMEDIR_FORMAT` to generate
    the directory from the other user attribute keywords.

    :return: The newly created user object
    :rtype: LDAPObject
    """
    kwds = CaseIgnoreDict(kwds)
    if 'uid' not in kwds:
        raise TypeError('Missing required keyword uid')
    fill_gaps = kwds.pop('fill_gaps', DEFAULT_FILL_GAPS)
    if 'uidNumber' not in kwds:
        all_uidnumbers = self._get_uid_numbers()
        my_uidnumber = _find_available_idnumber(all_uidnumbers, MIN_AUTO_UID_NUMBER, fill_gaps)
        kwds['uidNumber'] = [my_uidnumber]
    if 'cn' not in kwds:
        kwds['cn'] = kwds['uid']
    if 'homeDirectory' not in kwds:
        kwds['homeDirectory'] = [HOMEDIR_FORMAT.format(**kwds)]
    if 'gidNumber' not in kwds:
        kwds['gidNumber'] = [DEFAULT_GIDNUMBER]
    try:
        dn = kwds.pop('dn')
    except KeyError:
        dn = self._place_user(**kwds)
    if 'objectClass' not in kwds:
        kwds['objectClass'] = _get_user_object_classes(list(kwds.keys()))
    attrs_dict = _kwds_to_attrs_dict(kwds)
    return self.add(dn, attrs_dict)


_LDAP_methods.append(add_user)


def update_user(self, dn, **kwds):
    """update_user(dn, **kwds)

    Update attributes on a user object. Performs a modify replace operation, allowing new attributes to be added,
    existing attributes to be replaced, and all values for an attribute to be deleted.

    Pass attribute keywords with new values. Single-value attributes DO NOT need to be wrapped in a list.

    :param str dn: The DN of the user to update
    :return: None
    """
    # TODO update objectClass - need to know current attrs to combine with new
    self.replace_attrs(dn, _kwds_to_attrs_dict(kwds))


_LDAP_methods.append(update_user)


def _place_group(self, **kwds):
    parent_dn = GroupPlacement.run(self, **kwds)
    rdn_attr = self._get_rdn_attr(GROUPS_BASE_TAG, DEFAULT_GROUP_RDN_ATTR)
    return '{0}={1},{2}'.format(rdn_attr, _get_kwd_attr(kwds, rdn_attr), parent_dn)


_LDAP_methods.append(_place_group)


def add_group(self, **kwds):
    """add_group(**kwds)

    Create a new group. Pass attributes as keywords. Single-value attributes DO NOT need to be wrapped in a list.

    If the ``dn`` keyword is not passed, the DN will be automatically generated using the group placement function and
    the passed attribute keywords. The default placement function puts all objects directly below the tagged base
    group object.

    ``cn`` is required by this function as well as the object class.

    ``objectClass`` will be automatically set to ``posixGroup`` if not defined.

    ``gidNumber`` is required by the object class. If not supplied, performs a search for all gidNumbers below the
    tagged group base to find an available id number. Respects the ``fill_gaps`` keyword argument which defaults True,
    and determines whether or not to fill gaps in the id number range, or to always increment the highest id number.

    :return: The new group object
    :rtype: LDAPObject
    """
    kwds = CaseIgnoreDict(kwds)
    if 'cn' not in kwds:
        raise TypeError('Missing required keyword cn')
    if 'gidNumber' not in kwds:
        fill_gaps = kwds.pop('fill_gaps', DEFAULT_FILL_GAPS)
        all_gidnumbers = self._get_gid_numbers()
        my_gidnumber = _find_available_idnumber(all_gidnumbers, MIN_AUTO_GID_NUMBER, fill_gaps)
        kwds['gidNumber'] = [my_gidnumber]
    if 'objectClass' not in kwds:
        kwds['objectClass'] = [GROUP_OBJECT_CLASS]
    try:
        dn = kwds.pop('dn')
    except KeyError:
        dn = self._place_group(**kwds)
    attrs_dict = _kwds_to_attrs_dict(kwds)
    return self.add(dn, attrs_dict)


_LDAP_methods.append(add_group)


def update_group(self, dn, **kwds):
    """update_group(dn, **kwds)

    Update attributes on a group object. Performs a modify replace operation, allowing new attributes to be added,
    existing attributes to be replaced, and all values for an attribute to be deleted.

    Pass attribute keywords with new values. Single-value attributes DO NOT need to be wrapped in a list.

    :param str dn: The DN of the group to update
    :return: None
    """
    self.replace_attrs(dn, _kwds_to_attrs_dict(kwds))


_LDAP_methods.append(update_group)


def add_group_members(self, dn, member_uid):
    """add_group_members(dn, member_uid)

    Add new members to a POSIX group

    :param str dn: The DN of the group to add members to
    :param list[str] member_uid: A list of new member usernames to add
    :return: None
    """
    self.add_attrs(dn, {'memberUid': member_uid})


_LDAP_methods.append(add_group_members)


def delete_group_members(self, dn, member_uid):
    """delete_group_members(dn, member_uid)

    Delete members from a POSIX group

    :param str dn: The DN/ of the group to remove members from
    :param list[str] member_uid: A list of member usernames to delete
    :return: None
    """
    self.delete_attrs(dn, {'memberUid': member_uid})


_LDAP_methods.append(delete_group_members)


# LDAPObject extensions methods

_LDAPObject_methods = []


def _require_user(self):
    if not self.has_object_class(USER_OBJECT_CLASS):
        raise RuntimeError('objectClass {0} is required'.format(USER_OBJECT_CLASS))


_LDAPObject_methods.append(_require_user)


def _require_group(self):
    if not self.has_object_class(GROUP_OBJECT_CLASS):
        raise RuntimeError('objectClass {0} is required'.format(GROUP_OBJECT_CLASS))


_LDAPObject_methods.append(_require_group)


def obj_update_user(self, **kwds):
    """obj_update_user(**kwds)

    Update attributes on this user object. Performs a modify replace operation, allowing new attributes to be added,
    existing attributes to be replaced, and all values for an attribute to be deleted.

    Pass attribute keywords with new values. Single-value attributes DO NOT need to be wrapped in a list.

    :return: None
    """
    self._require_user()
    # TODO objectClasses
    self.replace_attrs(_kwds_to_attrs_dict(kwds))


obj_update_user.__name__ = 'update_user'
_LDAPObject_methods.append(obj_update_user)


def obj_update_group(self, **kwds):
    """obj_update_group(**kwds)

    Update attributes on this group object. Performs a modify replace operation, allowing new attributes to be added,
    existing attributes to be replaced, and all values for an attribute to be deleted.

    Pass attribute keywords with new values. Single-value attributes DO NOT need to be wrapped in a list.

    :return: None
    """
    self._require_group()
    self.replace_attrs(_kwds_to_attrs_dict(kwds))


obj_update_group.__name__ = 'update_group'
_LDAPObject_methods.append(obj_update_group)


def obj_add_group_members(self, member_uid):
    """obj_add_group_members(member_uid)

    Add new members to this POSIX group

    :return: None
    """
    self._require_group()
    self.add_attrs({'memberUid': member_uid})


obj_add_group_members.__name__ = 'add_group_members'
_LDAPObject_methods.append(obj_add_group_members)


def obj_delete_group_members(self, member_uid):
    """obj_delete_group_members(member_uid)

    Delete members from this POSIX group

    :return: None
    """
    self._require_group()
    self.delete_attrs({'memberUid': member_uid})


obj_delete_group_members.__name__ = 'delete_group_members'
_LDAPObject_methods.append(obj_delete_group_members)


# activation function


def activate_extension():
    LDAP.EXTEND(_LDAP_methods)
    LDAPObject.EXTEND(_LDAPObject_methods)


# private functions

def _kwds_to_attrs_dict(kwds):
    for attr in kwds:
        val = kwds[attr]
        if not isinstance(val, list):
            kwds[attr] = [val]
    return kwds


def _kwds_to_filter(kwds):
    and_items = ''
    for attr in kwds:
        values = kwds[attr]
        if isinstance(values, list):
            for value in values:
                and_items += '({0}={1})'.format(attr, value)
        else:
            and_items += '({0}={1})'.format(attr, values)
    and_items = '(&({0}))'.format(and_items)
    return and_items


def _get_kwd_attr(kwds, attr):
    values = kwds[attr]
    if isinstance(values, list):
        if len(values) == 1:
            return values[0]
        else:
            raise TypeError('Too many values for {0}'.format(attr))
    else:
        return values


def _find_available_idnumber(id_numbers, min, fill_gaps):
    if not id_numbers:
        return str(min)
    n_id_numbers = len(id_numbers)
    if n_id_numbers == 1:
        idn = id_numbers[0]
        if fill_gaps and idn != min:
            return str(min)
        else:
            return str(idn+1)
    unique_id_numbers = set(id_numbers)
    if len(unique_id_numbers) != n_id_numbers:
        raise LDAPPOSIXError('Duplicate ID numbers')
    id_numbers.sort()
    if fill_gaps:
        if id_numbers[0] != min:
            return str(min)
        for i in range(len(id_numbers)-1):
            id_number = id_numbers[i]
            if id_number+1 < id_numbers[i+1]:
                return str(id_number+1)
        return str(id_numbers[i+1]+1)
    else:
        return str(id_numbers[-1]+1)


def _get_oc_attrs(oc):
    oc_attrs = set(oc.must)
    oc_attrs.update(oc.may)
    return oc_attrs


def _get_oc_name_attrs(oc_name):
    oc = get_object_class(oc_name)
    return _get_oc_attrs(oc)


def _get_user_object_classes(attrs):
    """Find a minimal list of objectClass attributes to support the given list of attribute names"""
    attrs_set = set()
    for attr in attrs:
        attr = attr.lower()
        attrs_set.add(attr)
    attrs_set.add('objectclass')
    attrs = attrs_set

    object_classes = set((USER_OBJECT_CLASS,))

    for attr in USER_ATTRS:
        try:
            attrs.remove(attr.lower())
        except KeyError:
            pass

    shadow_account = False
    for attr in _get_oc_attrs(_shadow_account):
        try:
            attrs.remove(attr)
            shadow_account = True
        except KeyError:
            pass
    if shadow_account:
        object_classes.add(_shadow_account.names[0])

    inheritance_chain = ['top', 'person', 'organizationalPerson', 'inetOrgPerson']
    max_index = -1
    for i, oc_name in enumerate(inheritance_chain):
        for attr in _get_oc_name_attrs(oc_name):
            try:
                attrs.remove(attr.lower())
                if i > max_index:
                    max_index = i
            except KeyError:
                pass
    if max_index > -1:
        object_classes.add(inheritance_chain[max_index])

    if attrs:
        raise LDAPPOSIXError('Could not find objectClass for attributes: ' + ','.join(attrs))
    return list(object_classes)


def _add_or_get_child_ou(ldap, tag, ou):
    rdn = 'ou={0}'.format(ou)
    try:
        obj = ldap.tag(tag).get_child(rdn)
    except NoSearchResults:
        obj = ldap.tag(tag).add_child(rdn, {
            'objectClass': ['organizationalUnit'],
            'ou': [ou],
        })
    return obj


class LDAPPOSIXError(LDAPError):
    pass
