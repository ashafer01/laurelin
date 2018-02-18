"""Extension adding netgroup support to laurelin.

Includes schema definitions.

You should begin by tagging the base object which all netgroups are below, and defining the RDN attribute and scope. If
the structure is flat there is a performance advantage by setting ``relative_search_scope=Scope.ONE``::

    from laurelin.ldap import LDAP, Scope
    netgroups_extension = LDAP.activate_extension('laurelin.extensions.netgroups')

    with LDAP() as ldap:
        netgroups = ldap.base.obj('ou=netgroups',
                                  tag=netgroups_extension.TAG,
                                  relative_search_scope=Scope.ONE,
                                  rdn_attr='cn')

Member Lists
^^^^^^^^^^^^

This extension module allows a shortcut to specify members of netgroups. Any function with a ``members`` argument uses
this feature.

The function name will tell you whether it expects users (e.g., :meth:`LDAP.add_netgroup_users`) or hosts (e.g.
:meth:`LDAP.add_netgroup_hosts`). If you just specify a string in your member list, it will be assumed to be either a
user or a host accordingly.

You can also specify a tuple with up to 3 elements for any member list entry. These fields must correspond to the
``nisNetgroupTriple`` fields: host, user, and domain. For user functions, at least the first 2 tuple elements must be
specified. For host functions, only the first is required, the 2nd (user) field will be assumed as an empty string. In
all cases, the domain can be specified for all members by passing the ``domain`` argument to the function (it defaults
to an empty string).

The third option for member list entries is to specify the full ``nisNetgroupTriple`` yourself in a string.

Finally, you can specify a ``memberNisNetgroup`` by prefixing the entry with a ``+`` symbol. For example: ``+users``.

Examples::

    users = [
       'alice',
       'bob',
       ('dir.example.org', 'admin'),
       '(dir.example.org,manager,example.org)',
    ]

    ldap.add_netgroup_users('cn=managers,ou=netgroups,dc=example,dc=org', users, domain='example.org')
    # Adds the following nisNetgroupTriples:
    #  (,alice,example.org)
    #  (,bob,example.org)
    #  (dir.example.org,admin,example.org)
    #  (dir.example.org,manager,example.org)
    # Does not add any memberNisNetgroups

    hosts = [
        'dir1.example.org',
        'dir2.example.org',
        '(dir3.example.org,,)',
        ('dir4.example.org',),
        '+aws_backup_dir_servers',
    ]

    ldap.add_netgroup_hosts('cn=dir_servers,ou=netgroups,dc=example,dc=org', hosts)
    # Adds the following nisNetgroupTriples:
    #  (dir1.example.org,,)
    #  (dir2.example.org,,)
    #  (dir3.example.org,,)
    #  (dir4.example.org,,)
    # Adds the following memberNisNetgroup:
    #  aws_backup_dir_servers
"""
from __future__ import absolute_import
import re
from laurelin.ldap import LDAP, LDAPObject, LDAPError
from laurelin.ldap.attributetype import AttributeType
from laurelin.ldap.objectclass import ObjectClass
from laurelin.ldap.rules import RegexSyntaxRule
import six

TAG = 'netgroup_base'
OBJECT_CLASS = 'nisNetgroup'
NETGROUP_ATTRS = ['cn', 'nisNetgroupTriple', 'memberNisNetgroup', 'objectClass']

_TRIPLE_RE = '^\(([^,]*),([^,]*),([^)]*)\)$'


## Schema definitions from RFC 2307


ObjectClass('''
( 1.3.6.1.1.1.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
  MUST cn
  MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
''')

AttributeType('''
( 1.3.6.1.1.1.1.13 NAME 'memberNisNetgroup'
  EQUALITY caseExactIA5Match
  SUBSTR caseExactIA5SubstringsMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
''')

AttributeType('''
( 1.3.6.1.1.1.1.14 NAME 'nisNetgroupTriple'
  DESC 'Netgroup triple'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.1.1.0.0 )
''')


class nisNetgroupTripleSytnax(RegexSyntaxRule):
    OID = '1.3.6.1.1.1.0.0'
    DESC = 'NIS netgroup triple'
    regex = _TRIPLE_RE


## LDAP extension methods

LDAP_methods = []


def get_netgroup(self, cn, attrs=NETGROUP_ATTRS):
    """get_netgroup(cn, attrs=NETGROUP_ATTRS)

    Find a specific netgroup object.

    This depends on the base object having been tagged and configured properly. See
    :mod:`laurelin.extensions.netgroups`.

    :param str cn: The name of the group or an RDN
    :param list[str] attrs: List of attribute names to get. Defaults to all netgroup attributes.
    :return: The netgroup object
    :rtype: LDAPObject
    :raises TagError: if the base object has not been tagged.
    """
    return self.tag(TAG).find(cn, attrs)


LDAP_methods.append(get_netgroup)


def netgroup_search(self, filter, attrs=NETGROUP_ATTRS):
    """netgroup_search(filter, attrs=NETGROUP_ATTRS)

    Search for netgroups.

    This depends on the base object having been tagged and configured properly. See
    :mod:`laurelin.extensions.netgroups`.

    :param str filter: A partial filter string. The nisNetgroup objectClass will automatically be included in the
                       filter sent to the server.
    :param list[str] attrs: List of attribute names to get. Defaults to all netgroup attributes.
    :return: An iterator over matching netgroup objects, yielding instances of :class:`.LDAPObject`.
    :rtype: SearchResultHandle
    :raises TagError: if the base object has not been tagged.
    """
    return self.tag(TAG).search(_netgroup_filter(filter), attrs)


LDAP_methods.append(netgroup_search)


def get_netgroup_obj_users(self, ng_obj, recursive=True):
    """get_netgroup_obj_users(ng_obj, recursive=True)

    Get a list of netgroup users from an already queried object, possibly querying for memberNisNetgroups if
    ``recursive=True`` (the default).

    :param LDAPObject ng_obj: A netgroup LDAP object
    :param bool recursive: Set to False to only consider members of this group directly
    :return: A list of usernames
    :rtype: list[str]
    """
    users = _extract_triple_field(ng_obj, 2)
    if recursive and ('memberNisNetgroup' in ng_obj):
        for member in ng_obj['memberNisNetgroup']:
            users += self.get_netgroup_users(member, True)
    return users


LDAP_methods.append(get_netgroup_obj_users)


def get_netgroup_users(self, cn, recursive=True):
    """get_netgroup_users(cn, recursive=True)

    Get a list of all user entries for a netgroup.

    This depends on the base object having been tagged and configured properly. See
    :mod:`laurelin.extensions.netgroups`.

    :param str cn: The name of the group or an RDN
    :param bool recursive: Recursively get users by following memberNisNetgroups
    :return: A list of usernames
    :rtype: list[str]
    :raises TagError: if the base object has not been tagged.
    """
    ng = self.get_netgroup(cn)
    return self.get_netgroup_obj_users(ng, recursive)


LDAP_methods.append(get_netgroup_users)


def get_netgroup_obj_hosts(self, ng_obj, recursive=True):
    """get_netgroup_obj_hosts(ng_obj, recursive=True)

    Get a list of netgroup hosts from an already queried object, possibly querying for memberNisNetgroups if
    ``recursive=True`` (the default).

    :param LDAPObject ng_obj: A netgroup LDAP object
    :param bool recursive: Set to False to only consider members of this group directly
    :return: A list of hostnames
    :rtype: list[str]
    """
    hosts = _extract_triple_field(ng_obj, 1)
    if recursive and ('memberNisNetgroup' in ng_obj):
        for member in ng_obj['memberNisNetgroup']:
            hosts += self.get_netgroup_hosts(member, True)
    return hosts


LDAP_methods.append(get_netgroup_obj_hosts)


def get_netgroup_hosts(self, cn, recursive=True):
    """get_netgroup_hosts(cn, recursive=True)

    Query a list of all host entries for a netgroup.

    This depends on the base object having been tagged and configured properly. See
    :mod:`laurelin.extensions.netgroups`.

    :param str cn: The name of the group or an RDN
    :param bool recursive: Recursively get hosts by following memberNisNetgroups
    :return: A list of hostnames
    :rtype: list[str]
    :raises TagError: if the base object has not been tagged.
    """
    ng = self.get_netgroup(cn)
    return self.get_netgroup_obj_hosts(ng, recursive)


LDAP_methods.append(get_netgroup_hosts)


def add_netgroup_users(self, dn, members, domain=''):
    """add_netgroup_users(dn, members, domain='')

    Add new users to a netgroup.

    :param str dn: The absolute DN of the netgroup object
    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or sinlge member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    """
    self.add_attrs(dn, _member_user_list_to_attrs(members, domain))


LDAP_methods.append(add_netgroup_users)


def add_netgroup_hosts(self, dn, members, domain=''):
    """add_netgroup_hosts(dn, members, domain='')

    Add new hosts to a netgroup.

    :param str dn: The absolute DN of the netgroup object
    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    """
    self.add_attrs(dn, _member_host_list_to_attrs(members, domain))


LDAP_methods.append(add_netgroup_hosts)


def replace_netgroup_users(self, dn, members, domain=''):
    """replace_netgroup_users(dn, members, domain='')

    Set new users on a netgroup.

    :param str dn: The absolute DN of the netgroup object
    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or sinlge member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    """
    self.replace_attrs(dn, _member_user_list_to_attrs(members, domain))


LDAP_methods.append(replace_netgroup_users)


def replace_netgroup_hosts(self, dn, members, domain=''):
    """replace_netgroup_hosts(dn, members, domain='')

    Set new hosts on a netgroup.

    :param str dn: The absolute DN of the netgroup object
    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    """
    self.replace_attrs(dn, _member_host_list_to_attrs(members, domain))


LDAP_methods.append(replace_netgroup_hosts)


def delete_netgroup_users(self, dn, members, domain=''):
    """delete_netgroup_users(dn, members, domain='')

    Delete users from a netgroup.

    :param str dn: The absolute DN of the netgroup object
    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or sinlge member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    """
    self.delete_attrs(dn, _member_user_list_to_attrs(members, domain))


LDAP_methods.append(delete_netgroup_users)


def delete_netgroup_hosts(self, dn, members, domain=''):
    """delete_netgroup_hosts(dn, members, domain='')

    Delete hosts from a netgroup.

    :param str dn: The absolute DN of the netgroup object
    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    """
    self.delete_attrs(dn, _member_host_list_to_attrs(members, domain))


LDAP_methods.append(delete_netgroup_hosts)


## LDAPObject extension methods

LDAPObject_methods = []


def _require_netgroup(self):
    """Requires that this :class:`.LDAPObject` has the required netgroup object class.

    :raises RuntimeError: if the object is missing the netgroup object class
    """
    if not self.has_object_class(OBJECT_CLASS):
        raise RuntimeError('objectClass {0} is required'.format(OBJECT_CLASS))


LDAPObject_methods.append(_require_netgroup)


def obj_get_netgroup_users(self, recursive=True):
    """obj_get_netgroup_users(recursive=True)

    Get all users in this netgroup object.

    :param bool recursive: Set to False to ignore any memberNisNetgroups defined for this object.
    :return: A list of usernames
    :rtype: list[str]
    :raises RuntimeError: if this object is missing the netgroup object class
    """
    self._require_netgroup()
    return self.ldap_conn.get_netgroup_obj_users(self, recursive)


obj_get_netgroup_users.__name__ = 'get_netgroup_users'
LDAPObject_methods.append(obj_get_netgroup_users)


def obj_get_netgroup_hosts(self, recursive=True):
    """obj_get_netgroup_hosts(recursive=True)

    Get all hosts in this netgroup object.

    :param bool recursive: Set to False to ignore any memberNisNetgroups defined for this object.
    :return: A list of hostnames
    :rtype: list[str]
    :raises RuntimeError: if this object is missing the netgroup object class
    """
    self._require_netgroup()
    return self.ldap_conn.get_netgroup_obj_hosts(self, recursive)


obj_get_netgroup_hosts.__name__ = 'get_netgroup_hosts'
LDAPObject_methods.append(obj_get_netgroup_hosts)


def obj_add_netgroup_users(self, members, domain=''):
    """obj_add_netgroup_users(members, domain='')

    Add new user netgroup entries to this netgroup object.

    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    :raises RuntimeError: if this object is missing the netgroup object class
    """
    self._require_netgroup()
    self.add_attrs(_member_user_list_to_attrs(members, domain))


obj_add_netgroup_users.__name__ = 'add_netgroup_users'
LDAPObject_methods.append(obj_add_netgroup_users)


def obj_add_netgroup_hosts(self, members, domain=''):
    """obj_add_netgroup_hosts(members, domain='')

    Add new host netgroup entries to this netgroup object.

    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    :raises RuntimeError: if this object is missing the netgroup object class
    """
    self._require_netgroup()
    self.add_attrs(_member_host_list_to_attrs(members, domain))


obj_add_netgroup_hosts.__name__ = 'add_netgroup_hosts'
LDAPObject_methods.append(obj_add_netgroup_hosts)


def obj_replace_netgroup_users(self, members, domain=''):
    """obj_replace_netgroup_users(members, domain='')

    Set new user netgroup entries on this netgroup object.

    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    :raises RuntimeError: if this object is missing the netgroup object class
    """
    self._require_netgroup()
    self.replace_attrs(_member_user_list_to_attrs(members, domain))


obj_replace_netgroup_users.__name__ = 'replace_netgroup_users'
LDAPObject_methods.append(obj_replace_netgroup_users)


def obj_replace_netgroup_hosts(self, members, domain=''):
    """obj_replace_netgroup_hosts(members, domain='')

    Set new host netgroup entries on this netgroup object.

    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    :raises RuntimeError: if this object is missing the netgroup object class
    """
    self._require_netgroup()
    self.replace_attrs(_member_host_list_to_attrs(members, domain))


obj_replace_netgroup_hosts.__name__ = 'replace_netgroup_hosts'
LDAPObject_methods.append(obj_replace_netgroup_hosts)


def obj_delete_netgroup_users(self, members, domain=''):
    """obj_delete_netgroup_users(members, domain='')

    Delete user netgroup entries from this netgroup object.

    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    :raises RuntimeError: if this object is missing the netgroup object class
    """
    self._require_netgroup()
    self.delete_attrs(_member_user_list_to_attrs(members, domain))


obj_delete_netgroup_users.__name__ = 'delete_netgroup_users'
LDAPObject_methods.append(obj_delete_netgroup_users)


def obj_delete_netgroup_hosts(self, members, domain=''):
    """obj_delete_netgroup_hosts(members, domain='')

    Delete host netgroup entries from this netgroup object.

    :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
    :type members: list or str or tuple
    :param str domain: The default domain to use in nisNetgroupTriples where not already specified
    :rtype: None
    :raises RuntimeError: if this object is missing the netgroup object class
    """
    self._require_netgroup()
    self.delete_attrs(_member_host_list_to_attrs(members, domain))


obj_delete_netgroup_hosts.__name__ = 'delete_netgroup_hosts'
LDAPObject_methods.append(obj_delete_netgroup_hosts)


## Extension activation function


def activate_extension():
    """Extension activation function. Installs extension methods to :class:`.LDAP` and :class:`.LDAPObject`"""
    LDAP.EXTEND(LDAP_methods)
    LDAPObject.EXTEND(LDAPObject_methods)


## private functions


TRIPLE_RE = re.compile(_TRIPLE_RE)


def _netgroup_filter(filter):
    return '(&(objectClass={0}){1})'.format(OBJECT_CLASS, filter)


def _is_triple(val):
    return (TRIPLE_RE.match(val) is not None)


def _nis_netgroup_triple(host, user, domain):
    return '({0},{1},{2})'.format(host, user, domain)


def _extract_triple_field(ng_obj, index):
    ret = []
    for triple in ng_obj.get('nisNetgroupTriple', []):
        m = TRIPLE_RE.match(triple)
        if m is None:
            raise LDAPError('Invalid nisNetgroupTriple: {0}'.format(triple))
        else:
            ret.append(m.group(index))
    return ret


def _member_user_list_to_attrs(member_list, domain=''):
    if not isinstance(member_list, list):
        member_list = [member_list]
    attrs = {}
    for member in member_list:
        attr = 'nisNetgroupTriple'
        if isinstance(member, six.string_types):
            if member[0] == '+':
                attr = 'memberNisNetgroup'
                member = member[1:]
            else:
                if not _is_triple(member):
                    member = _nis_netgroup_triple('', member, domain)
        elif isinstance(member, tuple):
            if len(member) == 1:
                raise ValueError('At least first 2 triple values (host,user) must be specified for users')
            elif len(member) == 2:
                member = _nis_netgroup_triple(member[0], member[1], domain)
            elif len(member) == 3:
                member = _nis_netgroup_triple(*member)
            else:
                raise ValueError('tuple must have 2 or 3 elements')
        else:
            raise TypeError('member_list elements must be string or tuple')
        if attr not in attrs:
            attrs[attr] = []
        attrs[attr].append(member)
    return attrs


def _member_host_list_to_attrs(member_list, domain=''):
    if not isinstance(member_list, list):
        member_list = [member_list]
    attrs = {}
    for member in member_list:
        attr = 'nisNetgroupTriple'
        if isinstance(member, six.string_types):
            if member[0] == '+':
                attr = 'memberNisNetgroup'
                member = member[1:]
            else:
                if not _is_triple(member):
                    member = _nis_netgroup_triple(member, '', domain)
        elif isinstance(member, tuple):
            if len(member) == 1:
                member = _nis_netgroup_triple(member[0], '', domain)
            elif len(member) == 2:
                member = _nis_netgroup_triple(member[0], member[1], domain)
            elif len(member) == 3:
                member = _nis_netgroup_triple(*member)
            else:
                raise ValueError('tuple must have 1-3 elements')
        else:
            raise TypeError('member_list elements must be string or tuple')
        if attr not in attrs:
            attrs[attr] = []
        attrs[attr].append(member)
    return attrs
