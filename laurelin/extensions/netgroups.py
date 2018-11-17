"""Extension adding netgroup support to laurelin.

Includes schema definitions.

You should begin by tagging the base object which all netgroups are below, and defining the RDN attribute and scope. If
the structure is flat there is a performance advantage by setting ``relative_search_scope=Scope.ONE``::

    from laurelin.ldap import LDAP, Scope, extensions

    with LDAP() as ldap:
        ldap.base.obj('ou=netgroups',
                      tag=extensions.netgroups.TAG,
                      relative_search_scope=Scope.ONE,
                      rdn_attr='cn')

Member Lists
^^^^^^^^^^^^

This extension module allows a shortcut to specify members of netgroups. Any function with a ``members`` argument uses
this feature.

The function name will tell you whether it expects users (e.g., ``add_users``) or hosts (e.g. ``add_hosts``). If you
just specify a string in your member list, it will be assumed to be either a user or a host accordingly.

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
       '(dir.example.org,manager,secrets.example.org)',
    ]

    ldap.netgroups.add_users('cn=managers,ou=netgroups,dc=example,dc=org', users, domain='example.org')
    # Adds the following nisNetgroupTriples:
    #  (,alice,example.org)
    #  (,bob,example.org)
    #  (dir.example.org,admin,example.org)
    #  (dir.example.org,manager,secrets.example.org)
    # Does not add any memberNisNetgroups

    hosts = [
        'dir1.example.org',
        'dir2.example.org',
        '(dir3.example.org,,)',
        ('dir4.example.org',),
        '+aws_backup_dir_servers',
    ]

    ldap.netgroups.add_hosts('cn=dir_servers,ou=netgroups,dc=example,dc=org', hosts)
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
from laurelin.ldap import (
    AttributeType,
    ObjectClass,
    get_object_class,
    RegexSyntaxRule,
    LDAPError,
    extensions,
    BaseLaurelinExtension,
    BaseLaurelinSchema,
    BaseLaurelinLDAPExtension,
    BaseLaurelinLDAPObjectExtension,
)
import six

extensions.base_schema.require()

TAG = 'netgroup_base'

_TRIPLE_RE = '^\(([^,]*),([^,]*),([^)]*)\)$'


class LaurelinExtension(BaseLaurelinExtension):
    NAME = 'netgroups'
    TAG = TAG


class LaurelinSchema(BaseLaurelinSchema):
    NIS_NETGROUP = ObjectClass('''
    ( 1.3.6.1.1.1.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
      MUST cn
      MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
    ''')

    MEMBER_NIS_NETGROUP = AttributeType('''
    ( 1.3.6.1.1.1.1.13 NAME 'memberNisNetgroup'
      EQUALITY caseExactIA5Match
      SUBSTR caseExactIA5SubstringsMatch
      SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
    ''')

    NIS_NETGROUP_TRIPLE = AttributeType('''
    ( 1.3.6.1.1.1.1.14 NAME 'nisNetgroupTriple'
      DESC 'Netgroup triple'
      EQUALITY caseExactMatch
      SYNTAX 1.3.6.1.1.1.0.0 )
    ''')

    class NisNetgroupTripleSytnax(RegexSyntaxRule):
        OID = '1.3.6.1.1.1.0.0'
        DESC = 'NIS netgroup triple'
        regex = _TRIPLE_RE


OBJECT_CLASS = 'nisNetgroup'


def _netgroup_attrs():
    oc = get_object_class(OBJECT_CLASS)
    return oc.must + oc.may


def _netgroup_attrs_arg(attrs_arg):
    if attrs_arg is None:
        return _netgroup_attrs()
    else:
        return attrs_arg


class LaurelinLDAPExtension(BaseLaurelinLDAPExtension):
    def get(self, cn, attrs=None):
        """Find a specific netgroup object.

        This depends on the base object having been tagged and configured properly. See
        :mod:`laurelin.extensions.netgroups`.

        :param str cn: The name of the group or an RDN
        :param list[str] attrs: List of attribute names to get. Defaults to all netgroup attributes.
        :return: The netgroup object
        :rtype: LDAPObject
        :raises TagError: if the base object has not been tagged.
        """
        attrs = _netgroup_attrs_arg(attrs)
        return self.parent.tag(TAG).find(cn, attrs)

    def search(self, filter, attrs=None):
        """Search for netgroups.

        This depends on the base object having been tagged and configured properly. See
        :mod:`laurelin.extensions.netgroups`.

        :param str filter: A partial filter string. The nisNetgroup objectClass will automatically be included in the
                           filter sent to the server.
        :param list[str] attrs: List of attribute names to get. Defaults to all netgroup attributes.
        :return: An iterator over matching netgroup objects, yielding instances of :class:`.LDAPObject`.
        :rtype: SearchResultHandle
        :raises TagError: if the base object has not been tagged.
        """
        attrs = _netgroup_attrs_arg(attrs)
        return self.parent.tag(TAG).search(_netgroup_filter(filter), attrs)

    def get_obj_users(self, ng_obj, recursive=True):
        """Get a list of netgroup users from an already queried object, possibly querying for memberNisNetgroups if
        ``recursive=True`` (the default).

        :param LDAPObject ng_obj: A netgroup LDAP object
        :param bool recursive: Set to False to only consider members of this group directly
        :return: A list of usernames
        :rtype: list[str]
        """
        users = _extract_triple_field(ng_obj, 2)
        if recursive and ('memberNisNetgroup' in ng_obj):
            for member in ng_obj['memberNisNetgroup']:
                users += self.get_users(member, True)
        return users

    def get_users(self, cn, recursive=True):
        """Get a list of all user entries for a netgroup.

        This depends on the base object having been tagged and configured properly. See
        :mod:`laurelin.extensions.netgroups`.

        :param str cn: The name of the group or an RDN
        :param bool recursive: Recursively get users by following memberNisNetgroups
        :return: A list of usernames
        :rtype: list[str]
        :raises TagError: if the base object has not been tagged.
        """
        ng = self.get(cn)
        return self.get_obj_users(ng, recursive)

    def get_obj_hosts(self, ng_obj, recursive=True):
        """Get a list of netgroup hosts from an already queried object, possibly querying for memberNisNetgroups if
        ``recursive=True`` (the default).

        :param LDAPObject ng_obj: A netgroup LDAP object
        :param bool recursive: Set to False to only consider members of this group directly
        :return: A list of hostnames
        :rtype: list[str]
        """
        hosts = _extract_triple_field(ng_obj, 1)
        if recursive and ('memberNisNetgroup' in ng_obj):
            for member in ng_obj['memberNisNetgroup']:
                hosts += self.get_hosts(member, True)
        return hosts

    def get_hosts(self, cn, recursive=True):
        """Query a list of all host entries for a netgroup.

        This depends on the base object having been tagged and configured properly. See
        :mod:`laurelin.extensions.netgroups`.

        :param str cn: The name of the group or an RDN
        :param bool recursive: Recursively get hosts by following memberNisNetgroups
        :return: A list of hostnames
        :rtype: list[str]
        :raises TagError: if the base object has not been tagged.
        """
        ng = self.get(cn)
        return self.get_obj_hosts(ng, recursive)

    def add_users(self, dn, members, domain=''):
        """Add new users to a netgroup.

        :param str dn: The absolute DN of the netgroup object
        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or sinlge member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        """
        self.parent.add_attrs(dn, _member_user_list_to_attrs(members, domain))

    def add_hosts(self, dn, members, domain=''):
        """Add new hosts to a netgroup.

        :param str dn: The absolute DN of the netgroup object
        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        """
        self.parent.add_attrs(dn, _member_host_list_to_attrs(members, domain))

    def replace_users(self, dn, members, domain=''):
        """Set new users on a netgroup.

        :param str dn: The absolute DN of the netgroup object
        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or sinlge member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        """
        self.parent.replace_attrs(dn, _member_user_list_to_attrs(members, domain))

    def replace_hosts(self, dn, members, domain=''):
        """Set new hosts on a netgroup.

        :param str dn: The absolute DN of the netgroup object
        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        """
        self.parent.replace_attrs(dn, _member_host_list_to_attrs(members, domain))

    def delete_users(self, dn, members, domain=''):
        """Delete users from a netgroup.

        :param str dn: The absolute DN of the netgroup object
        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or sinlge member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        """
        self.parent.delete_attrs(dn, _member_user_list_to_attrs(members, domain))

    def delete_hosts(self, dn, members, domain=''):
        """Delete hosts from a netgroup.

        :param str dn: The absolute DN of the netgroup object
        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        """
        self.parent.delete_attrs(dn, _member_host_list_to_attrs(members, domain))


class LaurelinLDAPObjectExtension(BaseLaurelinLDAPObjectExtension):
    def _require_netgroup(self):
        """Requires that this :class:`.LDAPObject` has the required netgroup object class.

        :raises RuntimeError: if the object is missing the netgroup object class
        """
        if not self.parent.has_object_class(OBJECT_CLASS):
            raise RuntimeError('objectClass {0} is required'.format(OBJECT_CLASS))

    def get_users(self, recursive=True):
        """Get all users in this netgroup object.

        :param bool recursive: Set to False to ignore any memberNisNetgroups defined for this object.
        :return: A list of usernames
        :rtype: list[str]
        :raises RuntimeError: if this object is missing the netgroup object class
        """
        self._require_netgroup()
        return self.parent.ldap_conn.netgroups.get_obj_users(self, recursive)

    def get_hosts(self, recursive=True):
        """Get all hosts in this netgroup object.

        :param bool recursive: Set to False to ignore any memberNisNetgroups defined for this object.
        :return: A list of hostnames
        :rtype: list[str]
        :raises RuntimeError: if this object is missing the netgroup object class
        """
        self._require_netgroup()
        return self.parent.ldap_conn.netgroups.get_obj_hosts(self, recursive)

    def add_users(self, members, domain=''):
        """Add new user netgroup entries to this netgroup object.

        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        :raises RuntimeError: if this object is missing the netgroup object class
        """
        self._require_netgroup()
        self.parent.add_attrs(_member_user_list_to_attrs(members, domain))

    def add_hosts(self, members, domain=''):
        """Add new host netgroup entries to this netgroup object.

        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        :raises RuntimeError: if this object is missing the netgroup object class
        """
        self._require_netgroup()
        self.parent.add_attrs(_member_host_list_to_attrs(members, domain))

    def replace_users(self, members, domain=''):
        """Set new user netgroup entries on this netgroup object.

        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        :raises RuntimeError: if this object is missing the netgroup object class
        """
        self._require_netgroup()
        self.parent.replace_attrs(_member_user_list_to_attrs(members, domain))

    def replace_hosts(self, members, domain=''):
        """Set new host netgroup entries on this netgroup object.

        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        :raises RuntimeError: if this object is missing the netgroup object class
        """
        self._require_netgroup()
        self.parent.replace_attrs(_member_host_list_to_attrs(members, domain))

    def delete_users(self, members, domain=''):
        """Delete user netgroup entries from this netgroup object.

        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        :raises RuntimeError: if this object is missing the netgroup object class
        """
        self._require_netgroup()
        self.parent.delete_attrs(_member_user_list_to_attrs(members, domain))

    def delete_hosts(self, members, domain=''):
        """Delete host netgroup entries from this netgroup object.

        :param members: A Member List (see :mod:`laurelin.extensions.netgroups` doc) or single member list entry
        :type members: list or str or tuple
        :param str domain: The default domain to use in nisNetgroupTriples where not already specified
        :rtype: None
        :raises RuntimeError: if this object is missing the netgroup object class
        """
        self._require_netgroup()
        self.parent.delete_attrs(_member_host_list_to_attrs(members, domain))


## private functions


TRIPLE_RE = re.compile(_TRIPLE_RE)


def _netgroup_filter(filter):
    return '(&(objectClass={0}){1})'.format(OBJECT_CLASS, filter)


def _is_triple(val):
    return TRIPLE_RE.match(val) is not None


def _nis_netgroup_triple(host, user, domain):
    if not host:
        host = ''
    if not user:
        user = ''
    if not domain:
        domain = ''
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
