Built-In Extensions
===================

.. contents::
   :local:

POSIX Users and Groups
----------------------

.. automodule:: laurelin.extensions.posix

   .. autoattribute:: laurelin.extensions.posix.MIN_AUTO_UID_NUMBER

   .. autoattribute:: laurelin.extensions.posix.MIN_AUTO_GID_NUMBER

   .. autoattribute:: laurelin.extensions.posix.DEFAULT_GIDNUMBER

   .. autoattribute:: laurelin.extensions.posix.USER_RDN_ATTR

   .. autoattribute:: laurelin.extensions.posix.GROUP_RDN_ATTR

   .. autoattribute:: laurelin.extensions.posix.HOMEDIR_FORMAT

   .. autoattribute:: laurelin.extensions.posix.DEFAULT_FILL_GAPS

   .. autoclass:: laurelin.extensions.posix.UserPlacement
      :members:
      :undoc-members:

   .. autoclass:: laurelin.extensions.posix.GroupPlacement
      :members:
      :undoc-members:

.. module:: laurelin.ldap
   :noindex:

.. class:: LDAP
   :noindex:

   The following new methods get bound to :class:`.laurelin.ldap.LDAP` upon extension activation:

   .. autofunction:: laurelin.extensions.posix.get_user

   .. autofunction:: laurelin.extensions.posix.get_group

   .. autofunction:: laurelin.extensions.posix.add_user

   .. autofunction:: laurelin.extensions.posix.update_user

   .. autofunction:: laurelin.extensions.posix.add_group

   .. autofunction:: laurelin.extensions.posix.update_group

   .. autofunction:: laurelin.extensions.posix.add_group_members

   .. autofunction:: laurelin.extensions.posix.delete_group_members

.. class:: LDAPObject
   :noindex:

   The following new methods get bound to :class:`.laurelin.ldap.LDAPObject` upon extension activation:

   .. autofunction:: laurelin.extensions.posix.obj_update_user

   .. autofunction:: laurelin.extensions.posix.obj_update_group

   .. autofunction:: laurelin.extensions.posix.obj_add_group_members

   .. autofunction:: laurelin.extensions.posix.obj_delete_group_members

NIS Netgroups
-------------

.. automodule:: laurelin.extensions.netgroups

   .. autoattribute:: laurelin.extensions.netgroups.TAG

   .. autoattribute:: laurelin.extensions.netgroups.NETGROUP_ATTRS

   .. autoattribute:: laurelin.extensions.netgroups.OBJECT_CLASS

.. module:: laurelin.ldap
   :noindex:

.. class:: LDAP
   :noindex:

   The following new methods get bound to :class:`laurelin.ldap.LDAP` upon extension activation:

   .. autofunction:: laurelin.extensions.netgroups.get_netgroup

   .. autofunction:: laurelin.extensions.netgroups.netgroup_search

   .. autofunction:: laurelin.extensions.netgroups.get_netgroup_users

   .. autofunction:: laurelin.extensions.netgroups.get_netgroup_hosts

   .. autofunction:: laurelin.extensions.netgroups.get_netgroup_obj_users

   .. autofunction:: laurelin.extensions.netgroups.get_netgroup_obj_hosts

   .. autofunction:: laurelin.extensions.netgroups.add_netgroup_users

   .. autofunction:: laurelin.extensions.netgroups.add_netgroup_hosts

   .. autofunction:: laurelin.extensions.netgroups.replace_netgroup_users

   .. autofunction:: laurelin.extensions.netgroups.replace_netgroup_hosts

   .. autofunction:: laurelin.extensions.netgroups.delete_netgroup_users

   .. autofunction:: laurelin.extensions.netgroups.delete_netgroup_hosts

.. class:: LDAPObject
   :noindex:

   The following new methods get bound to :class:`laurelin.ldap.LDAPObject` upon extension activation:

   .. autofunction:: laurelin.extensions.netgroups.obj_get_netgroup_users

   .. autofunction:: laurelin.extensions.netgroups.obj_get_netgroup_hosts

   .. autofunction:: laurelin.extensions.netgroups.obj_add_netgroup_users

   .. autofunction:: laurelin.extensions.netgroups.obj_add_netgroup_hosts

   .. autofunction:: laurelin.extensions.netgroups.obj_replace_netgroup_users

   .. autofunction:: laurelin.extensions.netgroups.obj_replace_netgroup_hosts

   .. autofunction:: laurelin.extensions.netgroups.obj_delete_netgroup_users

   .. autofunction:: laurelin.extensions.netgroups.obj_delete_netgroup_hosts

Description Attributes
----------------------

.. automodule:: laurelin.extensions.descattrs

.. module:: laurelin.ldap
   :noindex:

.. class:: LDAPObject
   :noindex:

   The following new methods get bound to :class:`laurelin.ldap.LDAPObject` upon extension activation:

   .. autofunction:: laurelin.extensions.descattrs.desc_attrs

   .. autofunction:: laurelin.extensions.descattrs.add_desc_attrs

   .. autofunction:: laurelin.extensions.descattrs.delete_desc_attrs

   .. autofunction:: laurelin.extensions.descattrs.replace_desc_attrs

Paged Results
-------------

.. automodule:: laurelin.extensions.pagedresults
