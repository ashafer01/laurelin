Built-In Extensions
===================

.. contents::
   :local:

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
