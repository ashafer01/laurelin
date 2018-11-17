Extensions
==========

The following class documents show names of available extensions on different instances.

Laurelin Extensions
-------------------

Every defined extension has a property in this class. An instance is accessible at :attr:`laurelin.ldap.extensions`.
For example, to require the base schema::

    from laurelin.ldap import extensions

    extensions.base_schema.require()

.. autoclass:: laurelin.ldap.extensible.laurelin_extensions.Extensions
   :members:
   :show-inheritance:

LDAP Extensions
---------------

These properties are available on :class:`.LDAP` instances.

.. autoclass:: laurelin.ldap.extensible.ldap_extensions.LDAPExtensions
   :members:
   :show-inheritance:

LDAPObject Extensions
---------------------

These properties are available on :class:`.LDAPObject` instances.

.. autoclass:: laurelin.ldap.extensible.ldapobject_extensions.LDAPObjectExtensions
   :members:
   :show-inheritance:
