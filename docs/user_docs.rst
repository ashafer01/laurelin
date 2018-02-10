User Docs
=========

Major missing/incomplete features
---------------------------------

The following features have not yet been implemented or are incomplete:

 * Controls

   * Framework in place, no actual controls implemented yet

 * Referrals

   * In place for search but untested
   * Need to implement for other methods

 * LDIF input

   * Partial, not full spec

 * Binary data

   * Entirely missing

 * Docs

   * Minimal so far pending some confidence in API stability

 * Testing

   * Only ad-hoc functional testing

Please feel free to open a github ticket if you spot anything else missing, or have any thoughts regarding naming,
default settings, etc.

Walkthrough
-----------

Begin by initializing a connection to an LDAP server. Pass a URI string to the `LDAP` constructor::

    from laurelin.ldap import LDAP
    ldap = LDAP('ldap://dir.example.org:389')

This will open a connection and query the server to find the "base DN" or DN suffix. With some server configurations,
you may have to supply this yourself by passing the ``base_dn`` keyword argument, like so::

    ldap = LDAP('ldap://dir.example.org:389', base_dn='dc=example,dc=org')

An empty :class:`.LDAPObject` will be created with the base DN and stored as the ``base`` attribute on the
:class:`.LDAP` instance. More on this later. For now we will briefly cover the basic LDAP interface which may seem
somewhat familiar if you have used the standard python-ldap client before.

-----

:meth:`.LDAP.search` sends a search request and returns an iterable over instances of :class:`.LDAPObject`. Basic
arguments are described here (listed in order):

 * ``base_dn`` - the absolute DN to start the search from
 * ``scope`` - One of:

   * :attr:`.Scope.BASE` - only search ``base_dn`` itself
   * :attr:`.Scope.ONE` - search ``base_dn`` and its immediate children
   * :attr:`.Scope.SUB` - search ``base_dn`` and all of its descendents (default)

 * ``filter`` - standard LDAP filter string
 * ``attrs`` - a list of attributes to return for each object

Use :meth:`LDAP.get` if you just need to get a single object by its DN. Also accepts an optional list of attributes.

-----

:meth:`.LDAP.add` adds a new object, and returns the corresponding :class:`.LDAPObject`, just pass the full, absolute
DN and an :ref:`attributes dict <attributes-dictionaries>`

-----

:meth:`.LDAP.delete` deletes an entire object. Just pass the full, absolute DN of the object to delete.

-----

The following methods are preferred for modification, however raw :ref:`modify methods <modify-operations>` are
provided.

All accept the absolute DN of the object to modify, and an :ref:`attributes dictionary <attributes-dictionaries>`.

:meth:`.LDAP.add_attrs` adds new attributes

:meth:`.LDAP.delete_attrs` deletes attribute values. Pass an empty values list in the attributes dictionary to delete
all values for an attribute.

:meth:`.LDAP.replace_attrs` replaces all values for the given attributes with the values passed in the attributes
dictionary. Atrributes that are not mentioned are not touched. Passing an empty list removes all values.

-----

Great, right? But specifying absolute DNs all the time is no fun. Enter :class:`.LDAPObject`, and keep in mind the
``base`` attribute mentioned earlier.

:class:`.LDAPObject` inherits from :class:`.AttrsDict` to present attributes. This interface is documented
:ref:`here <attributes-dictionaries>`.

:class:`.LDAPObject` defines methods corresponding to all of the :class:`.LDAP` methods, but pass the object's ``dn``
automatically, or only require the RDN prefix, with the object's ``dn`` automatically appended to obtain the absolute
DN.

:meth:`.LDAPObject.search` accepts all the same arguments as :meth:`.LDAP.search` except ``base_dn`` (and ``scope`` -
more on this in future section). The object's own DN is always used for ``base_dn``.

:meth:`.LDAPObject.get_child` is analagous to :meth:`.LDAP.get` but it only needs the RDN, appending the object's own DN
as mentioned earlier. (Note that :meth:`.LDAPObject.get` inherits from the native :meth:`dict.get`)

:meth:`.LDAPObject.add_child` is analagous to :meth:`LDAP.add` again accepting an RDN in place of a full absolute DN.

Use :meth:`.LDAPObject.get_attr` like ``dict.get()`` except an empty list will always be returned as default if the
attribute is not defined.

:class:`.LDAPObject`'s modify methods update the server first, then update the local attributes dictionary to match if
successful. :meth:`.LDAPObject.add_attrs`, :meth:`.LDAPObject.delete_attrs`, and :meth:`LDAPObject.replace_attrs`
require only a new attributes dictionary as an argument, of the same format as for the matching :class:`.LDAP` methods.

:class:`.LDAPObject` Examples::

    people = ldap.base.get_child('ou=people')

    print(people['objectClass'])
    # ['top', 'organizationalUnit']

    people.add_attrs({'description':['Contains all users']})

    # list all users
    for user in people.search(filter='(objectClass=posixAccount)'):
        print(user['uid'][0])

This should cover the basics. More complexity to follow.

.. _attributes-dictionaries:

Attributes Dictionaries
-----------------------

This common interface is used both for input and output of LDAP attributes. In short: dict keys are attribute names, and
dict values are a ``list`` of attribute values. For example::

    {
        'objectClass': ['posixAccount', 'inetOrgPerson'],
        'uid': ['ashafer01'],
        'uidNumber': ['1000'],
        'gidNumber': ['100'],
        'cn': ['Alex Shafer'],
        'homeDirectory': ['/home/ashafer01'],
        'loginShell': ['/bin/zsh'],
        'mail': ['ashafer01@example.org'],
    }

Note that there is an :class:`.AttrsDict` class defined - there is **no requirement** to create instances of this class
to pass as arguments, though you are welcome to if you find the additional methods provided this class convenient, such
as :meth:`.AttrsDict.get_attr`. Further, it overrides ``dict`` special methods to enforce type requirements and enable
case-insensitive keys and matching rule-based comparisons in value lists.

.. _modify-operations:

Modify Operations
-----------------

Raw modify methods
^^^^^^^^^^^^^^^^^^

:meth:`.LDAP.modify` and :meth:`.LDAPObject.modify` work similarly to the modify functions in python-ldap, which in turn
very closely align with how modify operations are described at the protocol level. A list of :class:`.Mod` instances is
required with 3 arguments:

1. One of the :class:`.Mod` constants which describe the operation to perform on an attribute:

  * :attr:`.Mod.ADD` adds new attributes/values
  * :attr:`.Mod.REPLACE` replaces all values for an attribute, creating new attributes if necessary
  * :attr:`.Mod.DELETE` removes attributes/values.

2. The name of the attribute to modify. Each entry may only modify one attribute, but an unlimited number of entries may
   be specified in a single modify operation.
3. A list of attribute values to use with the modify operation:

  * The list may be empty for :attr:`.Mod.REPLACE` and :attr:`.Mod.DELETE`, both of which will cause all values for the
    given attribute to be removed from the object. The list may not be empty for :attr:`.Mod.ADD`.
  * A non-empty list for :attr:`.Mod.ADD` lists all new attribute values to add
  * A non-empty list for :attr:`.Mod.DELETE` lists specific attribute values to remove
  * A non-empty list for :attr:`.Mod.REPLACE` indicates ALL new values for the attribute - all others will be removed.

Example custom modify operation::

    from laurelin.ldap.modify import Mod

    ldap.modify('uid=ashafer01,ou=people,dc=example,dc=org', [
        Mod(Mod.ADD, 'mobile', ['+1 401 555 1234', '+1 403 555 4321']),
        Mod(Mod.ADD, 'homePhone', ['+1 404 555 6789']),
        Mod(Mod.REPLACE, 'homeDirectory', ['/export/home/ashafer01']),
    ])

Using an :class:`.LDAPObject` instead::

    ldap.base.obj('uid=ashafer01,ou=people').modify([
        Mod(Mod.DELETE, 'mobile', ['+1 401 555 1234']),
        Mod(Mod.DELETE, 'homePhone', []), # delete all homePhone values
    ])

Again, an arbitrary number of :class:`.Mod` entries may be specified for each ``modify`` call.

Strict modification and higher-level modify functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The higher-level modify functions (``add_attrs``, ``delete_attrs``, and ``replace_attrs``) all rely on the concept of
*strict modification* - that is, to only send the modify operation, and to never perform an additional search. By
default, strict modification is **disabled**, meaning that, if necessary, an extra search **will** be performed before
sending a modify request.

You can enable strict modification by passing ``strict_modify=True`` to the :class:`.LDAP` constructor.

With strict modification disabled, the :class:`.LDAP` modify functions will engage a more intelligent modification
strategy after performing the extra query: for :meth:`.LDAP.add_attrs`, no duplicate values are sent to the server to be
added. Likewise for :meth:`.LDAP.delete_attrs`, deletion will not be requested for values that are not known to exist.
This prevents many unnecessary failures, as ultimately the final semantic state of the object is unchanged with or
without such failures. (Note that with :meth:`.LDAP.replace_attrs` no such failures are possible)

With the :class:`.LDAPObject` modify functions, the situaiton is slightly more complex. Regardless of the
``strict_modify`` setting, the more intelligent modify strategy will always be used, using at least any already-queried
attribute data stored with the object (which could be complete data depending on how the object was originally
obtained). If ``strict_modify`` is disabled, however, another search *may* still be performed to fill in any missing
attributes that are mentioned in the passed attributes dict.

The raw ``modify`` functions on both :class:`.LDAP` and :class:`.LDAPObject` are unaffected by the ``strict_modify``
setting - they will always attempt the modify operation exactly as specified.

Basic usage examples
--------------------

1. Connect to local LDAP instance and iterate all objects
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 ::

    from laurelin.ldap import LDAP

    with LDAP('ldapi:///') as ldap:
        ldap.sasl_bind()
        for obj in ldap.base.search():
        print(obj.format_ldif())

:meth:`.LDAP.sasl_bind()` defaults to the ``EXTERNAL`` mechanism when an ``ldapi:`` URI is given, which uses the current
user for authorization via the unix socket (Known as "autobind" with 389 Directory Server)

