User Docs
=========

.. contents::
   :local:

Major missing/incomplete features
---------------------------------

Laurelin is still under development. What is done should be usable, but the following features have not yet been
implemented or are incomplete:

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

   * In progress

 * Testing

   * In progress

Please feel free to open a github ticket if you spot anything else missing, or have any thoughts regarding naming,
default settings, etc.

Walkthrough
-----------

Navigating
^^^^^^^^^^

Just about everything you need for routine user tasks is available in the :mod:`laurelin.ldap` package. You should not
need to get into the sub-modules below this unless you are defining controls, extensions, schema, or validators, or if
you are viewing the source.

:doc:`/built_in_extensions` are stored in the :mod:`laurelin.extensions` package.

Getting Started
^^^^^^^^^^^^^^^

The first thing you should typically do after importing is configure logging and/or warnings. There is a lot of useful
information available at all log levels::

    from laurelin.ldap import LDAP

    LDAP.enable_logging()
    # Enables all log output on stderr
    # It also accepts an optional log level argument, e.g. LDAP.enable_logging(logging.ERROR)
    # The function also returns the handler it creates for optional further manual handling

    import logging

    logger = logging.getLogger('laurelin.ldap')
    # Manually configure the logger and handlers here using the standard logging module
    # Submodules use the logger matching their name, below laurelin.ldap

    LDAP.log_warnings()
    # emit all LDAP warnings as WARN-level log messages on the laurelin.ldap logger
    # all other warnings will take the default action

    LDAP.disable_warnings()
    # do not emit any LDAP warnings
    # all other warnings will take the default action

    LDAP.default_warnings()
    # take the default action for all warnings

You can then initialize a connection to an LDAP server. Pass a URI string to the :class:`.LDAP` constructor::

   with LDAP('ldap://dir.example.org:389') as ldap:
        # do stuff...

   # Its also possible, but not reccommended, to not use the context manager:
   ldap = LDAP('ldap://dir.example.org:389')

This will open a connection and query the server to find the "base DN" or DN suffix. An empty :class:`.LDAPObject` will
be created with the base DN and stored as the ``base`` attribute on the :class:`.LDAP` instance. More on this later. For
now we will briefly cover the basic LDAP interface which may seem somewhat familiar if you have used the standard
python-ldap client before.

LDAP Methods Intro
^^^^^^^^^^^^^^^^^^

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

LDAPObject Methods Intro
^^^^^^^^^^^^^^^^^^^^^^^^

Great, right? But specifying absolute DNs all the time is no fun. Enter :class:`.LDAPObject`, and keep in mind the
``base`` attribute mentioned earlier.

:class:`.LDAPObject` inherits from :class:`.AttrsDict` to present attributes. This interface is documented
:ref:`here <attributes-dictionaries>`.

:class:`.LDAPObject` defines methods corresponding to all of the :class:`.LDAP` methods, but pass the object's ``dn``
automatically, or only require the RDN prefix, with the object's ``dn`` automatically appended to obtain the absolute
DN.

:meth:`.LDAPObject.search` accepts all the same arguments as :meth:`.LDAP.search` except ``base_dn`` (and ``scope`` -
more on this in future section). The object's own DN is always used for ``base_dn``.

:meth:`.LDAPObject.find` is more or less a better :meth:`.LDAPObject.get_child`. It looks at the object's
``relative_search_scope`` property to determine the most efficient way to find a single object below this one. It will
either do a `BASE` search if ``relative_seach_scope=Scope.ONE`` or a `SUBTREE` search if
``relative_search_Scope=Scope.SUB``. It is an error to use this method if ``relative_search_scope=Scope.BASE``.

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

Global Defaults, LDAP instance attributes, and LDAP constructor arguments
-------------------------------------------------------------------------

All of the :class:`.LDAP` constructor arguments are set to None by default. In the constructor, any explicitly
``is None`` arguments are set to their associated global default. These are attributes of the :class:`.LDAP` class, have
the same name as the argument, upper-cased, and with a ``DEFAULT_`` prefix (but the prefix wont be repeated).

For example, the ``server`` argument has global default :attr:`.LDAP.DEFAULT_SERVER`, and ``default_criticality`` is
:attr:`.LDAP.DEFAULT_CRITICALITY`.

*Most* arguments also have an associated instance property. A complete table is below:

================================================ ================================= ==================================
Global Default                                   :class:`.LDAP` instance attribute :class:`.LDAP` constructor keyword
================================================ ================================= ==================================
:attr:`.LDAP.DEFAULT_SERVER`                     ``host_uri``                      ``server``
:attr:`.LDAP.DEFAULT_BASE_DN`                    ``base_dn``                       ``base_dn``
:attr:`.LDAP.DEFAULT_FILTER`                     none                              none
:attr:`.LDAP.DEFAULT_DEREF_ALIASES`              ``default_deref_aliases``         ``deref_aliases``
:attr:`.LDAP.DEFAULT_SEARCH_TIMEOUT`             ``default_search_timeout``        ``search_timeout``
:attr:`.LDAP.DEFAULT_CONNECT_TIMEOUT`            ``sock_params[0]``                ``connect_timeout``
:attr:`.LDAP.DEFAULT_STRICT_MODIFY`              ``strict_modify``                 ``strict_modify``
:attr:`.LDAP.DEFAULT_REUSE_CONNECTION`           none                              ``reuse_connection``
:attr:`.LDAP.DEFAULT_SSL_VERIFY`                 ``ssl_verify``                    ``ssl_verify``
:attr:`.LDAP.DEFAULT_SSL_CA_FILE`                ``ssl_ca_file``                   ``ssl_ca_file``
:attr:`.LDAP.DEFAULT_SSL_CA_PATH`                ``ssl_ca_path``                   ``ssl_ca_path``
:attr:`.LDAP.DEFAULT_SSL_CA_DATA`                ``ssl_ca_data``                   ``ssl_ca_data``
:attr:`.LDAP.DEFAULT_FETCH_RESULT_REFS`          ``default_fetch_result_refs``     ``fetch_result_refs``
:attr:`.LDAP.DEFAULT_FOLLOW_REFERRALS`           ``default_follow_referrals``      ``follow_referrals``
:attr:`.LDAP.DEFAULT_SASL_MECH`                  ``default_sasl_mech``             ``default_sasl_mech``
:attr:`.LDAP.DEFAULT_SASL_FATAL_DOWNGRADE_CHECK` ``sasl_fatal_downgrade_check``    ``sasl_fatal_downgrade_check``
:attr:`.LDAP.DEFAULT_CRITICALITY`                ``default_criticality``           ``default_criticality``
:attr:`.LDAP.DEFAULT_VALIDATORS`                 ``validators``                    ``validators``
================================================ ================================= ==================================

The :class:`.LDAP` instance attributes beginning with ``default_`` are used as the defaults for corresponding arguments
on other methods. ``default_sasl_mech`` is used with :meth:`.LDAP.sasl_bind`, ``default_criticality`` is the default
criticality of all controls, the other ``default_`` attributes are used with :meth:`.LDAP.search`.

The ``ssl_`` prefixed instances attributes are used as the defaults for :meth:`.LDAP.start_tls`, as well as the socket
configuration when connecting to an ``ldaps://`` socket.

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

:meth:`.LDAP.sasl_bind` defaults to the ``EXTERNAL`` mechanism when an ``ldapi:`` URI is given, which uses the current
user for authorization via the unix socket (Known as "autobind" with 389 Directory Server)

