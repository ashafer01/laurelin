Changelog
=========

2.0.0
-----

Released 2018.11.17

* Extensions API has been changed, both for users and creators of extensions:

    * Rather than attaching new attributes directly to the LDAP or LDAPObject class, a
      property (or dynamic attribute) is made available on those classes for each
      extension, which provides access to an object exposing those same attributes.
    * Many extension attributes have been renamed to avoid semantic duplication introduced
      by this change. For example ``ldap.get_netgroup_users()`` should be replaced with
      ``ldap.netgroups.get_users()``.
    * The base schema is no longer defined in ``laurelin.ldap.schema``. It now is housed in
      a built-in extension. If previously using ``import laurelin.ldap.schema`` or similar
      to enable client-side schema checking, this should be replaced with something like the
      following::

        from laurelin.ldap import extensions
        extensions.base_schema.require()

    * The ``descattrs`` extension has been changed slightly to work better with these new
      changes. Description attributes can now be accessed and modified like so (no additional
      imports necessary)::

        o = ldap.base.obj('cn=metadata')
        print(o.descattrs['some_attr'])
        # ['value1', 'value2']

        o.descattrs.add({'some_attr': ['value3']})
        print(o.descattrs['some_attr'])
        # ['value1', 'value2', 'value3']

        # these also work now:

        'some_attr' in o.descattrs

        for attr in o.descattrs:

    * Docs have been updated with information about creating extensions.
    * Internal changes around loading of schema elements and controls

* Properly documented the public API definition


1.5.3
-----

Release 2018.08.30

* Add python 3.7 support

1.5.2
-----

Released 2018.06.15

1.5.1 was built off of the wrong branch and will be removed.

* Minor fix: Added FilterSyntax to all
* Doc update: added dependent info section to readme

1.5.0
-----

Released 2018.06.09

* Added new simple filter syntax
* Switched default filter syntax to UNIFIED which should be backwards compatible with standard RFC 4515 filters

Special thanks to @jpypi for authoring the new grammar

1.4.1
-----

Released 2018.05.31

* Fix: Checked for failed import of AF_UNIX to improve Windows support
* Fix: Required latest pure-sasl

1.4.0
-----

Released 2018.05.29

* Validation updates:

    * Added :meth:`.LDAP.disable_validation` which creates a context with any or all validators skipped
    * Added an ``ldap_conn`` attribute to validator instances to allow validators to query the server
    * Allowed passing a class as well as an instance with the ``validators`` constructor keyword

* Greatly improved handling of unsolcitied messages (message ID 0)
* Fix: enforce maximum length for attribute types
* Fix: SASL auth issues with pure-sasl 0.5.1+

1.3.1
-----

Released 2018.04.01

* Fixed logic bug in :class:`.SchemaValidator` when an object has two or more object classes that require one or more
  of the same attributes
* Fixed: allowed string ``some.module.Class`` specification for validators in config files

1.3.0
-----

Released 2018.03.22

* Added config file support, see :mod:`.laurelin.ldap.config`
* Fixed: ensured extensions can be safely activated multiple times
* Fixed: :class:`.Mod` constants ``repr`` updated for consistency

1.2.0
-----

Released 2018.03.16

* Add DELETE_ALL to use as an attribute value list with modify, replace_attrs, and delete_attrs
* Added new constructor keywords to alter the behavior of empty value lists for modify, replace_attrs, and delete_attrs:

  * ``ignore_empty_list`` to silently ignore empty value lists and not send them to the server. This will be enabled by
    default in a future release.
  * ``error_empty_list`` to raise an exception when an empty value list is passed.
  * ``warn_empty_list`` to emit a warning when an empty value list is passed.

1.1.0
-----

Released 2018.03.12

Initial stable API.
