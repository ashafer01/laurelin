Changelog
=========

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
