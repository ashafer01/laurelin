Changelog
=========

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
