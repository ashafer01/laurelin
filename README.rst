laurelin-ldap
=============

.. image:: https://travis-ci.org/ashafer01/laurelin.svg?branch=master
    :target: https://travis-ci.org/ashafer01/laurelin

View documentation on `ReadTheDocs <http://laurelin-ldap.readthedocs.io/en/latest/index.html>`_. You might also like
to read the `introduction <https://medium.com/@ashafer01/laurelin-a-new-ldap-client-for-python-675ebac78d96>`_.

``pip install laurelin-ldap`` or clone the repo to get started.

Please star the repo on `GitHub <https://github.com/ashafer01/laurelin>`_ if you like the project!

Named for one of the Two Trees of Valinor in Tolkien lore.

    Laurelin, which means 'Golden-song' in the Quenya tongue, bore shining golden leaves, the Light from which mingled
    with the Silver Flowers of the Elder Tree to illuminate the land of the Valar.

Features Overview
-----------------

* Fully compliant with RFC 4510 and its children, as well as several other related standards.
* Tested against CPython 2.7, 3.3, 3.4, 3.5, 3.6, PyPy, and PyPy3.
* Pythonic attributes input and presentation. It's just a dictionary.
* Exceedingly easy relative searching. All objects have a suite of search methods which will automatically pass the
  object's DN as the search base. In many cases, you wont have to pass *any* arguments to search methods.
* Similarly, all objects have a suite of modify methods which allow you to change attributes on already-queried objects
  without having to pass their DN again.
* You never have to type the full absolute DN.
* Intelligent modification will never send existing attribute values to the server, nor will it request deletion of
  attribute values that do not exist. This prevents many unnecessary server errors. Laurelin will go as far as to query
  the object for you before modifying it to ensure you don't see pointless errors (if you want it to).
* Custom validation. You can define validators which check new objects and modify operations for correctness before
  sending them to the server. Since you control this code, this can be anything from a simple regex check against a
  particular attribute value, to a complex approval queue mechanism.
* Highly extensible. New methods can easily and safely be bound to base classes.
* Seamless integration of controls. Once defined, these are just new keyword arguments on particular methods, and
  additional attributes on the response object.
* Includes Python implementations of standard schema elements.
