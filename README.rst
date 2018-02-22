laurelin-ldap
=============

.. image:: https://travis-ci.org/ashafer01/laurelin.svg?branch=master
    :target: https://travis-ci.org/ashafer01/laurelin

View documentation on `ReadTheDocs <http://laurelin-ldap.readthedocs.io/en/latest/index.html>`_.

Please star the repo on `GitHub <https://github.com/ashafer01/laurelin>`_ if you like the project!

Named for one of the Two Trees of Valinor in Tolkien lore.

    Laurelin, which means 'Golden-song' in the Quenya tongue, bore shining golden leaves, the Light from which mingled
    with the Silver Flowers of the Elder Tree to illuminate the land of the Valar.

Goals
-----

* Personally, learn more about LDAP, and make an LDAP library that I'd like to use
* Make LDAP easier to work with in Python

  * Easy to use object-oriented API
  * Abstractions for common patterns
  * Tools for extensions to provide further abstraction wherever possible

    * Object tagging to allow for automated absolute DN construction
    * Storage of RDN attributes for a subtree, allowing users to supply only a single string used as the RDN attribute
      value to fully generate an absolute DN

      * (The above two not only allow for significant abstraction, but can even improve performance by minimzing the
        need for subtree searches)

    * Easily bind additional methods to base classes
    * Attribute level validation and object level validation that will be applied to all write operations, and can also
      be performed on objects read from the server for auditing purposes

* Pure-Python implementation
* Stretch

  * OpenLDAP CLI implementation which could take advantage of validation extensions
  * OpenLDAP config parser and full compatability
