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
* Tested against CPython 2.7, 3.4 - 3.7, PyPy, and PyPy3.
* Simplified filter syntax (optional, standard filter syntax is fully supported and used by default)
* Pythonic attributes input and presentation. It's just a dictionary.
* Exceedingly easy relative searching. All objects have a suite of search methods which will automatically pass the
  object's DN as the search base. In many cases, you wont have to pass *any* arguments to search methods.
* Similarly, all objects have a suite of modify methods which allow you to change attributes on already-queried objects
  without having to pass their DN again.
* You never have to type the full absolute DN.
* Intelligent modification will never send existing attribute values to the server, nor will it request deletion of
  attribute values that do not exist. This prevents many unnecessary server errors. Laurelin will go as far as to query
  the object for you before modifying it to ensure you don't see pointless errors (if you want it to).
* Full support for configuring laurelin and connecting to a server from a config file
* Custom validation. You can define validators which check new objects and modify operations for correctness before
  sending them to the server. Since you control this code, this can be anything from a simple regex check against a
  particular attribute value, to a complex approval queue mechanism.
* Highly extensible. New methods can easily and safely be bound to base classes.
* Seamless integration of controls. Once defined, these are just new keyword arguments on particular methods, and
  additional attributes on the response object.
* Includes Python implementations of standard schema elements.

Dependent Info
--------------

Laurelin follows `SemVer <https://semver.org/>`_. When you add ``laurelin-ldap`` to your requirements, I strongly
suggest using the `compatible release operator <https://www.python.org/dev/peps/pep-0440/#compatible-release>`_ with
the ``major.minor`` that you use initially. For example::

    % pip install laurelin-ldap
    ...
    Successfully installed laurelin-ldap-1.5.0 ...
                                         ^^^

Since ``1.5.0`` was installed, add the following to your ``requirements.txt`` and/or ``install_requires`` list::

    laurelin-ldap~=1.5

But of course use whatever version you actually installed. You're also welcome to ``pip freeze``, but patch and
minor releases will always be compatible. Patch releases tend to contain important fixes, too. If you're sure you don't
want new features coming in and only fixes, you can still use the compatible release operator like so (again subbing in
your actual installed version)::

    laurelin-ldap~=1.5.0


Feel free to open a GitHub issue with any questions or concerns.

Public API Definition
---------------------

* **Everything in laurelin.ldap.__all__** - import directly ``from laurelin.ldap`` whenever possible
* ``laurelin.ldap.exceptions``
* ``laurelin.ldap.rfc*``
* ``laurelin.ldap.protoutils``
* ``laurelin.ldap.config``
* ``laurelin.extensions``

Note that stability of any 3rd party extensions with names hard coded into the laurelin core code cannot be guaranteed.
The stability guarantee applies only to built-in extensions shipped with laurelin-ldap in the ``laurelin.extensions``
package (There are no 3rd party extensions defined at this time).

If the user should venture into other modules outside of the declared public API above, I strongly suggest pinning your
version. I also strongly advise against EVER calling a private function or method (with underscore prefix).
