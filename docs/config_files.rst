Config Files
============

.. contents::
    :local:

Intro
-----

Laurelin config files may be YAML or JSON formatted out of the box. You can also supply your own custom decoding
function to handle arbitrary formats. The important part is that the file contents decode to a dictionary. Below is an
example YAML file::

    global:
      SSL_CA_PATH: /etc/ldap/cacerts
      IGNORE_EMPTY_LIST: true
    extensions:
      - laurelin.extensions.descattrs
      - laurelin.extensions.netgroups
    connection:
      server: ldap://dir01.example.org
      start_tls: true
      simple_bind:
        username: testuser
        passowrd: testpassword
      connect_timeout: 30
    objects:
      - rdn: ou=people
        tag: posix_user_base
      - rdn: ou=groups
        tag: posix_group_base
      - rdn: ou=netgroups
        tag: netgroup_base

You can load and apply such a file by using :func:`.config.load_file`. If a ``connection`` section was specified, a new
connection will be established and returned from the function.

Global Section
--------------

Each key in the global section must correspond to one of the ``DEFAULT_`` prefixed attributes on :class:`.LDAP`. As you
can see in the example, the ``DEFAULT_`` prefix is optional. Not demonstrated by the example is that keys are
case-insensitive (that is, they will be upper-cased for you).

Extensions Section
------------------

This is simply a list of extension module names which will get activated when the config file is loaded.

Connection Section
------------------

Keys here are *mostly* corresponding to :class:`.LDAP` constructor arguments, however there are a few special ones:

* ``start_tls`` A boolean option, if set to ``true`` will execute :meth:`.LDAP.start_tls` after opening the connection
* ``simple_bind`` A dictionary of parameters to pass to :meth:`.LDAP.simple_bind`
* ``sasl_bind`` A dictionary of parameters to pass to :meth:`.LDAP.sasl_bind`

Note that ``simple_bind`` and ``sasl_bind`` are both optional, and mutually exclude each other. In other words, it is an
error to specify both of these keys.

Note that ``start_tls`` will always occur before any bind (if requested).

Objects Section
---------------

.. note::

   You cannot specify ``objects`` without also specifying a ``connection``

This is a list of dicts where keys correspond to :meth:`.LDAP.obj` or :meth:`.LDAPObject.obj` arguments. You *must*
specify exactly one of ``dn`` or ``rdn``. If ``dn`` is specified, this will be taken as the full, absolute DN of the
object, and parameters will be passed to :meth:`.LDAP.obj`. If ``rdn`` is specified, this will be taken as the RDN
relative to the connection's base object, or the base of the tree, and parameters will be passed to
:meth:`.LDAPObject.obj`.

Also required for all objects is the ``tag`` key. This is how you will access created objects. For example, to access
the first object in the config file example above::

    ldap = config.load_file('/path/to/file.yaml')
    posix_users = ldap.tag('posix_user_base')

Its important to note that the server is not queried when creating these objects, so they will not have any local
attributes. If you require local attributes, you can all :meth:`.LDAPObject.refresh` on the object.

Global vs. Connection
---------------------

As mentioned elsewhere in the docs, there is a global config parameter associated with every connection parameter,
meaning in a config file you can define your connection parameters in either section. This *does not* have the exact
same end functionality, though. In general you should prefer ``connection`` for the following reasons:

* The connection will not be created when the config file is loaded if you configure everything in ``global``
* You cannot define ``objects`` without defining a ``connection``
* You cannot specify ``start_tls`` or bind parameters globally

However there are cases where it may be desirable to specify everything as a global default. Taking this approach allows
you to use the :class:`.LDAP` constructor with as few as zero arguments after loading the config. You can still bind as
usual by calling :meth:`.LDAP.simple_bind` or :meth:`.LDAP.sasl_bind` on the connection. You can also manually create
objects with ``obj()`` methods.

Load Order
----------

Sections are loaded and applied in a specific order:

1. ``global``
2. ``extensions``
3. ``connection``
4. ``objects``

You can specify sections in whatever order is convenient in your file. They will *always* be used in the above order.

Using Dicts Directly
--------------------

If you already have your configuration parameters in one or more dictionaries, you can apply them directly without
going through the file interface. You can pass a dictionary of the same format as in a config file to
:func:`.config.load_config_dict`. Like ``load_file()``, this will establish and return the new connection if one was
defined.

You can also use the other :mod:`.config` methods to apply dictionary configurations piecemeal. These process fragments
of the larger config dictionary. Check the reference docs for details if you need to do this.

