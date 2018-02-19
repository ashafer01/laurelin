Creating Extensions
===================

.. contents::
   :local:

The most important thing to note about "extensions" is that they are not necessarily LDAP extensions. In laurelin, they
are simply a module that binds additional methods to base classes (:class:`.LDAP`, or :class:`.LDAPObject`).

Extension Activation
--------------------

The :meth:`.LDAP.activate_extension` method accepts a string containing the name of the module to import. After
importing, an ``activate_extension()`` function will be called on the module itself if defined. Any setup can be done in
this function, including calls to ``EXTEND()`` (see below).

Binding New Methods
-------------------

In order to ensure all extensions play nicely together, **do not** bind methods to these yourself. Each extensible class
has a classmethod called ``EXTEND`` which accepts a list of methods (or any callable object) to bind. If you need to
bind the method as a different name, override it's ``__name__`` attribute before calling ``EXTEND``.

No method may ever be overwritten, built-in or otherwise. If you want to modify the behavior of existing methods, you
should create a subclass in your extension module and instruct your users to import this instead.

Below is a simple extension module::

    from laurelin.ldap import LDAP, LDAPObject

    def get_group_members(self, dn):
        """get_group_members(dn)

        Get all members of a group at a particular dn.

        :param str dn: The group's distinguished name
        :return: A list of member usernames
        :rtype: list[str]
        """
        group = self.get(dn)
        return group.get_attr('memberUid')

    def obj_get_group_members(self):
        """obj_get_group_members()

        Get all members of this group object.

        :return: A list of member usernames
        :rtype: list[str]
        """
        return self.get_attr('memberUid')

    obj_get_group_members.__name__ = 'get_group_members'

    def activate_extension()
        LDAP.EXTEND([get_group_members])
        LDAPObject.EXTEND([obj_get_group_members])

The module can then be used like so::

    from laurelin.ldap import LDAP
    LDAP.activate_extension('extension.module.name')

    with LDAP() as ldap:
        print(ldap.get_group_members('cn=foo,ou=groups,o=example'))  # Example LDAP usage
        print(ldap.get('cn=foo,ou=groups,o=example').get_group_members())  # Example LDAPObject usage

LDAP Extensions
---------------

When defining an actual LDAP extension with an OID and requiring server support, you'll create the laurelin extension as
shown above, but you'll be calling the :meth:`LDAP.send_extended_request` method from your extension methods.

.. automethod:: laurelin.ldap.LDAP.send_extended_request
   :noindex:

As you can see, this accepts the OID of the LDAP extension and an optional request value. You can also pass control
keywords, and the ``require_success`` keyword, which will automatically check for success on the final extendedResponse
message (and raise an :exc:`.LDAPError` on failure).

If your LDAP extension expects intermediateResponse messages, you can iterate the return from
:meth:`LDAP.send_extended_request`. You can also call :meth:`.ExtendedResponseHandle.recv_response` to get only one
message at a time (preferred to iteration if you only expect the one extendedResponse message).

The built-in :meth:`LDAP.who_am_i` method is an excellent example of a simple LDAP extension::

   from laurelin.ldap import LDAP
   from laurelin.ldap.protoutils import get_string_component

   def who_am_i(self):
        handle = self.send_extended_request(LDAP.OID_WHOAMI, require_success=True, **ctrl_kwds)
        xr, res_ctrls = handle.recv_response()
        return get_string_component(xr, 'responseValue')

If this were a laurelin extension, you could go on to bind it to :class:`.LDAP` as follows::

   def activate_extension()
      LDAP.EXTEND([who_am_i])

Controls
--------

Extensions may wish to define controls for use on existing methods. See :ref:`defining-controls` for more information.

Schema
------

Extensions may be associated with a set of new schema elements, including object classes, attribute types, matching
rules, and syntax rules. Once defined, these will get used automatically by other parts of laurelin, including the
:class:`.SchemaValidator`, and for comparing items in attribute value lists within an :class:`.LDAPObject`.

Object Classes and Attribute Types
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Creating object classes and attribute types is very simple. Just take the standard LDAP specification and pass it to the
appropriate class constructor. Examples from the netgroups extension::

   from laurelin.ldap.objectclass import ObjectClass
   from laurelin.ldap.attributetype import AttributeType

    ObjectClass('''
    ( 1.3.6.1.1.1.2.8 NAME 'nisNetgroup' SUP top STRUCTURAL
      MUST cn
      MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
    ''')

    AttributeType('''
    ( 1.3.6.1.1.1.1.14 NAME 'nisNetgroupTriple'
      DESC 'Netgroup triple'
      EQUALITY caseExactMatch
      SYNTAX 1.3.6.1.1.1.0.0 )
    ''')

Matching Rules
^^^^^^^^^^^^^^

Defining matching rules takes a little more effort. Matching rules must subclass :class:`.EqualityMatchingRule`.
Required class attributes include:


* ``OID`` - the numeric OID of this rule. Note that this does not need to be IANA-registered to work in laurelin, but it
  still must be globally unique.
* ``NAME`` - the name of the rule. Must also be globally unique. This is usually how matching rules are referenced in
  attribute type specs (see ``caseExactMatch`` in above example).
* ``SYNTAX`` - the numeric OID of the syntax rule that assertion values must match.

Matching rule classes may also optionally define the following attribute:

* ``prep_methods`` - a sequence of callables that will be used to prepare both the attribute value and assertion value
  for comparison. These will typically be defined in :mod:`laurelin.ldap.rfc4518`. The initial attribute/assertion value
  will be passed into the first item in the sequence, and the return from each is passed into the next item.

If you prefer, you can also override the :meth:`.MatchingRule.prepare` method on your matching rule class.

You may also wish to override :meth:`.EqualityMatchingRule.do_match`. This is passed the two prepared values and must
return a boolean. Overriding :meth:`.MatchingRule.match` *is not recommended*.

Below is an example matching rule from :mod:`laurelin.ldap.schema`::

   from laurelin.ldap.rules import EqualityMatchingRule
   from laurelin.ldap import rfc4518

    class numericStringMatch(EqualityMatchingRule):
        OID = '2.5.13.8'
        NAME = 'numericStringMatch'
        SYNTAX = '1.3.6.1.4.1.1466.115.121.1.36'
        prep_methods = (
            rfc4518.Transcode,
            rfc4518.Map.characters,
            rfc4518.Normalize,
            rfc4518.Prohibit,
            rfc4518.Insignificant.numeric_string,
        )

Syntax Rules
^^^^^^^^^^^^

Syntax rules must subclass :class:`.SyntaxRule`, although in almost all cases you can use :class:`.RegexSyntaxRule`. If
you do not use a regular expression, you must override :meth:`.SyntaxRule.validate`, which receives a single string
argument, and must raise :exc:`.InvalidSyntaxError` when it is incorrect.

In all cases, you must define the following attributes on your syntax rule class:

* ``OID`` - the numeric OID of the rule. As with matching rules, there is no requirement that this is IANA-registered,
  but it must be globally unique.
* ``DESC`` - a brief description of the rule. This is mainly used in exception messages.

Regex syntax rules must also define:

* ``regex`` - the regular expression.

Below are examples from :mod:`laurelin.ldap.schema`::

   from laurelin.ldap.rules import SyntaxRule, RegexSyntaxRule
   from laurelin.ldap.exceptions import InvalidSyntaxError
   import six

    class DirectoryString(SyntaxRule):
        OID = '1.3.6.1.4.1.1466.115.121.1.15'
        DESC = 'Directory String'

        def validate(self, s):
            if not isinstance(s, six.string_types) or (len(s) == 0):
                raise InvalidSyntaxError('Not a valid {0}'.format(self.DESC))

    class Integer(RegexSyntaxRule):
        OID = '1.3.6.1.4.1.1466.115.121.1.27'
        DESC = 'INTEGER'
        regex = r'^-?[1-9][0-9]*$'


SchemaValidator
^^^^^^^^^^^^^^^

Laurelin ships with :class:`.SchemaValidator` which, when applied to a connection, automatically checks write operations
for schema validity *before* sending the request to the server. This includes any schema you define in your extensions.
Users can enable this like so::

      from laurelin.ldap import LDAP
      from laurelin.ldap.schema import SchemaValidator

      with LDAP('ldaps://dir.example.org', validators=[SchemaValidator()]) as ldap:
         # do stuff

You can also define your own validators, see below.

Validators
----------

Validators must subclass :class:`.Validator`. The public interface includes :meth:`.Validator.validate_object` and
:meth:`.Validator.validate_modify`. You will usually just want to override these, however they do include a default
implementation which checks all attributes using the abstract :meth:`.Validator._validate_attribute`. Check method docs
for more information about how to define these.

When defining validators in your extension, you can avoid needing to import the module again by using the return value
from :meth:`.LDAP.activate_extension`, like so::

   from laurelin.ldap import LDAP
   my_ext = LDAP.activate_extension('an.extension.module')

   with LDAP('ldaps://dir.example.org', validators=[my_ext.MyValidator()]) as ldap:
      # do stuff

