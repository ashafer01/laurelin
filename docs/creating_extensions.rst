Creating Extensions
===================

.. contents::
   :local:

The most important thing to note about "extensions" is that they are not necessarily LDAP extensions. In laurelin, they
are simply a module that does any combination of: defining new schema elements, defining new controls, or defining new
methods to be attached to :class:`LDAP` or :class:`LDAPObject`.

Extension System and Basic Requirements
---------------------------------------

Extensions live in an importable module or package. They must at minimum define a class called ``LaurelinExtension`` as
follows::

    from laurelin.ldap import BaseLaurelinExtension

    class LaurelinExtension(BaseLaurelinExtension):
        NAME = 'some_name'

At this point, for a user to use the package, they would first add your extension::

    from laurelin.ldap import LDAP

    LDAP.add_extension("your.extension.module")

If you had also defined a class called ``LaurelinLDAPExtension`` the user would be able to access an instance of that
class as follows (continuing above code block)::

    with LDAP() as ldap:
        ldap.some_name.some_method('foo')

Where ``some_name`` is what you defined at ``LaurelinExtension.NAME``. You can also define a class called
``LaurelinLDAPObjectExtension``, an instance of which gets attached to any :class:`.LDAPObject` that uses it in the same
way.

This is pretty cool, but since its fully dynamic, IDEs aren't aware of your extension's instance attributes. But for the
low cost of a 4-line patch to laurelin, a ``@property`` can automatically be generated which includes a docstring
specifying the return type; in other words, the absolute bare minimum of static declaration is included to let IDEs
do their thing. I have tested this approach with PyCharm, but should work with any IDE that is Sphinx docstring aware.

The needed patch is a simple addition to the :attr:`laurelin.ldap.extensible.Extensible.AVAILABLE_EXTENSIONS` dict::

    AVAILABLE_EXTENSIONS = {
        # ...
        'my_name': {  # This must match your LaurelinExtension.NAME and be globally unique
            'module': 'your.extension.module',
            'pip_package': 'your_cool_laurelin_extension',
            'docstring': 'This will get rendered on laurelin docs.'  # Feel free to include reST/Sphinx format such as
                                                                     # a link to your docs, but keep it to one line.
        },
        # ...
    }

Any such PR will be prompty accepted after testing that the extension is installable and importable.

Attaching New Methods
---------------------

As mentioned briefly in the previous section, you can define a class in your extension module called
``LaurelinLDAPExtension`` and/or ``LaurelinLDAPObjectExtension``. An instance of the appropriate class will be created,
one per :class:`.LDAP` connection and one per :class:`.LDAPObject`. Instances are created only when they are needed.

For example::

    """your.extension.module

    An example Laurelin extension
    """

    from laurelin.ldap import BaseLaurelinExtension, BaseLaurelinLDAPExtension, BaseLaurelinLDAPObjectExtension

    class LaurelinExtension(BaseLaurelinExtension):
        NAME = 'your_name'

    class LaurelinLDAPExtension(BaseLaurelinLDAPExtension):
        def search(self, param):
            # self.parent refers to the LDAP instance this instance is attached to
            return self.parent.base.search(filter='(description={0})'.format(param))

    class LaurelinLDAPObjectExtension(BaseLaurelinLDAPObjectExtension):
        def delete(self, param):
            # self.parent refers to the LDAPObject instance this instance is attached to
            self.parent.delete_attrs({'description': [param]})

User code might then look like the following (with the addition of a call to :func:`.add_extension` if not defined)::

    from laurelin.ldap import LDAP

    # LDAP.add_extension('your.extension.module')

    with LDAP() as ldap:
        for obj in ldap.your_name.search('foo'):
            obj.your_name.delete('bar')

Other points of note:

* :func:`.add_extension` is attached to :class:`.LDAP` as a static method for convenience. Calling this function will
  also potentially make new extensions available on :class:`.LDAPObject`. :func:`.add_extension` can also be imported
  directly from :mod:`laurelin.ldap`.
* Your ``LaurelinExtension`` class is instantiated once per interpreter when the extension is imported. This instance
  is stored at the class attribute ``LaurelinExtension.INSTANCE``. Feel free to utilize ``__init__()`` on this class
  for any setup tasks that need to be done and otherwise define anything you feel is appropriate here. You should
  probably *not* put anything exposed to users here.

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

The built-in :meth:`.LDAP.who_am_i` method is an excellent example of a simple LDAP extension::

   from laurelin.ldap import LDAP
   from laurelin.ldap.protoutils import get_string_component

   def who_am_i(self):
        handle = self.send_extended_request(LDAP.OID_WHOAMI, require_success=True, **ctrl_kwds)
        xr, res_ctrls = handle.recv_response()
        return get_string_component(xr, 'responseValue')

As an extension this might look like::

    from laurelin.ldap import BaseLaurelinLDAPExtension

    # ...

    class LaurelinLDAPExtension(BaseLaurelinLDAPExtension):
        def who_am_i(self):
            handle = self.parent.send_extended_request(...)
            # ...

 Note the use of ``self.parent`` to access :meth:`.LDAP.send_extended_request`.

Controls
--------

Extensions may wish to define controls for use on existing methods. You will need to define one or more
:class:`.Control` classes, see :ref:`defining-controls` for more information about this. The important part for the
purposes of this document is where to place those class definitions in your extension module.

You must define a method on your ``LaurelinExtension`` class called ``define_controls()`` and place class definitions
inside it. This method will be called once when the extension is imported. For example::

    from laurelin.ldap import BaseLaurelinExtension, Control

    class LaurelinExtension(BaseLaurelinExtension):
        NAME = 'your_name'

        def define_controls(self):
            class YourControl(Control):
                method = ('search',)
                keyword = 'some_kwd'
                REQUEST_OID = '1.2.3.4'

Schema
------

Extensions may be associated with a set of new schema elements, including object classes, attribute types, matching
rules, and syntax rules. Once defined, these will get used automatically by other parts of laurelin, including the
:class:`.SchemaValidator`, and for comparing items in attribute value lists within an :class:`.LDAPObject`.

Like controls, all extension schema elements must be defined in a ``LaurelinExtension`` method called
``define_schema()``. This gets called once when the extension is imported.

If your schema depends on the laurelin built-in base schema, set ``REQUIRES_BASE_SCHEMA = True`` on your
``LaurelinExtension`` class.

Below is a simple example of defining a new object class depending on the base schema::

    from laurelin.ldap import BaseLaurelinExtension

    class LaurelinExtension(BaseLaurelinExtension):
        NAME = 'your_name'
        REQUIRES_BASE_SCHEMA = True

        def define_schema(self):
            ObjectClass('''
            ( 1.2.3.4 NAME 'myCompanyUser' SUP inetOrgPerson STRUCTURAL
              MUST ( companyAttribute $ anotherAttribute )
              MAY description
            ''')

 The superclass of ``inetOrgPerson`` makes this example require the base schema.

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


Packaging
---------

``laurelin.extensions`` is a
`namespace package <https://setuptools.readthedocs.io/en/latest/setuptools.html#namespace-packages>`_ meaning you can
add your own modules and packages to it. You can use this on your private infrastructure, publish it in its own
package that way, or submit it as a pull request to be shipped as a built-in extension. You're also welcome to package
in your own namespace, as long as it is reachable for import.
