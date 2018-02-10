Controls
========

Using Controls
--------------

Once controls have been :ref:`defined <defining-controls>`, they are very easy to use. Each control has a ``keyword``
and optionally a ``response_attr``.

The ``keyword`` can be passed as a keyword argument to specific methods. The value type and format is up to the control
implementation. Whatever value the control expects can be wrapped in :class:`.critical` or :class:`.optional` to declare
the criticality of the control.

The ``response_attr`` will be set as an attribute on the object returned from the method call for most methods.

For search response controls, the control value will be set on the individual :class:`.LDAPObject` if it appeared on the
associated search result entry. If it appeared on the search results done message, the control value will be set on the
iterator object.

In the highly unusual case that a response control is set on a search result reference message, the control values will
be inaccessible if ``fetch_result_refs`` is set to True. A warning will be issued in this case.

If ``fetch_result_refs`` is set to False, the response control values will be set on the :class:`.SearchReferenceHandle`
that is yielded from the results iterator.

.. autoclass:: laurelin.ldap.critical
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: laurelin.ldap.optional
    :members:
    :undoc-members:
    :show-inheritance:


.. _defining-controls:

Defining Controls
-----------------

Controls must subclass Control and define at least:
 * :attr:`.Control.keyword`, the keyword argument to be used for the request control
 * :attr:`.Control.method`, a tuple of method names that this control supports. Current method names are `bind`,
   `search`, `compare`, `add`, `delete`, `modDN`, `modify`, and `ext` (extended request).
 * :attr:`.Control.REQUEST_OID` the OID of the reuqest control. If the control has criticality, the OID must be listed
   in the supportedControl attribute of the root DSE of the server at runtime.

If there is an associated response control, also define the following:
 * :attr:`.Control.response_attr`, the name of the attribute which will be set on objects returned from the method.
 * :attr:`.Control.RESPONSE_OID` the OID of the response control. This may be equal to :attr:`.Control.REQUEST_OID`
   depending on the spec. This must match the controlType of the response control to be properly set.

Most controls will not need to override methods if only strings are used for request and response values. However, if it
is desirable to use a more complex data structure as a control value, you can override the :meth:`.Control.prepare`
method to accept this structure as its first argument. You will need to process this into a single string for
transmission to the server, and pass it into, and return, the base :meth:`.Control.prepare`. The second argument is a
boolean describing criticality, and must also be passed into the base method.

To return a more complex value for the response, you can override the :meth:`.Control.handle` method. This will be
passed the response control value string, and the return will be assigned to the ``response_attr`` attribute on the
returned object.

.. autoclass:: laurelin.ldap.controls.Control
    :members:
    :undoc-members:
    :show-inheritance:
