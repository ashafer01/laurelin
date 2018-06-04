Simple Search Filters
=====================

Laurelin provides an alternate syntax for search filters that is much simpler than the standard, RFC 4515-compliant,
filter syntax. In short, it is a hybrid between SQL logic expressions and standard LDAP filter comparisons.

In the simplest case of a single comparison, the two syntaxes are identical:

=================== ===================
Standard            Simple
=================== ===================
``(gidNumber=100)`` ``(gidNumber=100)``
=================== ===================

But when it comes to expressing logic, the Laurelin simplified filter differs quite a bit:

======================================== ===========================================
Standard                                 Simple
======================================== ===========================================
``(&(gidNumber<=1000)(!(memberUid=*)))`` ``(gidNumber<=1000) AND NOT (memberUid=*)``
======================================== ===========================================

Feel free to include parentheses in your simple filters if it helps clarify the logic:

=========================================== =============================================
Simple (without extra parens)               Simple (equivalent with extra parens)
=========================================== =============================================
``(gidNumber<=1000) AND NOT (memberUid=*)`` ``(gidNumber<=1000) AND (NOT (memberUid=*))``
=========================================== =============================================

Some more equivalent standard and simple filters:

============================================== ========================================================
Standard                                       Simple
============================================== ========================================================
``(&(abc=foo)(|(def=bar)(ghi=jkl)))``          ``(abc=foo) AND ((def=bar) OR (ghi=jkl))``
``(|(abc=foo)(&(def=bar)(ghi=jkl)))``          ``(abc=foo) OR (def=bar) AND (ghi=jkl)``
``(&(abc=foo)(|(def=bar)(ghi=jkl))(xyz=abc))`` ``(abc=foo) AND ((def=bar) OR (ghi=jkl)) AND (xyz=abc)``
============================================== ========================================================

By default, Laurelin will interpret your filters with the **unified** filter syntax, meaning you can embed a full
RFC 4515-compliant filter anywhere you see a simple comparison in the above examples. This includes as the only element
in the filter, making this fully backwards compatible with RFC 4515 standard filters.

If you wish to restrict the syntax in either direction, you can do one of the following:

Currently available syntaxes are ``FilterSyntax.STANDARD`` to limit to RFC 4515, ``FilterSyntax.SIMPLE`` to limit to
only simple comparisons within SQL-style logic, and the default ``FilterSyntax.UNIFIED``.

1. Pass ``filter_syntax=`` to :meth:`.LDAP.search`::

    from laurelin.ldap import LDAP, FilterSyntax

    with LDAP() as ldap:
        search = ldap.search('o=foo', filter='(abc=foo) AND (def=bar)', filter_syntax=FilterSyntax.SIMPLE)

2. Pass ``filter_syntax=`` to the :class:`.LDAP` constructor::

    from laurelin.ldap import LDAP, FilterSyntax

    with LDAP(filter_syntax=FilterSyntax.SIMPLE) as ldap:
        search1 = ldap.search('o=foo', filter='(abc=foo) AND (def=bar)')
        search2 = ldap.search('o=bar', filter='(xyz=foo) OR (abc=bar)')

3. Set the global default ``LDAP.DEFAULT_FILTER_SYNTAX`` before instantiating any :class:`.LDAP` instances::

    from laurelin.ldap import LDAP, FilterSyntax

    LDAP.DEFAULT_FILTER_SYNTAX = FilterSyntax.STANDARD

    with LDAP() as ldap:
        search = ldap.search('o=foo', filter='(&(abc=foo)(def=bar))')

    with LDAP('ldap://localhost:10389') as ldap:
        search = ldap.search('o=bar', filter='(|(xyz=foo)(abc=bar))')

4. Do either of the two above using :doc:`config_files`.

.. note:: How is this possible?

   Doesn't the filter get sent to the server and parsed there like SQL? No! In LDAP, it is up to the client to parse
   the filter string into a set of objects that are encoded and sent to the server. If you've got any other ideas
   for alternate filter syntaxes, please submit a PR!
