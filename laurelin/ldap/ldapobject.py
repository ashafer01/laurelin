from __future__ import absolute_import
from . import utils
from .attrsdict import AttrsDict
from .attrvaluelist import AttrValueList
from .constants import Scope, FilterSyntax
from .exceptions import (
    LDAPError,
    Abandon,
    LDAPTransactionError,
)
from .extensible.ldapobject_extensions import LDAPObjectExtensions
from .modify import (
    Mod,
    Modlist,
    AddModlist,
    DeleteModlist,
)
import re
from base64 import b64encode


class LDAPObject(AttrsDict, LDAPObjectExtensions):
    """Represents a single object with optional server affinity.

    Many methods will raise an exception if used without a server connection. To instantiate an :class:`LDAPObject`
    bound to a server connection, use :meth:`LDAP.obj`.

    Attributes and values are stored using the mapping interface inherited from AttrsDict, where dict keys are
    case-insensitive attribute names, and dict values are a list of attribute values.

    Value lists are automatically wrapped in :class:`.AttrValueList`. This allows the use of any schema-defined matching
    and syntax rules for the attribute type in list operations.

    :param str dn: The DN of the object
    :param attrs_dict: The object's attributes
    :type attrs_dict: dict(str, list[str or bytes]) or AttrsDict or None
    :param ldap_conn: The optional LDAP connection to use
    :type ldap_conn: LDAP or None
    :param Scope relative_search_scope: One of the :class:`Scope` constants, this is the default scope used when using
                                        this object's :meth:`LDAPObject.search` method. New objects created below this
                                        one will inherit this attribute by default. This attribute also defines the
                                        behavior of :meth:`.LDAPObject.find`.
    :param rdn_attr: The default attribute name used in RDN's for descendents of this object. If specified, this
                     allows you to only specify the value for methods that have an ``rdn`` argument. You can always
                     specify a full attr=value for ``rdn`` arguments as well to override this behavior. New objects
                     created below this one will inherit this attribute by default.
    :type rdn_attr: str or None
    """

    def __init__(self, dn, attrs_dict=None, ldap_conn=None, relative_search_scope=Scope.SUBTREE, rdn_attr=None):
        AttrsDict.__init__(self, attrs_dict)
        LDAPObjectExtensions.__init__(self)

        self.dn = dn
        self.ldap_conn = ldap_conn
        self.relative_search_scope = relative_search_scope
        self.rdn_attr = rdn_attr
        if ldap_conn:
            self._built_in_only = ldap_conn._built_in_only

    def __repr__(self):
        return "LDAPObject(dn='{0}', attrs={1})".format(self.dn, AttrsDict.__repr__(self))

    def __eq__(self, other):
        if not isinstance(other, LDAPObject):
            return False
        elif self.dn != other.dn:
            return False
        else:
            return AttrsDict.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __setitem__(self, attr, values):
        if not isinstance(values, list):
            raise TypeError('must be list')
        values = AttrValueList(attr, values)
        AttrsDict.__setitem__(self, attr, values)

    def _has_ldap(self):
        return (self.ldap_conn is not None)

    def _require_ldap(self):
        if not self._has_ldap():
            raise RuntimeError('No LDAP instance')

    ## relative methods

    def _rdn_attr(self, rdn):
        if '=' not in rdn:
            if self.rdn_attr is not None:
                return '{0}={1}'.format(self.rdn_attr, rdn)
            else:
                raise ValueError('No rdn_attr specified, must supply full RDN attr=val')
        else:
            return rdn

    def rdn(self, rdn):
        """Return an absolute DN from an RDN or RDN value

        :param str rdn: The RDN, or RDN value if `rdn_attr` is defined for this object
        :return: The absolute DN
        :rtype: str
        """
        rdn = self._rdn_attr(rdn)
        return '{0},{1}'.format(rdn, self.dn)

    def _set_obj_kwd_defaults(self, obj_kwds):
        """set inherited attributes on keywords dictionary, to make its way into new LDAPObjects"""
        obj_kwds.setdefault('relative_search_scope', self.relative_search_scope)
        obj_kwds.setdefault('rdn_attr', self.rdn_attr)

    def obj(self, rdn, attrs_dict=None, tag=None, **kwds):
        """Create a new object below this one.

        :param str rdn: The RDN, or RDN value if `rdn_attr` is defined for this object
        :param attrs_dict: The attributes for the object
        :type attrs_dict: dict(str, list[str or bytes]) or AttrsDict or None
        :param tag: Optional tag for the object
        :type tag: str or None
        :return: The new object
        :rtype: LDAPObject
        :raises LDAPError: if a ``tag`` is specified but this object is not bound to an LDAP connection

        Additional keywords are passed through into :meth:`.LDAP.obj`. or the :class:`.LDAPObject` constructor.
        """
        self._set_obj_kwd_defaults(kwds)
        if self._has_ldap():
            return self.ldap_conn.obj(self.rdn(rdn), attrs_dict=attrs_dict, tag=tag, **kwds)
        else:
            if tag is not None:
                raise LDAPError('tagging requires LDAP instance')
            return LDAPObject(self.rdn(rdn), attrs_dict=attrs_dict, **kwds)

    def get_child(self, rdn, attrs=None, **kwds):
        """Query the server for a child object.

        :param str rdn: The RDN, or RDN value if ``rdn_attr`` is defined for this object
        :param attrs: The list of attributes to query
        :type attrs: list[str] or None
        :return: The object populated with data from the server
        :rtype: LDAPObject
        :raises RuntimeError: if this object is not bound to an LDAP connection

        Additional keywords are passed through into :meth:`LDAP.search` and :class:`LDAPObject`
        """
        self._require_ldap()
        self._set_obj_kwd_defaults(kwds)
        return self.ldap_conn.get(self.rdn(rdn), attrs, **kwds)

    def add_child(self, rdn, attrs_dict, **kwds):
        """Create a new object below this one.

        :param str rdn: The RDN, or RDN value if `rdn_attr` is defined for this object
        :param attrs_dict: The attributes for the object
        :type attrs_dict: dict(str, list[str or bytes]) or AttrsDict or None
        :return: The new object
        :rtype: LDAPObject

        Additional keyword arguments are passed through into :meth:`LDAP.add`
        """
        self._require_ldap()
        self._set_obj_kwd_defaults(kwds)
        return self.ldap_conn.add(self.rdn(rdn), attrs_dict, **kwds)

    def delete_child(self, rdn, **ctrl_kwds):
        """Delete a child object below this one.

        :param str rdn: The RDN, or RDN value if `rdn_attr` is defined for this object
        :return: The :class:`.LDAPResponse` from the delete operation
        :rtype: LDAPResponse

        Additional keyword arguments are treated as controls.
        """
        self._require_ldap()
        return self.ldap_conn.delete(self.rdn(rdn), **ctrl_kwds)

    def search(self, filter=None, attrs=None, **kwds):
        """Perform a search below this object.

        :param str filter: Optional. The filter string to use to filter returned objects.
        :param list[str] attrs: Optional. The list of attribute names to retrieve.
        :return: An iterator over :class:`.LDAPObject` and possibly :class:`.SearchReferenceHandle`. See
                 :meth:`.LDAP.search` for more details.
        :rtype: SearchResultHandle

        Additional keywords are passed through into :meth:`.LDAP.search`.
        """
        self._require_ldap()
        self._set_obj_kwd_defaults(kwds)
        return self.ldap_conn.search(self.dn, self.relative_search_scope, filter, attrs, **kwds)

    def find(self, rdn, attrs=None, **kwds):
        """Obtain a single object below this one with the most efficient means possible.

        The strategy used is based on the ``relative_search_scope`` property of this object.

        * If it is :attr:`.Scope.BASE`, this method will always raise an :exc:`.LDAPError`.
        * If it is :attr:`.Scope.ONE`, then the absolute DN for the child object will be constructed, and a
          :attr:`.Scope.BASE` search will be performed to get the object.
        * If it is :attr:`.Scope.SUB`, then a subtree search will be performed below this object, using the RDN as a
          search filter.

        Additional keywords are passed through into :meth:`.LDAPObject.search`.

        :param str rdn: The RDN, or RDN value if ``rdn_attr`` is defined for this object
        :param list[str] attrs: Optional. The list of attribute names to obtain.
        :return: The LDAP object
        :rtype: LDAPObject
        :raises LDAPError: if this object's ``relative_search_scope`` is :attr:`.Scope.BASE`.
        :raises NoSearchResults: if no object could be found matching ``rdn``.
        :raises MultipleSearchResults: if more than one object was found.
        :raises RuntimeError: if this object is not bound to an LDAP connection
        :raises ValueError: if the ``relative_search_scope`` is set to an invalid value.
        """
        self._require_ldap()
        self._set_obj_kwd_defaults(kwds)
        if self.relative_search_scope == Scope.BASE:
            raise LDAPError('Object has no children')
        elif self.relative_search_scope == Scope.ONELEVEL:
            return self.get_child(rdn, attrs, **kwds)
        elif self.relative_search_scope == Scope.SUBTREE:
            filter = '({0})'.format(self._rdn_attr(rdn))
            res = list(self.search(filter=filter, filter_syntax=FilterSyntax.STANDARD, attrs=attrs, limit=2, **kwds))
            return utils.get_one_result(res)
        else:
            raise ValueError('Unknown relative_search_scope')

    def compare(self, attr, value):
        """Ask the server if this object has a matching attribute value. The comparison will take place following the
        schema-defined matching rules and syntax rules.

        :param str attr: The attribute name
        :param str value: The assertion value
        :return: A response object, :func:`bool` evaluating to the result of the comparison
        :rtype: CompareResponse
        :raises RuntimeError: if this object is not bound to an LDAP connection
        """
        self._require_ldap()
        return self.ldap_conn.compare(self.dn, attr, value)

    ## object-specific methods

    def format_ldif(self):
        """Format the object as an LDIF string.

        :return: The object encoded as an LDIF.
        :rtype: str
        """
        def b64ascii(s):
            return b64encode(s.encode()).decode('ascii')

        def encode_value(strvalue):
            if not re.match(r'^[\x01-\x09\x0b-\x0c\x0e-\x1f\x21-\x39\x3b\x3d-\x7f][\x01-\x09\x0b-\x0c\x0e-\x7f]*$',
                            strvalue):
                # Any value that contains characters other than those defined as
                # "SAFE-CHAR", or begins with a character other than those
                # defined as "SAFE-INIT-CHAR", above, MUST be base-64 encoded.
                return ': ' + b64ascii(strvalue)
            elif strvalue.endswith(' '):
                # Values or distinguished names that end with SPACE SHOULD be
                # base-64 encoded.
                return ': ' + b64ascii(strvalue)
            else:
                return ' ' + strvalue

        ldif = 'dn:{0}\n'.format(encode_value(self.dn))
        for attr, val in self.iterattrs():
            try:
                if hasattr(val, 'decode'):
                    val = val.decode('utf-8')
                line = '{0}:{1}'.format(attr, encode_value(val))
            except UnicodeDecodeError:
                val = b64encode(val).decode('ascii')
                line = '{0}:: {1}'.format(attr, val)
            line_len = len(line)
            n = 0
            step = 76
            if line_len > step:
                ldif += line[n:step]
                ldif += '\n '
                n += step
                fragments = []
                step = 75
                while n < line_len:
                    fragments.append(line[n:n+step])
                    n += step
                ldif += '\n '.join(fragments)
            else:
                ldif += line
            ldif += '\n'
        return ldif

    def has_object_class(self, object_class):
        """A convenience method which checks if this object has a particular objectClass. May query the server for the
        objectClass attribute if it is not yet known.

        :param object_class: The objectClass to check for.
        :return: True if the objectClass is present, False otherwise
        :rtype: bool
        """
        self.refresh_missing(['objectClass'])
        return object_class in self['objectClass']

    def refresh(self, attrs=None):
        """Query the server to update the attributes on this object.

        :param list[str] attrs: Optional. A list of attribute names to query. If not specified, will query the server
                                for all user attributes.
        :rtype: None
        :raises RuntimeError: if this object is not bound to an LDAP connection
        """
        self._require_ldap()
        self.update(self.ldap_conn.get(self.dn, attrs))

    def refresh_all(self):
        """Query the server to update all user and operational attributes on this object.

        :rtype: None
        :raises RuntimeError: if this object is not bound to an LDAP connection
        """
        self._require_ldap()
        self.refresh(['*', '+'])

    def refresh_missing(self, attrs):
        """Potentially query the server for any listed attributes that are not yet defined on this object. If no listed
        attributes aren't defined, the query will not be performed. If a subset of the list is undefined, only those
        attributes will be queried.

        :param list[str] attrs: A list of attribute names to check, and possibly query for.
        :rtype: None
        """
        missing_attrs = []
        for attr in attrs:
            if attr not in self:
                missing_attrs.append(attr)
        if len(missing_attrs) > 0:
            self.refresh(missing_attrs)

    ## object modify methods

    def modify(self, modlist, **ctrl_kwds):
        """Perform a series of modify operations on this object atomically.

        :param list[Mod] modlist: A list of :class:`Mod` instances,
                                  e.g. [Mod(Mod.ADD, 'someAttr', ['value1', 'value2'])]
        :rtype: None
        :raises RuntimeError: if this object is not bound to an LDAP connection

        Additional keywords are passed through into :meth:`.LDAP.modify`.
        """
        self._require_ldap()
        self.ldap_conn.modify(self.dn, modlist, current=self, **ctrl_kwds)
        self._local_modify(modlist)

    def add_attrs(self, attrs_dict, **ctrl_kwds):
        """Add new attribute values to this object.

        :param attrs_dict: The new attributes to add to the object
        :type attrs_dict: dict(str, list[str or bytes]) or AttrsDict
        :rtype: None

        Additional keywords are passed through into :meth:`.LDAPObject.modify`.
        """
        if not self.ldap_conn.strict_modify:
            self.refresh_missing(list(attrs_dict.keys()))
        modlist = AddModlist(self, attrs_dict)
        self.modify(modlist, **ctrl_kwds)

    def replace_attrs(self, attrs_dict, **ctrl_kwds):
        """Replace all values on the given attributes with the passed values.

        :param attrs_dict: The new attributes to set on the object
        :type attrs_dict: dict(str, list[str or bytes]) or AttrsDict
        :rtype: None

        Additional keywords are passed through into :meth:`.LDAPObject.modify`.
        """
        modlist = Modlist(Mod.REPLACE, attrs_dict)
        self.modify(modlist, **ctrl_kwds)

    def delete_attrs(self, attrs_dict, **ctrl_kwds):
        """Delete specifc attribute values given in ``attrs_dict``. Specifying a zero-length list for any attribute will
        delete all values for that attribute.

        :param attrs_dict: The attributes to delete from the object
        :type attrs_dict: dict(str, list[str or bytes]) or AttrsDict
        :rtype: None

        Additional keywords are passed through into :meth:`.LDAPObject.modify`.
        """
        if not self.ldap_conn.strict_modify:
            self.refresh_missing(list(attrs_dict.keys()))
        modlist = DeleteModlist(self, attrs_dict)
        self.modify(modlist, **ctrl_kwds)

    def _local_modify(self, modlist):
        """Perform local modify after writing to server"""
        for mod in modlist:
            if mod.op == Mod.ADD:
                if mod.attr not in self:
                    self[mod.attr] = mod.vals
                else:
                    self[mod.attr].extend(mod.vals)
            elif mod.op == Mod.REPLACE:
                if mod.vals:
                    self[mod.attr] = mod.vals
                else:
                    del self[mod.attr]
            elif mod.op == Mod.DELETE:
                if mod.attr in self:
                    if mod.vals:
                        for val in mod.vals:
                            try:
                                self._delete_attr_value(mod.attr, val)
                            except ValueError:
                                pass
                    else:
                        del self[mod.attr]
            else:
                raise ValueError('Invalid mod op')

    def _delete_attr_value(self, attr, val):
        """Delete a single local attribute value"""
        self[attr].remove(val)
        if not self[attr]:
            del self[attr]

    ## online-only object-level methods

    def delete(self, **ctrl_kwds):
        """Delete the entire object from the server, and render this instance useless.

        Additional keywords are passed through into :meth:`.LDAP.delete`.

        :rtype: None
        :raises RuntimeError: if this object is not bound to an LDAP connection
        """
        self._require_ldap()
        self.ldap_conn.delete(self.dn, **ctrl_kwds)
        self.clear()
        self.dn = None
        self.ldap_conn = None

    def mod_dn(self, new_rdn, clean_attr=True, new_parent=None, **ctrl_kwds):
        """Change the object DN, and possibly its location in the tree.

        :param str new_rdn: The new RDN of the object
        :param bool clean_attr: Optional, default True. Remove the attribute associated with the RDN when changing it.
        :param str new_parent: Optional. The absolute DN of the object's new parent.
        :rtype: None
        :raises RuntimeError: if this object is not bound to an LDAP connection

        Additional keywords are passed through into :meth:`.LDAP.mod_dn`.
        """
        self._require_ldap()
        cur_rdn, cur_parent = self.dn.split(',', 1)
        if new_parent is None:
            parent = cur_parent
        else:
            parent = new_parent
        self.ldap_conn.mod_dn(self.dn, new_rdn, clean_attr, parent, **ctrl_kwds)
        if clean_attr:
            rdn_attr, rdn_val = cur_rdn.split('=', 1)
            try:
                self._delete_attr_value(rdn_attr, rdn_val)
            except Exception:
                pass
        rdn_attr, rdn_val = new_rdn.split('=', 1)
        if rdn_attr not in self:
            self[rdn_attr] = [rdn_val]
        elif rdn_val not in self[rdn_attr]:
            self[rdn_attr].append(rdn_val)
        self.dn = '{0},{1}'.format(new_rdn, parent)

    def rename(self, new_rdn, clean_attr=True, **ctrl_kwds):
        """Change the object's RDN without changing it's location in the tree.

        :param str new_rdn: The new RDN of the object
        :param bool clean_attr: Optional, default True. Remove the attribute associated with the RDN when changing it.
        :rtype: None

        Additional keywords are passed through into :meth:`.LDAPObject.mod_dn`.
        """
        return self.mod_dn(new_rdn, clean_attr, **ctrl_kwds)

    def move(self, new_dn, clean_attr=True, **ctrl_kwds):
        """Specify the complete new absolute DN for this object.

        :param str new_dn: The new absolute DN for the object
        :param bool clean_attr: Optional, default True. Remove the attribute associated with the RDN when changing it.
        :rtype: None

        Additional keywords are passed through into :meth:`.LDAPObject.mod_dn`.
        """
        new_rdn, new_parent = new_dn.split(',', 1)
        return self.mod_dn(new_rdn, clean_attr, new_parent, **ctrl_kwds)

    ## validation methods

    def validate(self):
        """Validate the object, assuming all attributes are present locally"""
        self.ldap_conn.validate_object(self, write=False)

    def validate_modify(self, modlist):
        """Validate a modification list.

        :param list[Mod] modlist: The list of modify operations to validate.
        """
        self.ldap_conn.validate_modify(self.dn, modlist, self)

    ## transactions

    def mod_transaction(self):
        """Begin a modify transaction on this object. Important: This IS NOT an RFC 5805 transaction.

        :rtype: ModTransactionObject
        """
        return ModTransactionObject(self)


class ModTransactionObject(LDAPObject):
    """Provides a transaction-like construct for building up a single modify operation. Users should use
    :meth:`.LDAPObject.mod_transaction` rather than instantiating this directly.

    Inherits all modify methods from :class:`.LDAPObject`, allowing users to utilize the familiar interface for
    modifications, but overrides the base ``modify`` method so that changes are not immediately applied on the server.

    The state of attributes is mutated within this transaction object with each higher-level modify call
    (e.g., :meth:`.LDAPObject.add_attrs`) allowing the state to be inspected. When :meth:`.ModTransactionObject.commit`
    is invoked, the built-up series of raw modify operations is sent to the server, and the state of the underlying
    :class:`LDAPObject` is mutated.

    Since this ultimately constructs only one modify operation per commit, the transaction is atomic.

    You can also call ``mod_transaction()`` on a transaction object to create a "checkpoint". The local state of the
    transaction will be copied into a new transaction object. To "roll back", just delete the new object without
    committing.

    Example::

        from laurelin.ldap import LDAP

        with LDAP() as ldap:
            obj = ldap.base.get_child('cn=someobject')
            print(obj.get_attr('memberUid'))
            # ['foo', 'bar']
            with obj.mod_transaction() as trans:
                trans.add_attrs({'memberUid': ['foobar']})
                print(trans.get_attr('memberUid'))
                # ['foo', 'bar', 'foobar']
                print(obj.get_attr('memberUid'))
                # ['foo', 'bar']

                trans.delete_attrs({'memberUid': ['bar']})
                print(trans.get_attr('memberUid'))
                # ['foo', 'foobar']
                print(obj.get_attr('memberUid'))
                # ['foo', 'bar']

                with trans.mod_transaction() as checkpoint:
                    print(checkpoint.get_attr('memberUid'))
                    # ['foo', 'foobar']
                    print(trans.get_attr('memberUid'))
                    # ['foo', 'foobar']
                    print(obj.get_attr('memberUid'))
                    # ['foo', 'bar']

                    checkpoint.delete_attrs({'memberUid': ['foo']})
                    print(checkpoint.get_attr('memberUid'))
                    # ['foobar']
                    print(trans.get_attr('memberUid'))
                    # ['foo', 'foobar']
                    print(obj.get_attr('memberUid'))
                    # ['foo', 'bar']

                    # Note: no commit on checkpoint, meaning we will be rolled back to the pre-checkpoint state

                # Now in rolled-back (actually just unchanged) state
                print(trans.get_attr('memberUid'))
                # ['foo', 'foobar']
                print(obj.get_attr('memberUid'))
                # ['foo', 'bar']

                trans.commit()

            # Transaction was committed, we can now see changes reflected in the original object:
            print(obj.get_attr('memberUid'))
            # ['foo', 'foobar']

    You can also raise :exc:`.Abandon` from within a transaction context manager to cleanly abandon the transaction
    and exit the context manager.
    """

    def __init__(self, ldap_object):
        self._orig_obj = ldap_object
        self._modlist = []

        LDAPObject.__init__(self, dn=ldap_object.dn, attrs_dict=ldap_object.deepcopy(), ldap_conn=ldap_object.ldap_conn,
                            relative_search_scope=ldap_object.relative_search_scope, rdn_attr=ldap_object.rdn_attr)

    def __enter__(self):
        return self

    def __exit__(self, etype, e, trace):
        self._modlist = []
        if etype == Abandon:
            return True

    def commit(self):
        """Send the modify operation to the server and update the original local :class:`.LDAPObject`.

        :rtype: None
        """
        self._orig_obj.modify(self._modlist)
        self._modlist = []

    def modify(self, modlist, **kwds):
        """Process and validate a partial transaction, and mutate the transaction object's local attributes. Does not
        send anything to the server.

        :param list[Mod] modlist: A partial list of modify operations to include in the transaction.
        :rtype: None
        :raises TypeError: if any extra keyword arguments are passed to this function.
        """
        if kwds:
            raise TypeError('Unhandled keyword arguments: {0}'.format(', '.join(kwds.keys())))
        self.validate_modify(modlist)
        self._modlist.extend(modlist)
        self._local_modify(modlist)

    def format_mod_ldif(self):
        """Format the modify operation as an LDIF

        :return: The LDIF string describing the modify operation to be performed
        :rtype: str
        """
        ldif = 'dn: {0}\nchangetype: modify\n'.format(self.dn)
        for mod in self._modlist:
            ldif += '{0}: {1}\n'.format(Mod.op_to_string(mod.op).lower(), mod.attr)
            for val in mod.vals:
                ldif += '{0}: {1}\n'.format(mod.attr, val)
            ldif += '-\n'
        return ldif

    def add_child(self, rdn, attrs_dict, **kwds):
        """Raises an error if used in a transaction. Transactions can only modify one object at a time.

        :raises LDAPTransactionError: if this method is called.
        """
        raise LDAPTransactionError('add not included in modify transaction')

    def delete(self, **ctrl_kwds):
        """Raises an error if used in a transaction. Transactions can only modify one object at a time.

        :raises LDAPTransactionError: if this method is called.
        """
        raise LDAPTransactionError('delete not included in modify transaction')

    def delete_child(self, rdn, **ctrl_kwds):
        """Raises an error if used in a transaction. Transactions can only modify one object at a time.

        :raises LDAPTransactionError: if this method is called
        """
        raise LDAPTransactionError('delete not included in modify transaction')

    def mod_dn(self, new_rdn, clean_attr=True, new_parent=None, **ctrl_kwds):
        """Raises an error if used in a transaction. Transactions can only modify one object at a time.

        :raises LDAPTransactionError: if this method is called.
        """
        raise LDAPTransactionError('mod_dn not included in modify transaction')
