from __future__ import absolute_import
from .attrsdict import AttrsDict
from .attrvaluelist import AttrValueList
from .constants import Scope
from .exceptions import (
    LDAPError,
    Abandon,
    LDAPTransactionError,
    NoSearchResults,
    MultipleSearchResults,
)
from .extensible import Extensible
from .modify import (
    Mod,
    Modlist,
    AddModlist,
    DeleteModlist,
)


class LDAPObject(AttrsDict, Extensible):
    """Represents a single object with optional server affinity.

    Many methods will raise an exception if used without a server connection. To instantiate an :class:`LDAPObject`
    bound to a server connection, use :meth:`LDAP.obj`.

    Attributes and values are stored using the mapping interface inherited from AttrsDict, where dict keys are
    case-insensitive attribute names, and dict values are a list of attribute values.

    :param str dn: The DN of the object
    :param attrs_dict: The object's attributes
    :type attrs_dict: dict(str, list[str]) or AttrsDict or None
    :param ldap_conn: The optional LDAP connection to use
    :type ldap_conn: LDAP or None
    :param Scope relative_search_scope: One of the :class:`Scope` constants, this is the default scope used when using
                                        this object's :meth:`LDAPObject.search` method. New objects created below this
                                        one will inherit this attribute by default.
    :param rdn_attr: The default attribute name used in RDN's for descendents of this object. If specified, this
                     allows you to only specify the value for methods that have an `rdn` argument. You can always
                     specify a full attr=value for `rdn` arguments as well to override this behavior. New objects
                     created below this one will inherit this attribute by default.
    :type rdn_attr: str or None
    """

    def __init__(self, dn, attrs_dict=None, ldap_conn=None, relative_search_scope=Scope.SUBTREE, rdn_attr=None):
        self.dn = dn
        self.ldap_conn = ldap_conn
        self.relative_search_scope = relative_search_scope
        self.rdn_attr = rdn_attr
        AttrsDict.__init__(self, attrs_dict)

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

    def obj(self, rdn, attrs_dict=None, tag=None, *args, **kwds):
        """Create a new object below this one.

        :param str rdn: The RDN, or RDN value if `rdn_attr` is defined for this object
        :param attrs_dict: The attributes for the object
        :type attrs_dict: dict(str, list[str]) or AttrsDict or None
        :param tag: Optional tag for the object
        :type tag: str or None
        :return: The new object
        :rtype: LDAPObject
        :raises LDAPError: if a `tag` is specified but this object is not bound to an LDAP connection

        Additional arguments are passed through into the :class:`LDAPObject` constructor.
        """
        self._set_obj_kwd_defaults(kwds)
        if self._has_ldap():
            return self.ldap_conn.obj(self.rdn(rdn), attrs_dict=attrs_dict, tag=tag, *args, **kwds)
        else:
            if tag is not None:
                raise LDAPError('tagging requires LDAP instance')
            return LDAPObject(self.rdn(rdn), attrs_dict=attrs_dict, *args, **kwds)

    def get_child(self, rdn, attrs=None, **kwds):
        """Query the server for a child object.

        :param str rdn: The RDN, or RDN value if `rdn_attr` is defined for this object
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
        :type attrs_dict: dict(str, list[str]) or AttrsDict or None
        :return: The new object
        :rtype: LDAPObject

        Additional arguments are passed through into :meth:`LDAP.add`
        """
        self._require_ldap()
        self._set_obj_kwd_defaults(kwds)
        return self.ldap_conn.add(self.rdn(rdn), attrs_dict, **kwds)

    def search(self, filter=None, attrs=None, *args, **kwds):
        self._require_ldap()
        self._set_obj_kwd_defaults(kwds)
        return self.ldap_conn.search(self.dn, self.relative_search_scope, filter, attrs, *args, **kwds)

    def find(self, rdn, attrs=None, **kwds):
        self._require_ldap()
        self._set_obj_kwd_defaults(kwds)
        if self.relative_search_scope == Scope.BASE:
            raise LDAPError('Object has no children')
        elif self.relative_search_scope == Scope.ONELEVEL:
            return self.get_child(rdn, attrs, **kwds)
        elif self.relative_search_scope == Scope.SUBTREE:
            filter = '({0})'.format(self._rdn_attr(rdn))
            res = list(self.search(filter=filter, attrs=attrs, limit=2, **kwds))
            n = len(res)
            if n == 0:
                raise NoSearchResults()
            elif n == 1:
                return res[0]
            else:
                raise MultipleSearchResults()
        else:
            raise ValueError('Unknown relative_search_scope')

    def compare(self, attr, value):
        self._require_ldap()
        return self.ldap_conn.compare(self.dn, attr, value)

    ## object-specific methods

    def format_ldif(self):
        lines = ['dn: {0}'.format(self.dn)]
        for attr, val in self.iterattrs():
            lines.append('{0}: {1}'.format(attr, val))
        lines.append('')
        return '\n'.join(lines)

    def has_object_class(self, object_class):
        self.refresh_missing(['objectClass'])
        return object_class in self['objectClass']

    def refresh(self, attrs=None):
        self._require_ldap()
        self.update(self.ldap_conn.get(self.dn, attrs))

    def refresh_all(self):
        self._require_ldap()
        self.refresh(['*', '+'])

    def refresh_missing(self, attrs):
        missing_attrs = []
        for attr in attrs:
            if attr not in self:
                missing_attrs.append(attr)
        if len(missing_attrs) > 0:
            self.refresh(missing_attrs)

    ## object modify methods

    def modify(self, modlist, **ctrl_kwds):
        self._require_ldap()
        self.ldap_conn.modify(self.dn, modlist, current=self, **ctrl_kwds)
        self._local_modify(modlist)

    def add_attrs(self, attrs_dict, **ctrl_kwds):
        if not self.ldap_conn.strictModify:
            self.refresh_missing(list(attrs_dict.keys()))
        modlist = AddModlist(self, attrs_dict)
        self.modify(modlist, **ctrl_kwds)

    def replace_attrs(self, attrs_dict, **ctrl_kwds):
        modlist = Modlist(Mod.REPLACE, attrs_dict)
        self.modify(modlist, **ctrl_kwds)

    def delete_attrs(self, attrs_dict, **ctrl_kwds):
        if not self.ldap_conn.strictModify:
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
        """delete the entire object from the server, and render this instance useless"""
        self._require_ldap()
        self.ldap_conn.delete(self.dn, **ctrl_kwds)
        self.clear()
        self.dn = None
        self.ldap_conn = None

    def mod_dn(self, new_rdn, clean_attr=True, new_parent=None, **ctrl_kwds):
        """change the object DN, and possibly its location in the tree"""
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
        return self.mod_dn(new_rdn, clean_attr, **ctrl_kwds)

    def move(self, new_dn, clean_attr=True, **ctrl_kwds):
        new_rdn, new_parent = new_dn.split(',', 1)
        return self.mod_dn(new_rdn, clean_attr, new_parent, **ctrl_kwds)

    ## validation methods

    def validate(self):
        """Validate the object, assuming all attributes are present locally"""
        self.ldap_conn.validate_object(self, write=False)

    def validate_modify(self, modlist):
        """Validate a modification list"""
        self.ldap_conn.validate_modify(self.dn, modlist, self)

    ## transactions

    def mod_transaction(self):
        return ModTransactionObject(self)


class ModTransactionObject(LDAPObject):
    """Provides a transaction-like construct for building up a single modify operation"""

    def __init__(self, ldap_object):
        self._orig_obj = ldap_object
        self._modlist = []

        LDAPObject.__init__(dn=ldap_object.dn, attrs_dict=ldap_object.deepcopy(), ldap_conn=ldap_object.ldap_conn,
                            relative_search_scope=ldap_object.relative_search_scope, rdn_attr=ldap_object.rdn_attr)

    def __enter__(self):
        return self

    def __exit__(self, etype, e, trace):
        self._modlist = []
        if etype == Abandon:
            return True

    def commit(self):
        self._orig_obj.modify(self._modlist)
        self._modlist = []

    def modify(self, modlist, **kwds):
        if kwds:
            raise TypeError('Unhandled keyword arguments: {0}'.format(', '.join(kwds.keys())))
        self.validate_modify(modlist)
        self._modlist.extend(modlist)
        self._local_modify(modlist)

    def add_child(self, rdn, attrs_dict, **kwds):
        raise LDAPTransactionError('add not included in modify transaction')

    def delete(self, **ctrl_kwds):
        raise LDAPTransactionError('delete not included in modify transaction')

    def mod_dn(self, new_rdn, clean_attr=True, new_parent=None, **ctrl_kwds):
        raise LDAPTransactionError('modDN not included in modify transaction')
