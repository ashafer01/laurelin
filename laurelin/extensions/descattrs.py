"""Support for structured description fields.

This implements the common pattern of storing arbitrary key=value data in description fields, but presents an
attribute-like interface to access and change them.

Example::

    from laurelin.ldap import LDAP
    LDAP.activate_extension('laurelin.extensions.descattrs')

    with LDAP() as ldap:
        result = ldap.base.get_child('cn=someObject')

        result.add_desc_attrs({'foo':['one', 'two']})
        print(result.format_ldif())
        # ...
        # description: foo=one
        # description: foo=two
        # ...

        attr_vals = result.desc_attrs().get_attr('foo')
        print(attr_vals)
        # ['one', 'two']

        result.replace_desc_attrs({'foo':['one','two','three']})
        result.delete_desc_attrs({'foo':['two']})

        attr_vals = result.desc_attrs().get_attr('foo')
        print(attr_vals)
        # ['one', 'three']

        print(result.format_ldif())
        # ...
        # description: foo=one
        # description: foo=three
        # ...

"""

from laurelin.ldap import LDAPObject
from laurelin.ldap.attrsdict import AttrsDict
import six

DESC_ATTR_DELIM = '='
"""Key/value delimiter in description attrs. If this character is not present in the description value, then it will be
considered unstructured and ignored.
"""

LDAPObject_methods = []


def desc_attrs(self):
    """desc_attrs()

    Query the description attribute if unknown and return an :class:`.AttrsDict` representing the data stored in the
    description.

    :return: An :class:`.AttrsDict` representing the data stored in the description.
    :rtype: AttrsDict
    """
    self.refresh_missing(['description'])
    ret = AttrsDict()
    self._unstructured_desc = set()
    for desc in self.get_attr('description'):
        if DESC_ATTR_DELIM in desc:
            key, value = desc.split(DESC_ATTR_DELIM, 1)
            vals = ret.setdefault(key, [])
            vals.append(value)
        else:
            self._unstructured_desc.add(desc)
    return ret


LDAPObject_methods.append(desc_attrs)


def _modify_desc_attrs(self, method, attrs_dict):
    """Perform modification to the object's description attributes. This method gets bound to :class:`.LDAPObject`.

    :param callable method: The method to call to modify the description attributes dictionary
    :param attrs_dict: Will be passed as the 2nd argument to ``method``.
    :type attrs_dict: dict(str, list[str]) or AttrsDict
    :rtype: None
    :raises RuntimeError: if there is no :class:`.LDAP` connection associated with this :class:`.LDAPObject`.
    """
    self._require_ldap()
    desc_dict = self.desc_attrs()
    method(desc_dict, attrs_dict)
    desc_strings = []
    for key, values in six.iteritems(desc_dict):
        for value in values:
            desc_strings.append(key + DESC_ATTR_DELIM + value)
    self.replace_attrs({'description': desc_strings + list(self._unstructured_desc)})


LDAPObject_methods.append(_modify_desc_attrs)


def _dict_mod_add(to_dict, attrs_dict):
    """Adds attributes from attrs_dict to to_dict.

    :param to_dict: The dictionary to modify
    :type to_dict: dict(str, list[str]) or AttrsDict
    :param attrs_dict: Dictionary of attributes to add to ``to_dict``
    :type attrs_dict: dict(str, list[str]) or AttrsDict
    :return: None, modifies ``to_dict`` in place.
    :rtype: None
    """
    for attr, vals in six.iteritems(attrs_dict):
        if attr not in to_dict:
            to_dict[attr] = vals
        else:
            for val in vals:
                if val not in to_dict[attr]:
                    to_dict[attr].append(val)


def _dict_mod_replace(to_dict, attrs_dict):
    """Replaces attribute values in to_dict with those from attrs_dict.

    :param to_dict: The dictionary to modify
    :type to_dict: dict(str, list[str]) or AttrsDict
    :param attrs_dict: Dictionary of attributes to set in ``to_dict``
    :type attrs_dict: dict(str, list[str]) or AttrsDict
    :return: None, modifies ``to_dict`` in place.
    :rtype: None
    """
    to_dict.update(attrs_dict)


def _dict_mod_delete(to_dict, attrs_dict):
    """Deletes attribute values from to_dict that appear in attrs_dict

    :param to_dict: The dictionary to modify
    :type to_dict: dict(str, list[str]) or AttrsDict
    :param attrs_dict: Dictionary of attributes to delete from ``to_dict``. If any value is an empty list, delete all
                       attribute values.
    :type attrs_dict: dict(str, list[str]) or AttrsDict
    :return: None, modifies ``to_dict`` in place.
    :rtype: None
    """
    for attr, delVals in six.iteritems(attrs_dict):
        if attr in to_dict:
            if delVals:
                for val in delVals:
                    try:
                        to_dict[attr].remove(val)
                    except Exception:
                        pass
            else:
                del to_dict[attr]


def add_desc_attrs(self, attrs_dict):
    """add_desc_attrs(attrs_dict)

    Add new description attributes.

    :param attrs_dict: Dictionary of description attributes to add
    :type attrs_dict: dict(str, list[str]) or AttrsDict
    :rtype: None
    """
    self._modify_desc_attrs(_dict_mod_add, attrs_dict)


LDAPObject_methods.append(add_desc_attrs)


def replace_desc_attrs(self, attrs_dict):
    """replace_desc_attrs(attrs_dict)

    Replace description attributes.

    :param attrs_dict: Dictionary of description attributes to set
    :type attrs_dict: dict(str, list[str]) or AttrsDict
    :rtype: None
    """
    self._modify_desc_attrs(_dict_mod_replace, attrs_dict)


LDAPObject_methods.append(replace_desc_attrs)


def delete_desc_attrs(self, attrs_dict):
    """delete_desc_attrs(attrs_dict)

    Delete description attributes.

    :param attrs_dict: Dictionary of description attributes to delete
    :type attrs_dict: dict(str, list[str]) or AttrsDict
    :rtype: None
    """
    self._modify_desc_attrs(_dict_mod_delete, attrs_dict)


LDAPObject_methods.append(delete_desc_attrs)


def activate_extension():
    """Extension activation function. Installs extension methods on :class:`.LDAPObject`."""
    LDAPObject.EXTEND(LDAPObject_methods)
