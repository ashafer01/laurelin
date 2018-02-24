from __future__ import absolute_import
import six


class AttrsDict(dict):
    """Stores attributes and provides utility methods without any server or object affinity

     Dict keys are case-insensitive attribute names, and dict values are a list of attribute values
    """

    def get_attr(self, attr):
        """Get an attribute's values, or an empty list if the attribute is not defined

        :param attr: The name of the attribute
        :return: A list of values
        :rtype: list
        """
        return self.get(attr, [])

    def iterattrs(self):
        """Iterate all attributes of this object. Yields ``(attr, value)`` tuples."""
        for attr, vals in six.iteritems(self):
            for val in vals:
                yield (attr, val)

    def deepcopy(self):
        """Return a native dict copy of self."""
        ret = {}
        for attr, vals in six.iteritems(self):
            ret[attr] = []
            for val in vals:
                ret[attr].append(val)
        return ret

    ## dict overrides for case-insensitive keys and enforcing types

    def __init__(self, attrs_dict=None):
        self._keys = {}
        if attrs_dict is not None:
            self.update(attrs_dict)

    def __contains__(self, attr):
        try:
            return len(self[attr]) > 0
        except KeyError:
            return False

    def __setitem__(self, attr, values):
        AttrsDict.validate_attr(attr)
        AttrsDict.validate_values(values)
        self._keys[attr.lower()] = attr
        dict.__setitem__(self, attr, values)

    def setdefault(self, attr, default=None):
        AttrsDict.validate_attr(attr)
        if default is None:
            default = []
        try:
            AttrsDict.validate_values(default)
        except TypeError as e:
            raise TypeError('invalid default - {0}'.format(str(e)))
        try:
            return self[attr]
        except KeyError:
            self[attr] = default
            return default

    def __getitem__(self, key):
        key = self._keys[key.lower()]
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def update(self, attrs_dict):
        AttrsDict.validate(attrs_dict)
        for key in attrs_dict:
            self[key] = attrs_dict[key]

    def __delitem__(self, key):
        lkey = key.lower()
        key = self._keys[lkey]
        dict.__delitem__(self, key)
        del self._keys[lkey]

    def clear(self):
        dict.clear(self)
        self._keys.clear()

    @staticmethod
    def validate(attrs_dict):
        """Validate that ``attrs_dict`` is either already an :class:`.AttrsDict` or that it conforms to the required
        ``dict(str, list[str])`` typing.

        :param dict attrs_dict: The dictionary to validate for use as an attributes dictionary
        :rtype: None
        :raises TypeError: when the dict is invalid
        """
        if isinstance(attrs_dict, AttrsDict):
            return
        if not isinstance(attrs_dict, dict):
            raise TypeError('must be dict')
        for attr in attrs_dict:
            AttrsDict.validate_attr(attr)
            AttrsDict.validate_values(attrs_dict[attr])

    @staticmethod
    def validate_attr(attr):
        """Validate that ``attr`` is a valid attribute name.

        :param str attr: The string to validate for use as an attribute name
        :rtype: None
        :raises TypeError: when the string is invalid
        """
        if not isinstance(attr, six.string_types):
            raise TypeError('attribute name must be string')

    @staticmethod
    def validate_values(attr_val_list):
        """Validate that ``attr_val_list`` conforms to the required ``list[str]`` typing.

        :param list attr_val_list: The list to validate for use as an attribute value list.
        :rtype: None
        :raises TypeError: when the list is invalid
        """
        if not isinstance(attr_val_list, list):
            raise TypeError('must be list')
        for val in attr_val_list:
            # TODO binary data support throughout...
            if not isinstance(val, six.string_types):
                raise TypeError('attribute values must be string')
