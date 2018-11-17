from __future__ import absolute_import
from .attributetype import get_attribute_type
from .extensible import extensions


class AttrValueList(list):
    """List that follows schema matching rules for the ``in`` operator and other related methods.

    :param str attr: The attribute name or type identifier
    :param list[str] values: Initial values for the list
    """

    def __init__(self, attr, values):
        self.attr = attr
        list.__init__(self, values)

    def __contains__(self, value):
        try:
            self.index(value)
            return True
        except ValueError:
            return False

    def index(self, value, *args, **kwds):
        """Find the index of value or raise a ValueError if not found.
        The stock start/end arguments are ignored since a list of attribute
        values is defined to have exactly zero or one unique matching values.

        :param str value: The value to find
        :return: The index of the value
        :rtype: int
        :raises ValueError: if the value is not found or if the list has no values
        """
        extensions.base_schema.require()
        attr_type = get_attribute_type(self.attr)
        return attr_type.index(self, value)

    def count(self, value):
        """Count the number of occurrences of ``value``. Since attribute value lists are defined to only have at most
        one unique copy of any value, this will always return 0 or 1.

        :param str value: The value to count
        :return: The number of occurrences of ``value``, 1 or 0.
        :rtype: int
        :raises ValueError: if the value is not found or if the list has no values
        """
        try:
            self.index(value)
            return 1
        except ValueError:
            return 0

    def remove(self, value):
        """Remove ``value`` from the list if present.

        :param str value: The value to remove
        :rtype: None
        :raises ValueError: if the value is not found or if the list has no values
        """
        i = self.index(value)
        del self[i]
