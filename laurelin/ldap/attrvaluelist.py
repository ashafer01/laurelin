from __future__ import absolute_import
from .attributetype import get_attribute_type


class AttrValueList(list):
    """
     List that follows schema matching rules for the `in` operator and
     other related methods
    """

    def __init__(self, attr, values):
        self.attr_type = get_attribute_type(attr)
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
        """
        return self.attr_type.index(self, value)

    def count(self, value):
        try:
            self.index(value)
            return 1
        except ValueError:
            return 0

    def remove(self, value):
        i = self.index(value)
        del self[i]
