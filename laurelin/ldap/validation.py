import six


class Validator(object):
    """Abstract base class for a validator. All validators must inherit from here and ensure the public interface is
    fully implemented.
    """

    def validate_object(self, obj, write=True):
        """Validate an object when all attributes are present.

        By default, validate all attributes on the object.

        :param LDAPObject obj: An LDAP object with all attributes defined
        :param bool write: True if we are validating a write operation to the database
        :return: None
        :raises LDAPValidationError: if the object is invalid in any way
        """
        for attr, values in six.iteritems(obj):
            self._validate_attribute(attr, values, write)

    def validate_modify(self, dn, modlist, current):
        """Validate a modify operation.

        By default, validate all attributes for writing.

        :param str dn: The DN of the object being modified
        :param list[Mod] modlist: The list of modify operations to be performed this transaction
        :param current: The known state of the object prior to modification
        :type current: LDAPObject or None
        :return: None
        :raises LDAPValidationError: if any modify operation is invalid
        """
        for mod in modlist:
            if mod.vals:
                self._validate_attribute(mod.attr, mod.vals, True)

    def _validate_attribute(self, attr_name, values, write):
        """Validate a single attribute and list of values.

        :param str attr_name: The name of the attribute, or more formally the attribute type, being modified
        :param list[str] values: The new list of values or values to be deleted
        :param bool write: True if we are validating a write operation
        :return: None
        :raises LDAPValidationError: if the attribute is invalid in any way
        """
        raise NotImplementedError()
