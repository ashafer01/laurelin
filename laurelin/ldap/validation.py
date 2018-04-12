import six


class Validator(object):
    """Abstract base class for a validator. All validators must inherit from here and ensure the public interface is
    fully implemented.
    """
    def __init__(self):
        self.ldap_conn = None

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


class DisabledValidationContext(object):
    """This should be created by calling :meth:`.LDAP.disable_validation` and never directly instantiated."""

    def __init__(self, ldap, disabled_validators=None):
        self.ldap = ldap
        self.orig_validators = []
        self.disabled_validators = set()
        if disabled_validators:
            for val_spec in disabled_validators:
                if isinstance(val_spec, six.string_types):
                    self.disabled_validators.add(val_spec)
                elif issubclass(val_spec, Validator):
                    self.disabled_validators.add(val_spec.__name__)
                else:
                    raise TypeError('Invalid disabled validator spec, must be string class name or Validator subclass')

    def __enter__(self):
        new_validators = []
        for v in self.ldap.validators:
            self.orig_validators.append(v)
            if not self.disabled_validators:
                continue
            if v.__class__.__name__ in self.disabled_validators:
                continue
            new_validators.append(v)
        self.ldap.validators = new_validators

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ldap.validators = self.orig_validators
