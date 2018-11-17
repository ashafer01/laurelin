"""Schema specifications from various RFCs"""

from __future__ import absolute_import
from .extensible import extensions
from .exceptions import LDAPValidationError, LDAPWarning
from .attributetype import get_attribute_type
from .objectclass import get_object_class
from .validation import Validator

from warnings import warn


class SchemaValidator(Validator):
    """Ensures parameters conform to the available defined schema"""

    def __init__(self):
        extensions.base_schema.require()
        Validator.__init__(self)

    def validate_object(self, obj, write=True):
        """Validates an object when all attributes are present

         * Requires the objectClass attribute
         * Checks that all attributes required by the objectClass are defined
         * Checks that all attributes are allowed by the objectClass
         * Performs validation against the attribute type spec for all attributes
        """
        try:
            object_classes = obj['objectClass']
        except KeyError:
            raise LDAPValidationError('missing objectClass')
        required_attrs = set()
        allowed_attrs = set()
        for oc_name in object_classes:
            oc = get_object_class(oc_name)
            required_attrs.update(oc.must)
            allowed_attrs.update(oc.may)
        disallowed_attrs = []
        for attr in obj.keys():
            if attr in required_attrs:
                required_attrs.remove(attr)
            elif attr in allowed_attrs:
                pass
            else:
                disallowed_attrs.append(attr)
        if required_attrs:
            missing_required = ','.join(required_attrs)
            oc_names = ','.join(object_classes)
            raise LDAPValidationError('missing attributes {0} required by objectClasses {1}'.format(
                                      missing_required, oc_names))
        if disallowed_attrs:
            disallowed_attrs = ','.join(disallowed_attrs)
            oc_names = ','.join(object_classes)
            raise LDAPValidationError('attributes {0} are not permitted with objectClasses {1}'.format(
                                      disallowed_attrs, oc_names))
        Validator.validate_object(self, obj, write)

    def _validate_attribute(self, attr_name, values, write):
        attr = get_attribute_type(attr_name)
        if attr.obsolete:
            warn('Attribute {0} is obsolete'.format(attr_name), LDAPWarning)
        if attr.single_value and len(values) > 1:
            raise LDAPValidationError('Multiple values for single-value attribute {0}'.format(attr_name))
        if write and attr.no_user_mod:
            raise LDAPValidationError('Attribute {0} is not user modifiable'.format(attr_name))
        for value in values:
            attr.validate(value)

